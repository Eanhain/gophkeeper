package v1

import (
	"errors"
	"fmt"
	"time"

	"github.com/Eanhain/gophkeeper/domain"
	"github.com/Eanhain/gophkeeper/internal/controller/restapi/v1/request"
	"github.com/Eanhain/gophkeeper/internal/entity"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

// CreateJWT generates a signed HS256 JWT for the given username.
// The token contains the "login" and "crypto_key" claims and expires after 72 hours.
func (r *V1) CreateJWT(username, cryptoKey string) (string, error) {
	claims := jwt.MapClaims{
		"login":      username,
		"crypto_key": cryptoKey,
		"exp":        time.Now().Add(time.Hour * 72).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenJWT, err := token.SignedString(r.jwtConf.SigningKey.Key)
	if err != nil {
		return "", err
	}
	return tokenJWT, nil
}

// LoginJWT authenticates a user and returns a JWT token.
//
// @Summary      User login
// @Description  Authenticates a user by login and password, returns a signed JWT token
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        input body request.UserInput true "User credentials"
// @Success      200 {object} map[string]string "token"
// @Failure      401 {object} map[string]string "unauthorized"
// @Failure      500 {object} map[string]string "internal server error"
// @Router       /api/user/login [post]
func (r *V1) LoginJWT(c *fiber.Ctx) error {
	username, cryptoKey, err := r.AuthUser(c)
	if err != nil {
		r.l.Warn("Can't auth user: %v", err)
		return fiber.ErrUnauthorized
	}
	tokenJWT, err := r.CreateJWT(username, cryptoKey)
	if err != nil {
		r.l.Warn("Can't create jwt token %v", err)
		return fiber.ErrInternalServerError
	}
	c.Set("Authorization", "Bearer "+tokenJWT)
	return c.JSON(fiber.Map{"token": tokenJWT})
}

// HandlerRegUser registers a new user and returns a JWT token.
//
// The flow is:
//  1. Parse the request body into UserInput.
//  2. Call RegUser (hashes the password, generates crypto salt, and inserts into DB).
//  3. Immediately authenticate (AuthUser) to verify the record and derive crypto key.
//  4. Generate a JWT (with crypto_key claim) and return it.
//
// @Summary      Register user
// @Description  Creates a new user account, authenticates it and returns a JWT token
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        input body request.UserInput true "New user credentials"
// @Success      200 {object} map[string]string "message"
// @Failure      409 {object} map[string]string "user already exists"
// @Failure      500 {object} map[string]string "internal server error"
// @Router       /api/user/register [post]
func (r *V1) HandlerRegUser(c *fiber.Ctx) error {
	var user request.UserInput
	if err := c.BodyParser(&user); err != nil {
		r.l.Warn("can't parse body for registr %v", err)
		return fiber.ErrInternalServerError
	}
	if err := r.t.RegUser(c.Context(), entity.UserInput{Login: user.Login, Password: user.Password}); err != nil {
		if errors.Is(err, domain.ErrConflict) {
			return fiber.ErrConflict
		} else {
			return fiber.ErrInternalServerError
		}
	}
	ok, cryptoKey, err := r.t.AuthUser(c.Context(), entity.UserInput{Login: user.Login, Password: user.Password})
	if err != nil || !ok {
		r.l.Warn("Can't auth user: %v", err)
		return fiber.ErrInternalServerError
	}

	tokenJWT, err := r.CreateJWT(user.Login, cryptoKey)
	if err != nil {
		r.l.Warn("Can't create jwt token %v", err)
		return fiber.ErrInternalServerError
	}

	c.Set("Authorization", "Bearer "+tokenJWT)

	return c.JSON(fiber.Map{"message": "User registered successfully", "token": tokenJWT})
}

// AuthUser is a helper that parses the request body and verifies
// the credentials via the auth usecase. Returns the username and
// derived crypto key on success.
func (r *V1) AuthUser(c *fiber.Ctx) (string, string, error) {
	var user request.UserInput
	if err := c.BodyParser(&user); err != nil {
		r.l.Warn("can't parse body for registr %v", err)
		return "", "", err
	}
	ok, cryptoKey, err := r.t.AuthUser(c.Context(), entity.UserInput{Login: user.Login, Password: user.Password})
	if err != nil || !ok {
		return "", "", fmt.Errorf("user not auth %v", user.Login)
	}
	return user.Login, cryptoKey, nil
}

// DeleteUser deletes the authenticated user's account.
//
// @Summary      Delete user
// @Description  Deletes the currently authenticated user's account
// @Tags         auth
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Success      200 {object} map[string]string "message"
// @Failure      401 {object} map[string]string "unauthorized"
// @Failure      500 {object} map[string]string "internal server error"
// @Router       /api/user/delete-user [delete]
func (r *V1) DeleteUser(c *fiber.Ctx) error {
	userToken := c.Locals("user").(*jwt.Token)
	claims := userToken.Claims.(jwt.MapClaims)
	username := claims["login"].(string)
	if err := r.t.DeleteUser(c.Context(), entity.UserInput{Login: username}); err != nil {
		return fiber.ErrInternalServerError
	}
	return c.JSON(fiber.Map{"message": "User deleted successfully"})
}
