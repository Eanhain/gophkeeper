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

func (r *V1) CreateJWT(username string) (string, error) {
	claims := jwt.MapClaims{
		"login": username,
		"exp":   time.Now().Add(time.Hour * 72).Unix(),
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
	username, err := r.AuthUser(c)
	if err != nil {
		r.l.Warn("Can't auth user: %v", err)
		return fiber.ErrUnauthorized
	}
	tokenJWT, err := r.CreateJWT(username)
	if err != nil {
		r.l.Warn("Can't create jwt token %v", err)
		return fiber.ErrInternalServerError
	}
	c.Set("Authorization", "Bearer "+tokenJWT)
	return c.JSON(fiber.Map{"token": tokenJWT})
}

// HandlerRegUser registers a new user and returns a JWT token.
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
	if ok, err := r.t.AuthUser(c.Context(), entity.UserInput{Login: user.Login, Password: user.Password}); err != nil || !ok {
		r.l.Warn("Can't auth user: %v", err)
		return fiber.ErrInternalServerError
	}

	tokenJWT, err := r.CreateJWT(user.Login)
	if err != nil {
		r.l.Warn("Can't create jwt token %v", err)
		return fiber.ErrInternalServerError
	}

	c.Set("Authorization", "Bearer "+tokenJWT)

	return c.JSON(fiber.Map{"message": "User registered successfully"})
}

func (r *V1) AuthUser(c *fiber.Ctx) (string, error) {
	var user request.UserInput
	if err := c.BodyParser(&user); err != nil {
		r.l.Warn("can't parse body for registr %v", err)
		return "", err
	}
	if ok, err := r.t.AuthUser(c.Context(), entity.UserInput{Login: user.Login, Password: user.Password}); err != nil || !ok {
		return "", fmt.Errorf("user not auth %v", user.Login)
	}
	return user.Login, c.JSON(fiber.Map{"message": "User authenticated successfully"})
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
