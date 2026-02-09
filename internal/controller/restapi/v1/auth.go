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

func (r *V1) DeleteUser(c *fiber.Ctx) error {
	userToken := c.Locals("user").(*jwt.Token)
	claims := userToken.Claims.(jwt.MapClaims)
	username := claims["login"].(string)
	if err := r.t.DeleteUser(c.Context(), entity.UserInput{Login: username}); err != nil {
		return fiber.ErrInternalServerError
	}
	return c.JSON(fiber.Map{"message": "User deleted successfully"})
}
