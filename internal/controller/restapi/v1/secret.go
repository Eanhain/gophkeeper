package v1

import (
	"errors"

	"github.com/Eanhain/gophkeeper/domain"
	res "github.com/Eanhain/gophkeeper/internal/controller/restapi/v1/request"
	resp "github.com/Eanhain/gophkeeper/internal/controller/restapi/v1/response"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

type BodySecret interface {
	res.LoginPassword | res.TextSecret |
		res.BinarySecret | res.CardSecret | res.Secret |
		res.DeleteLoginPassword | res.DeleteTextSecret |
		res.DeleteBinarySecret | res.DeleteCardSecret
}

func ParseBody[T BodySecret](c *fiber.Ctx) (string, T, error) {
	var rValue T
	userToken, ok := c.Locals("user").(*jwt.Token)
	if !ok {
		return "", rValue, fiber.ErrUnauthorized
	}
	claims, ok := userToken.Claims.(jwt.MapClaims)
	if !ok {
		return "", rValue, fiber.ErrUnauthorized
	}
	username, ok := claims["login"].(string)
	if !ok {
		return "", rValue, fiber.ErrUnauthorized
	}
	if err := c.BodyParser(&rValue); err != nil {
		return "", rValue, fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	return username, rValue, nil
}

func usecaseErr(err error) error {
	switch {
	case errors.Is(err, domain.ErrAlreadyExists):
		return fiber.NewError(fiber.StatusConflict, "already exists")
	case errors.Is(err, domain.ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "not found")
	case errors.Is(err, domain.ErrInvalidInput):
		return fiber.NewError(fiber.StatusBadRequest, "required fields missing or invalid")
	default:
		return fiber.ErrInternalServerError
	}
}

func extractUsername(c *fiber.Ctx) (string, error) {
	userToken, ok := c.Locals("user").(*jwt.Token)
	if !ok {
		return "", fiber.ErrUnauthorized
	}
	claims, ok := userToken.Claims.(jwt.MapClaims)
	if !ok {
		return "", fiber.ErrUnauthorized
	}
	username, ok := claims["login"].(string)
	if !ok {
		return "", fiber.ErrUnauthorized
	}
	return username, nil
}

// --- Delete ---

func (r *V1) DeleteLoginPassword(c *fiber.Ctx) error {
	login, body, err := ParseBody[res.DeleteLoginPassword](c)
	if err != nil {
		return err
	}
	if err := r.secrets.DeleteLoginPassword(c.Context(), login, body.Login); err != nil {
		return usecaseErr(err)
	}
	return c.JSON(fiber.Map{"message": "login password deleted"})
}

func (r *V1) DeleteTextSecret(c *fiber.Ctx) error {
	login, body, err := ParseBody[res.DeleteTextSecret](c)
	if err != nil {
		return err
	}
	if err := r.secrets.DeleteTextSecret(c.Context(), login, body.Title); err != nil {
		return usecaseErr(err)
	}
	return c.JSON(fiber.Map{"message": "text secret deleted"})
}

func (r *V1) DeleteBinarySecret(c *fiber.Ctx) error {
	login, body, err := ParseBody[res.DeleteBinarySecret](c)
	if err != nil {
		return err
	}
	if err := r.secrets.DeleteBinarySecret(c.Context(), login, body.Filename); err != nil {
		return usecaseErr(err)
	}
	return c.JSON(fiber.Map{"message": "binary secret deleted"})
}

func (r *V1) DeleteCardSecret(c *fiber.Ctx) error {
	login, body, err := ParseBody[res.DeleteCardSecret](c)
	if err != nil {
		return err
	}
	if err := r.secrets.DeleteCardSecret(c.Context(), login, body.Cardholder); err != nil {
		return usecaseErr(err)
	}
	return c.JSON(fiber.Map{"message": "card secret deleted"})
}

// --- Get ---

func (r *V1) GetLoginPassword(c *fiber.Ctx) error {
	username, err := extractUsername(c)
	if err != nil {
		return err
	}
	result, err := r.secrets.GetLoginPasswords(c.Context(), username)
	if err != nil {
		return usecaseErr(err)
	}
	return c.JSON(resp.FromLoginPasswords(result))
}

func (r *V1) GetTextSecret(c *fiber.Ctx) error {
	username, err := extractUsername(c)
	if err != nil {
		return err
	}
	result, err := r.secrets.GetTextSecrets(c.Context(), username)
	if err != nil {
		return usecaseErr(err)
	}
	return c.JSON(resp.FromTextSecrets(result))
}

func (r *V1) GetBinarySecret(c *fiber.Ctx) error {
	username, err := extractUsername(c)
	if err != nil {
		return err
	}
	result, err := r.secrets.GetBinarySecrets(c.Context(), username)
	if err != nil {
		return usecaseErr(err)
	}
	return c.JSON(resp.FromBinarySecrets(result))
}

func (r *V1) GetCardSecret(c *fiber.Ctx) error {
	username, err := extractUsername(c)
	if err != nil {
		return err
	}
	result, err := r.secrets.GetCardSecrets(c.Context(), username)
	if err != nil {
		return usecaseErr(err)
	}
	return c.JSON(resp.FromCardSecrets(result))
}

func (r *V1) GetAllSecrets(c *fiber.Ctx) error {
	username, err := extractUsername(c)
	if err != nil {
		return err
	}
	all, err := r.secrets.GetAllSecrets(c.Context(), username)
	if err != nil {
		return usecaseErr(err)
	}
	return c.JSON(resp.FromAllSecrets(all))
}

// --- Post ---

func (r *V1) PostLoginPassword(c *fiber.Ctx) error {
	login, body, err := ParseBody[res.LoginPassword](c)
	if err != nil {
		return err
	}
	if err := r.secrets.CreateLoginPassword(c.Context(), login, body); err != nil {
		return usecaseErr(err)
	}
	return c.JSON(fiber.Map{"message": "login password created"})
}

func (r *V1) PostTextSecret(c *fiber.Ctx) error {
	login, body, err := ParseBody[res.TextSecret](c)
	if err != nil {
		return err
	}
	if err := r.secrets.CreateTextSecret(c.Context(), login, body); err != nil {
		return usecaseErr(err)
	}
	return c.JSON(fiber.Map{"message": "text secret created"})
}

func (r *V1) PostBinarySecret(c *fiber.Ctx) error {
	login, body, err := ParseBody[res.BinarySecret](c)
	if err != nil {
		return err
	}
	if err := r.secrets.CreateBinarySecret(c.Context(), login, body); err != nil {
		return usecaseErr(err)
	}
	return c.JSON(fiber.Map{"message": "binary secret created"})
}

func (r *V1) PostCardSecret(c *fiber.Ctx) error {
	login, body, err := ParseBody[res.CardSecret](c)
	if err != nil {
		return err
	}
	if err := r.secrets.CreateCardSecret(c.Context(), login, body); err != nil {
		return usecaseErr(err)
	}
	return c.JSON(fiber.Map{"message": "card secret created"})
}
