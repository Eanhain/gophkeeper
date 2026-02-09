package v1

import (
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
		return "", rValue, err
	}
	return username, rValue, nil
}

func (r *V1) DeleteLoginPassword(c *fiber.Ctx) error {
	login, body, err := ParseBody[res.DeleteLoginPassword](c)
	if err != nil {
		return err
	}
	r.secrets.DeleteLoginPassword(c.Context(), login, body.Login)
	return nil
}

func (r *V1) DeleteTextSecret(c *fiber.Ctx) error {
	login, body, err := ParseBody[res.DeleteTextSecret](c)
	if err != nil {
		return err
	}
	r.secrets.DeleteTextSecret(c.Context(), login, body.Title)
	return nil
}

func (r *V1) DeleteBinarySecret(c *fiber.Ctx) error {
	login, body, err := ParseBody[res.DeleteBinarySecret](c)
	if err != nil {
		return err
	}
	r.secrets.DeleteBinarySecret(c.Context(), login, body.Filename)
	return nil
}

func (r *V1) DeleteCardSecret(c *fiber.Ctx) error {
	login, body, err := ParseBody[res.DeleteCardSecret](c)
	if err != nil {
		return err
	}
	r.secrets.DeleteCardSecret(c.Context(), login, body.Cardholder)
	return nil
}

func (r *V1) GetLoginPassword(c *fiber.Ctx) error {
	userToken, ok := c.Locals("user").(*jwt.Token)
	if !ok {
		return fiber.ErrUnauthorized
	}
	claims, ok := userToken.Claims.(jwt.MapClaims)
	if !ok {
		return fiber.ErrUnauthorized
	}
	username, ok := claims["login"].(string)
	if !ok {
		return fiber.ErrUnauthorized
	}
	loginPasswords, err := r.secrets.GetLoginPasswords(c.Context(), username)
	if err != nil {
		return err
	}
	return c.JSON(resp.FromLoginPasswords(loginPasswords))
}

func (r *V1) GetTextSecret(c *fiber.Ctx) error {
	userToken, ok := c.Locals("user").(*jwt.Token)
	if !ok {
		return fiber.ErrUnauthorized
	}
	claims, ok := userToken.Claims.(jwt.MapClaims)
	if !ok {
		return fiber.ErrUnauthorized
	}
	username, ok := claims["login"].(string)
	if !ok {
		return fiber.ErrUnauthorized
	}
	textSecrets, err := r.secrets.GetTextSecrets(c.Context(), username)
	if err != nil {
		return err
	}
	return c.JSON(resp.FromTextSecrets(textSecrets))
}

func (r *V1) GetBinarySecret(c *fiber.Ctx) error {
	userToken, ok := c.Locals("user").(*jwt.Token)
	if !ok {
		return fiber.ErrUnauthorized
	}
	claims, ok := userToken.Claims.(jwt.MapClaims)
	if !ok {
		return fiber.ErrUnauthorized
	}
	username, ok := claims["login"].(string)
	if !ok {
		return fiber.ErrUnauthorized
	}
	binarySecrets, err := r.secrets.GetBinarySecrets(c.Context(), username)
	if err != nil {
		return err
	}
	return c.JSON(resp.FromBinarySecrets(binarySecrets))
}

func (r *V1) GetCardSecret(c *fiber.Ctx) error {
	userToken, ok := c.Locals("user").(*jwt.Token)
	if !ok {
		return fiber.ErrUnauthorized
	}
	claims, ok := userToken.Claims.(jwt.MapClaims)
	if !ok {
		return fiber.ErrUnauthorized
	}
	username, ok := claims["login"].(string)
	if !ok {
		return fiber.ErrUnauthorized
	}
	cardSecrets, err := r.secrets.GetCardSecrets(c.Context(), username)
	if err != nil {
		return err
	}
	return c.JSON(resp.FromCardSecrets(cardSecrets))
}

func (r *V1) GetAllSecrets(c *fiber.Ctx) error {
	userToken, ok := c.Locals("user").(*jwt.Token)
	if !ok {
		return fiber.ErrUnauthorized
	}
	claims, ok := userToken.Claims.(jwt.MapClaims)
	if !ok {
		return fiber.ErrUnauthorized
	}
	username, ok := claims["login"].(string)
	if !ok {
		return fiber.ErrUnauthorized
	}
	allSecrets, err := r.secrets.GetAllSecrets(c.Context(), username)
	if err != nil {
		return err
	}
	return c.JSON(resp.FromAllSecrets(allSecrets))
}

func (r *V1) PostLoginPassword(c *fiber.Ctx) error {
	login, body, err := ParseBody[res.LoginPassword](c)
	if err != nil {
		return err
	}
	r.secrets.CreateLoginPassword(c.Context(), login, body)
	return c.JSON(fiber.Map{"message": "Login password created"})
}

func (r *V1) PostTextSecret(c *fiber.Ctx) error {
	login, body, err := ParseBody[res.TextSecret](c)
	if err != nil {
		return err
	}
	r.secrets.CreateTextSecret(c.Context(), login, body)
	return c.JSON(fiber.Map{"message": "Text secret created"})
}

func (r *V1) PostBinarySecret(c *fiber.Ctx) error {
	login, body, err := ParseBody[res.BinarySecret](c)
	if err != nil {
		return err
	}
	r.secrets.CreateBinarySecret(c.Context(), login, body)
	return c.JSON(fiber.Map{"message": "Binary secret created"})
}

func (r *V1) PostCardSecret(c *fiber.Ctx) error {
	login, body, err := ParseBody[res.CardSecret](c)
	if err != nil {
		return err
	}
	r.secrets.CreateCardSecret(c.Context(), login, body)
	return c.JSON(fiber.Map{"message": "Card secret created"})
}
