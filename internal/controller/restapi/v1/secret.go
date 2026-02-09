package v1

import (
	"errors"

	"github.com/Eanhain/gophkeeper/domain"
	res "github.com/Eanhain/gophkeeper/internal/controller/restapi/v1/request"
	resp "github.com/Eanhain/gophkeeper/internal/controller/restapi/v1/response"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

// BodySecret is a type constraint that lists all request structs
// accepted by the generic ParseBody function.
type BodySecret interface {
	res.LoginPassword | res.TextSecret |
		res.BinarySecret | res.CardSecret | res.Secret |
		res.DeleteLoginPassword | res.DeleteTextSecret |
		res.DeleteBinarySecret | res.DeleteCardSecret
}

// ParseBody is a generic helper that:
//  1. Extracts the username from the JWT token stored in fiber.Ctx.Locals.
//  2. Parses the JSON request body into the concrete type T.
//
// Returns the username and the parsed struct, or an appropriate fiber.Error.
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

// usecaseErr maps a domain/usecase error to the corresponding
// fiber.Error with the correct HTTP status code:
//
//	domain.ErrAlreadyExists → 409 Conflict
//	domain.ErrNotFound      → 404 Not Found
//	domain.ErrInvalidInput  → 400 Bad Request
//	anything else           → 500 Internal Server Error
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

// extractUsername extracts the "login" claim from the JWT token
// stored in c.Locals("user"). Used by GET handlers that have
// no request body to parse.
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

// DeleteLoginPassword removes a login-password secret by login identifier.
//
// @Summary      Delete login-password
// @Description  Deletes a stored login-password secret identified by the login field
// @Tags         secrets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        input body request.DeleteLoginPassword true "Login identifier to delete"
// @Success      200 {object} map[string]string "message"
// @Failure      400 {object} map[string]string "required fields missing or invalid"
// @Failure      401 {object} map[string]string "unauthorized"
// @Failure      404 {object} map[string]string "not found"
// @Failure      500 {object} map[string]string "internal server error"
// @Router       /api/user/secret/delete-login-password [delete]
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

// DeleteTextSecret removes a text secret by title identifier.
//
// @Summary      Delete text secret
// @Description  Deletes a stored text secret identified by the title field
// @Tags         secrets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        input body request.DeleteTextSecret true "Title identifier to delete"
// @Success      200 {object} map[string]string "message"
// @Failure      400 {object} map[string]string "required fields missing or invalid"
// @Failure      401 {object} map[string]string "unauthorized"
// @Failure      404 {object} map[string]string "not found"
// @Failure      500 {object} map[string]string "internal server error"
// @Router       /api/user/secret/delete-text-secret [delete]
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

// DeleteBinarySecret removes a binary secret by filename identifier.
//
// @Summary      Delete binary secret
// @Description  Deletes a stored binary secret identified by the filename field
// @Tags         secrets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        input body request.DeleteBinarySecret true "Filename identifier to delete"
// @Success      200 {object} map[string]string "message"
// @Failure      400 {object} map[string]string "required fields missing or invalid"
// @Failure      401 {object} map[string]string "unauthorized"
// @Failure      404 {object} map[string]string "not found"
// @Failure      500 {object} map[string]string "internal server error"
// @Router       /api/user/secret/delete-binary-secret [delete]
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

// DeleteCardSecret removes a card secret by cardholder identifier.
//
// @Summary      Delete card secret
// @Description  Deletes a stored card secret identified by the cardholder field
// @Tags         secrets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        input body request.DeleteCardSecret true "Cardholder identifier to delete"
// @Success      200 {object} map[string]string "message"
// @Failure      400 {object} map[string]string "required fields missing or invalid"
// @Failure      401 {object} map[string]string "unauthorized"
// @Failure      404 {object} map[string]string "not found"
// @Failure      500 {object} map[string]string "internal server error"
// @Router       /api/user/secret/delete-card-secret [delete]
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

// GetLoginPassword returns all login-password secrets for the authenticated user.
//
// @Summary      Get login-passwords
// @Description  Returns all stored login-password secrets for the current user
// @Tags         secrets
// @Produce      json
// @Security     BearerAuth
// @Success      200 {array}  response.LoginPassword
// @Failure      401 {object} map[string]string "unauthorized"
// @Failure      500 {object} map[string]string "internal server error"
// @Router       /api/user/secret/get-login-password [get]
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

// GetTextSecret returns all text secrets for the authenticated user.
//
// @Summary      Get text secrets
// @Description  Returns all stored text secrets for the current user
// @Tags         secrets
// @Produce      json
// @Security     BearerAuth
// @Success      200 {array}  response.TextSecret
// @Failure      401 {object} map[string]string "unauthorized"
// @Failure      500 {object} map[string]string "internal server error"
// @Router       /api/user/secret/get-text-secret [get]
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

// GetBinarySecret returns all binary secrets for the authenticated user.
//
// @Summary      Get binary secrets
// @Description  Returns all stored binary secrets for the current user
// @Tags         secrets
// @Produce      json
// @Security     BearerAuth
// @Success      200 {array}  response.BinarySecret
// @Failure      401 {object} map[string]string "unauthorized"
// @Failure      500 {object} map[string]string "internal server error"
// @Router       /api/user/secret/get-binary-secret [get]
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

// GetCardSecret returns all card secrets for the authenticated user.
//
// @Summary      Get card secrets
// @Description  Returns all stored card secrets for the current user
// @Tags         secrets
// @Produce      json
// @Security     BearerAuth
// @Success      200 {array}  response.CardSecret
// @Failure      401 {object} map[string]string "unauthorized"
// @Failure      500 {object} map[string]string "internal server error"
// @Router       /api/user/secret/get-card-secret [get]
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

// GetAllSecrets returns all secrets of all types for the authenticated user.
//
// @Summary      Get all secrets
// @Description  Returns all stored secrets (login-passwords, text, binary, cards) for the current user
// @Tags         secrets
// @Produce      json
// @Security     BearerAuth
// @Success      200 {object} response.AllSecrets
// @Failure      401 {object} map[string]string "unauthorized"
// @Failure      500 {object} map[string]string "internal server error"
// @Router       /api/user/secret/get-all-secrets [get]
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

// PostLoginPassword creates a new login-password secret.
//
// @Summary      Create login-password
// @Description  Stores a new login-password secret for the authenticated user
// @Tags         secrets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        input body request.LoginPassword true "Login-password data"
// @Success      200 {object} map[string]string "message"
// @Failure      400 {object} map[string]string "required fields missing or invalid"
// @Failure      401 {object} map[string]string "unauthorized"
// @Failure      409 {object} map[string]string "already exists"
// @Failure      500 {object} map[string]string "internal server error"
// @Router       /api/user/secret/post-login-password [post]
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

// PostTextSecret creates a new text secret.
//
// @Summary      Create text secret
// @Description  Stores a new text secret for the authenticated user
// @Tags         secrets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        input body request.TextSecret true "Text secret data"
// @Success      200 {object} map[string]string "message"
// @Failure      400 {object} map[string]string "required fields missing or invalid"
// @Failure      401 {object} map[string]string "unauthorized"
// @Failure      409 {object} map[string]string "already exists"
// @Failure      500 {object} map[string]string "internal server error"
// @Router       /api/user/secret/post-text-secret [post]
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

// PostBinarySecret creates a new binary secret.
//
// @Summary      Create binary secret
// @Description  Stores a new binary secret (file) for the authenticated user. Data should be base64-encoded.
// @Tags         secrets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        input body request.BinarySecret true "Binary secret data"
// @Success      200 {object} map[string]string "message"
// @Failure      400 {object} map[string]string "required fields missing or invalid"
// @Failure      401 {object} map[string]string "unauthorized"
// @Failure      409 {object} map[string]string "already exists"
// @Failure      500 {object} map[string]string "internal server error"
// @Router       /api/user/secret/post-binary-secret [post]
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

// PostCardSecret creates a new card secret.
//
// @Summary      Create card secret
// @Description  Stores a new bank card secret for the authenticated user
// @Tags         secrets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        input body request.CardSecret true "Card secret data"
// @Success      200 {object} map[string]string "message"
// @Failure      400 {object} map[string]string "required fields missing or invalid"
// @Failure      401 {object} map[string]string "unauthorized"
// @Failure      409 {object} map[string]string "already exists"
// @Failure      500 {object} map[string]string "internal server error"
// @Router       /api/user/secret/post-card-secret [post]
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
