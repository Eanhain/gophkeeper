// Package v1 implements the REST API handlers for the /v1 route group.
//
// Architecture overview:
//
//	Client ──(encrypted)──> CryptoMiddleware ──(JSON)──> JWT check ──> Handler ──> UseCase ──> Repo ──> DB
//
// Each handler extracts the username from the JWT, parses the request body,
// calls the corresponding usecase method, and returns a JSON response.
// Errors from the usecase layer are mapped to HTTP codes by [usecaseErr].
package v1

import (
	"github.com/Eanhain/gophkeeper/domain"
	"github.com/Eanhain/gophkeeper/internal/usecase"
	"github.com/go-playground/validator/v10"
	jwtware "github.com/gofiber/contrib/jwt"
)

// V1 is the handler group for API version 1. It holds references to the
// auth and secret usecases, the logger, a struct validator, and the JWT
// middleware configuration. Separate instances are created for auth and
// secret route groups via NewAuthRoutes / NewSecretRoutes.
type V1 struct {
	t       usecase.AuthUseCase    // auth usecase (login, register, delete user)
	secrets usecase.SecretsUseCase // secrets usecase (CRUD for all secret types)
	l       domain.LoggerI         // structured logger
	v       *validator.Validate    // struct validator (currently unused, reserved)
	jwtConf jwtware.Config         // JWT middleware config (signing key, error handler)
}
