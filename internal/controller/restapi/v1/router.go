package v1

import (
	"github.com/Eanhain/gophkeeper/domain"
	"github.com/Eanhain/gophkeeper/internal/usecase"
	"github.com/go-playground/validator/v10"
	jwtware "github.com/gofiber/contrib/jwt"
	"github.com/gofiber/fiber/v2"
)

// NewAuthRoutes -.
func NewAuthRoutes(apiV1Group fiber.Router, t usecase.AuthUseCase, jwtConf jwtware.Config, l domain.LoggerI) {
	r := &V1{t: t, l: l, v: validator.New(validator.WithRequiredStructEnabled()), jwtConf: jwtConf}

	authGroup := apiV1Group.Group("/api/user/")

	{
		authGroup.Post("/register", r.HandlerRegUser)
		authGroup.Post("/login", r.LoginJWT)
	}
}
