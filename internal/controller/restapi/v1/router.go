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

	{
		authGroup.Use(jwtware.New(r.jwtConf))
		authGroup.Delete("/delete-user", r.DeleteUser)
	}

}

func NewSecretRoutes(apiV1Group fiber.Router, t usecase.AuthUseCase, jwtConf jwtware.Config, l domain.LoggerI) {
	r := &V1{t: t, l: l, v: validator.New(validator.WithRequiredStructEnabled()), jwtConf: jwtConf}

	secretGroup := apiV1Group.Group("/api/user/secret/")

	{
		secretGroup.Use(jwtware.New(r.jwtConf))
		secretGroup.Delete("/delete-login-password", r.DeleteLoginPassword)
		secretGroup.Delete("/delete-text-secret", r.DeleteTextSecret)
		secretGroup.Delete("/delete-binary-secret", r.DeleteBinarySecret)
		secretGroup.Delete("/delete-card-secret", r.DeleteCardSecret)

		secretGroup.Get("/get-login-password", r.GetLoginPassword)
		secretGroup.Get("/get-text-secret", r.GetTextSecret)
		secretGroup.Get("/get-binary-secret", r.GetBinarySecret)
		secretGroup.Get("/get-card-secret", r.GetCardSecret)
		secretGroup.Get("/get-all-secrets", r.GetAllSecrets)

		secretGroup.Post("/post-login-password", r.PostLoginPassword)
		secretGroup.Post("/post-text-secret", r.PostTextSecret)
		secretGroup.Post("/post-binary-secret", r.PostBinarySecret)
		secretGroup.Post("/post-card-secret", r.PostCardSecret)
	}
}
