// Package v1 implements routing paths. Each services in own file.
package restapi

import (
	"net/http"

	"github.com/Eanhain/gophkeeper/config"
	_ "github.com/Eanhain/gophkeeper/docs" // Swagger docs.
	"github.com/Eanhain/gophkeeper/domain"
	"github.com/Eanhain/gophkeeper/internal/controller/restapi/middleware"
	v1 "github.com/Eanhain/gophkeeper/internal/controller/restapi/v1"
	"github.com/Eanhain/gophkeeper/internal/usecase"
	jwtware "github.com/gofiber/contrib/jwt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/swagger"
)

// NewRouter -.
// Swagger spec:
// @title       Gophkeeper API
// @description Gophkeeper API
// @version     1.0
// @host        localhost:8080
// @BasePath    /v1
func NewRouter(app *fiber.App, cfg *config.Config, t usecase.AuthUseCase, l domain.LoggerI) {
	// Options
	app.Use(middleware.Logger(l))
	app.Use(middleware.Recovery(l))

	// Swagger
	if cfg.Swagger.Enabled {
		app.Get("/swagger/*", swagger.HandlerDefault)
	}

	// K8s probe
	app.Get("/healthz", func(ctx *fiber.Ctx) error { return ctx.SendStatus(http.StatusOK) })

	jwtConf := jwtware.Config{
		SigningKey: jwtware.SigningKey{Key: []byte(cfg.JWT.Secret)}, ErrorHandler: jwtError}

	// Routers
	apiV1Group := app.Group("/v1")
	{
		v1.NewAuthRoutes(apiV1Group, t, jwtConf, l)
	}
}
