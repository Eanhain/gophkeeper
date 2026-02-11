// Package restapi wires together the Fiber application, global middleware
// and route groups. It is the outermost layer of the onion architecture
// and depends on the usecase interfaces.
package restapi

import (
	"net/http"

	"github.com/Eanhain/gophkeeper/config"
	"github.com/Eanhain/gophkeeper/domain"
	"github.com/Eanhain/gophkeeper/internal/controller/restapi/middleware"
	v1 "github.com/Eanhain/gophkeeper/internal/controller/restapi/v1"
	"github.com/Eanhain/gophkeeper/internal/usecase"
	jwtware "github.com/gofiber/contrib/jwt"
	"github.com/gofiber/fiber/v2"
	fiberLogger "github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/swagger"
)

// NewRouter initialises all middleware and registers the API v1 routes.
//
// Middleware chain (order matters):
//  1. fiberLogger — structured JSON access logs
//  2. Recovery    — panic recovery with stack trace logging
//  3. JWT middleware   — token validation (per route group)
//
// Data at rest is encrypted per-user using AES-256-GCM with keys derived
// from user passwords via Argon2. Transport security is handled by TLS.
//
// @title       Gophkeeper API
// @description GophKeeper — secure vault for passwords, text notes, binary data and bank cards.
// @description
// @description ## Security
// @description Data at rest is encrypted per-user with AES-256-GCM.
// @description Encryption keys are derived from user passwords using Argon2id.
// @description Transport security should be provided by TLS.
// @version     1.0
// @host        localhost:8080
// @BasePath    /v1
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description JWT token obtained from /api/user/login. Format: "Bearer {token}"
func NewRouter(app *fiber.App, cfg *config.Config, t usecase.AuthUseCase, s usecase.SecretsUseCase, l domain.LoggerI) {

	app.Use(fiberLogger.New(fiberLogger.Config{
		Format:     `{"ip":"${ip}","method":"${method}","path":"${path}","status":${status},"latency":"${latency}","resBody":${resBody},"time":"${time}"}\n`,
		TimeFormat: "2006-01-02 15:04:05",
		TimeZone:   "UTC",
	}))
	app.Use(middleware.Recovery(l))

	// Swagger UI (only when enabled in config).
	if cfg.Swagger.Enabled {
		app.Get("/swagger/*", swagger.HandlerDefault)
	}

	// Kubernetes liveness / readiness probe.
	app.Get("/healthz", func(ctx *fiber.Ctx) error { return ctx.SendStatus(http.StatusOK) })

	jwtConf := jwtware.Config{
		SigningKey: jwtware.SigningKey{Key: []byte(cfg.JWT.Secret)}, ErrorHandler: jwtError}

	// API v1 — JSON over TLS (CryptoMiddleware removed per security review).
	apiV1Group := app.Group("/v1")
	{
		v1.NewAuthRoutes(apiV1Group, t, jwtConf, l)
		v1.NewSecretRoutes(apiV1Group, s, jwtConf, l)
	}
}
