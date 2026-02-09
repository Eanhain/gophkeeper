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
//  3. CryptoMiddleware — AES-256-GCM request/response encryption (v1 group only)
//  4. JWT middleware   — token validation (per route group)
//
// Swagger spec:
//
// @title       Gophkeeper API
// @description GophKeeper — secure vault for passwords, text notes, binary data and bank cards.
// @description
// @description ## Encryption Protocol
// @description All request/response bodies under /v1 are **AES-256-GCM encrypted**.
// @description The encryption key is derived as `SHA-256(CRYPTO_KEY)` — both client and server must share the same `CRYPTO_KEY`.
// @description
// @description ### Request flow (client → server):
// @description 1. Serialize the JSON payload.
// @description 2. Encrypt with AES-256-GCM: `nonce (12 bytes) || ciphertext`.
// @description 3. Send the raw bytes with `Content-Type: application/octet-stream`.
// @description
// @description ### Response flow (server → client):
// @description 1. Server handler produces JSON.
// @description 2. CryptoMiddleware encrypts it: `nonce (12 bytes) || ciphertext`.
// @description 3. Response is sent with `Content-Type: application/octet-stream`.
// @description 4. Client decrypts to get the original JSON.
// @description
// @description **Note:** Swagger "Try it out" will NOT work because the UI sends plain JSON. Use the GophKeeper TUI client or encrypt requests manually.
// @description
// @description ### Using the API without encryption
// @description The REST API **cannot** be called with plain JSON — the CryptoMiddleware will reject unencrypted bodies with HTTP 400.
// @description To test manually, use a script that encrypts/decrypts with the shared key (see `gophkeeper-client/internal/crypto`).
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

	// API v1 — all traffic encrypted with CryptoMiddleware.
	apiV1Group := app.Group("/v1")
	apiV1Group.Use(middleware.CryptoMiddleware(cfg.Crypto.Key))
	{
		v1.NewAuthRoutes(apiV1Group, t, jwtConf, l)
		v1.NewSecretRoutes(apiV1Group, s, jwtConf, l)
	}
}
