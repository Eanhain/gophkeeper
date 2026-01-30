// Package app configures and runs application.
package app

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Eanhain/gophkeeper/config"
	"github.com/Eanhain/gophkeeper/internal/controller/restapi"
	"github.com/Eanhain/gophkeeper/internal/repo/persistent"
	"github.com/Eanhain/gophkeeper/internal/usecase/auth"
	"github.com/Eanhain/gophkeeper/pkg/httpserver"
	"github.com/Eanhain/gophkeeper/pkg/logger"
	"github.com/Eanhain/gophkeeper/pkg/postgres"
)

// Run creates objects via constructors.
func Run(cfg *config.Config) { //nolint: gocyclo,cyclop,funlen,gocritic,nolintlint
	l := logger.New(cfg.Log.Level)

	// Repository
	pg, err := postgres.New(cfg.PG.URL, postgres.MaxPoolSize(cfg.PG.PoolMax))
	if err != nil {
		l.Fatal(fmt.Errorf("app - Run - postgres.New: %w", err))
	}
	defer pg.Close()

	// Use-Case
	authUseCase := auth.New(
		persistent.New(pg, l),
	)

	// HTTP Server
	httpServer := httpserver.New(l, httpserver.Port(cfg.HTTP.Port), httpserver.Prefork(cfg.HTTP.UsePreforkMode))

	restapi.NewRouter(httpServer.App, cfg, authUseCase, l)

	httpServer.Start()

	// Waiting signal
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	select {
	case s := <-interrupt:
		l.Info("app - Run - signal: %s", s.String())
	case err = <-httpServer.Notify():
		l.Error(fmt.Errorf("app - Run - httpServer.Notify: %w", err))
	}

	// Shutdown
	err = httpServer.Shutdown()
	if err != nil {
		l.Error(fmt.Errorf("app - Run - httpServer.Shutdown: %w", err))
	}

}
