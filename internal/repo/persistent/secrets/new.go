package secrets

import (
	"github.com/Eanhain/gophkeeper/domain"
	"github.com/Eanhain/gophkeeper/pkg/postgres"
)

// AuthRepo -.
type SecretsRepo struct {
	*postgres.Postgres
	log domain.LoggerI
}

// New -.
func New(pg *postgres.Postgres, log domain.LoggerI) *SecretsRepo {
	return &SecretsRepo{pg, log}
}
