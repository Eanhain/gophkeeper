package secrets

import (
	"github.com/Eanhain/gophkeeper/domain"
	"github.com/Eanhain/gophkeeper/internal/repo"
)

// SecretsUseCase -.
type SecretsUseCase struct {
	repo repo.SecretsRepo
	log  domain.LoggerI
}

// New -.
func New(r repo.SecretsRepo, log domain.LoggerI) *SecretsUseCase {
	return &SecretsUseCase{
		repo: r,
		log:  log,
	}
}
