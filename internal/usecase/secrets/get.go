package secrets

import (
	"context"

	"github.com/Eanhain/gophkeeper/internal/entity"
)

func (s *SecretsUseCase) GetLoginPasswords(ctx context.Context, username string) ([]entity.LoginPassword, error) {
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return nil, err
	}
	return s.repo.GetLoginPasswords(ctx, userID)
}

func (s *SecretsUseCase) GetTextSecrets(ctx context.Context, username string) ([]entity.TextSecret, error) {
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return nil, err
	}
	return s.repo.GetTextSecrets(ctx, userID)
}

func (s *SecretsUseCase) GetBinarySecrets(ctx context.Context, username string) ([]entity.BinarySecret, error) {
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return nil, err
	}
	return s.repo.GetBinarySecrets(ctx, userID)
}

func (s *SecretsUseCase) GetCardSecrets(ctx context.Context, username string) ([]entity.CardSecret, error) {
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return nil, err
	}
	return s.repo.GetCardSecrets(ctx, userID)
}

func (s *SecretsUseCase) GetAllSecrets(ctx context.Context, username string) (entity.AllSecrets, error) {
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return entity.AllSecrets{}, err
	}
	return s.repo.GetAllSecrets(ctx, userID)
}
