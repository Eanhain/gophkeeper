package secrets

import (
	"context"

	"github.com/Eanhain/gophkeeper/internal/entity"
)

func (s *SecretsUseCase) GetLoginPassword(ctx context.Context, username string, login string) ([]entity.LoginPassword, error) {
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return nil, err
	}
	return s.repo.GetLoginPassword(ctx, userID, login)
}

func (s *SecretsUseCase) GetTextSecret(ctx context.Context, username string, title string) ([]entity.TextSecret, error) {
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return nil, err
	}
	return s.repo.GetTextSecret(ctx, userID, title)
}

func (s *SecretsUseCase) GetBinarySecret(ctx context.Context, username string, filename string) ([]entity.BinarySecret, error) {
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return nil, err
	}
	return s.repo.GetBinarySecret(ctx, userID, filename)
}

func (s *SecretsUseCase) GetCardSecret(ctx context.Context, username string, cardholder string) ([]entity.CardSecret, error) {
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return nil, err
	}
	return s.repo.GetCardSecret(ctx, userID, cardholder)
}

func (s *SecretsUseCase) GetAllSecrets(ctx context.Context, username string) (entity.AllSecrets, error) {
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return entity.AllSecrets{}, err
	}
	return s.repo.GetAllSecrets(ctx, userID)
}
