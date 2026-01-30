package secrets

import (
	"context"
)

func (s *SecretsUseCase) DeleteLoginPassword(ctx context.Context, username string, login string) error {
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return err
	}
	return s.repo.DeleteLoginPassword(ctx, userID, login)
}

func (s *SecretsUseCase) DeleteTextSecret(ctx context.Context, username string, title string) error {
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return err
	}
	return s.repo.DeleteTextSecret(ctx, userID, title)
}

func (s *SecretsUseCase) DeleteBinarySecret(ctx context.Context, username string, filename string) error {
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return err
	}
	return s.repo.DeleteBinarySecret(ctx, userID, filename)
}

func (s *SecretsUseCase) DeleteCardSecret(ctx context.Context, username string, cardholder string) error {
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return err
	}
	return s.repo.DeleteCardSecret(ctx, userID, cardholder)
}
