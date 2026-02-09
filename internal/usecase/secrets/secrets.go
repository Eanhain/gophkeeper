package secrets

import (
	"context"

	"github.com/Eanhain/gophkeeper/domain"
	"github.com/Eanhain/gophkeeper/internal/controller/restapi/v1/request"
	"github.com/Eanhain/gophkeeper/internal/entity"
	"github.com/Eanhain/gophkeeper/internal/repo"
)

type UseCase struct {
	repo repo.SecretsRepo
	log  domain.LoggerI
}

func New(r repo.SecretsRepo, log domain.LoggerI) *UseCase {
	return &UseCase{repo: r, log: log}
}

func (s *UseCase) CreateLoginPassword(ctx context.Context, username string, lp request.LoginPassword) error {
	if lp.Login == "" {
		return domain.ErrInvalidInput
	}
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return err
	}
	return s.repo.CreateLoginPassword(ctx, entity.LoginPassword{
		UserID: userID, Login: lp.Login, Password: lp.Password, Label: lp.Label,
	})
}

func (s *UseCase) CreateTextSecret(ctx context.Context, username string, ts request.TextSecret) error {
	if ts.Title == "" {
		return domain.ErrInvalidInput
	}
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return err
	}
	return s.repo.CreateTextSecret(ctx, entity.TextSecret{
		UserID: userID, Title: ts.Title, Body: ts.Body,
	})
}

func (s *UseCase) CreateBinarySecret(ctx context.Context, username string, bs request.BinarySecret) error {
	if bs.Filename == "" {
		return domain.ErrInvalidInput
	}
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return err
	}
	return s.repo.CreateBinarySecret(ctx, entity.BinarySecret{
		UserID: userID, Filename: bs.Filename, MimeType: bs.MimeType, Data: bs.Data,
	})
}

func (s *UseCase) CreateCardSecret(ctx context.Context, username string, cs request.CardSecret) error {
	if cs.Cardholder == "" {
		return domain.ErrInvalidInput
	}
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return err
	}
	return s.repo.CreateCardSecret(ctx, entity.CardSecret{
		UserID: userID, Cardholder: cs.Cardholder, Pan: cs.Pan,
		ExpMonth: cs.ExpMonth, ExpYear: cs.ExpYear, Brand: cs.Brand, Last4: cs.Last4,
	})
}

func (s *UseCase) GetLoginPasswords(ctx context.Context, username string) ([]entity.LoginPassword, error) {
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return nil, err
	}
	return s.repo.GetLoginPasswords(ctx, userID)
}

func (s *UseCase) GetTextSecrets(ctx context.Context, username string) ([]entity.TextSecret, error) {
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return nil, err
	}
	return s.repo.GetTextSecrets(ctx, userID)
}

func (s *UseCase) GetBinarySecrets(ctx context.Context, username string) ([]entity.BinarySecret, error) {
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return nil, err
	}
	return s.repo.GetBinarySecrets(ctx, userID)
}

func (s *UseCase) GetCardSecrets(ctx context.Context, username string) ([]entity.CardSecret, error) {
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return nil, err
	}
	return s.repo.GetCardSecrets(ctx, userID)
}

func (s *UseCase) GetAllSecrets(ctx context.Context, username string) (entity.AllSecrets, error) {
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return entity.AllSecrets{}, err
	}
	return s.repo.GetAllSecrets(ctx, userID)
}

func (s *UseCase) DeleteLoginPassword(ctx context.Context, username string, login string) error {
	if login == "" {
		return domain.ErrInvalidInput
	}
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return err
	}
	return s.repo.DeleteLoginPassword(ctx, userID, login)
}

func (s *UseCase) DeleteTextSecret(ctx context.Context, username string, title string) error {
	if title == "" {
		return domain.ErrInvalidInput
	}
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return err
	}
	return s.repo.DeleteTextSecret(ctx, userID, title)
}

func (s *UseCase) DeleteBinarySecret(ctx context.Context, username string, filename string) error {
	if filename == "" {
		return domain.ErrInvalidInput
	}
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return err
	}
	return s.repo.DeleteBinarySecret(ctx, userID, filename)
}

func (s *UseCase) DeleteCardSecret(ctx context.Context, username string, cardholder string) error {
	if cardholder == "" {
		return domain.ErrInvalidInput
	}
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return err
	}
	return s.repo.DeleteCardSecret(ctx, userID, cardholder)
}
