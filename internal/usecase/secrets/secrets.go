// Package secrets implements CRUD business logic for the four secret types:
// login-password, text, binary and card.
//
// Every method first resolves the user's numeric ID from their JWT username
// via repo.GetUserID, then delegates to the corresponding repository method.
// Non-sensitive identifiers (login, title, filename, cardholder) are validated
// to be non-empty; sensitive fields (password, body, data, PAN) are intentionally
// NOT validated to avoid leaking information about stored secrets.
package secrets

import (
	"context"

	"github.com/Eanhain/gophkeeper/domain"
	"github.com/Eanhain/gophkeeper/internal/controller/restapi/v1/request"
	"github.com/Eanhain/gophkeeper/internal/entity"
	"github.com/Eanhain/gophkeeper/internal/repo"
)

// UseCase holds the dependencies for secret operations.
type UseCase struct {
	repo repo.SecretsRepo
	log  domain.LoggerI
}

// New creates a new secrets UseCase.
func New(r repo.SecretsRepo, log domain.LoggerI) *UseCase {
	return &UseCase{repo: r, log: log}
}

// CreateLoginPassword stores a new login-password pair.
// Returns domain.ErrInvalidInput if Login is empty.
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

// CreateTextSecret stores a new text note.
// Returns domain.ErrInvalidInput if Title is empty.
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

// CreateBinarySecret stores a new binary blob.
// Returns domain.ErrInvalidInput if Filename is empty.
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

// CreateCardSecret stores a new bank card.
// Returns domain.ErrInvalidInput if Cardholder is empty.
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

// GetLoginPasswords returns every login-password record owned by the user.
func (s *UseCase) GetLoginPasswords(ctx context.Context, username string) ([]entity.LoginPassword, error) {
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return nil, err
	}
	return s.repo.GetLoginPasswords(ctx, userID)
}

// GetTextSecrets returns every text secret owned by the user.
func (s *UseCase) GetTextSecrets(ctx context.Context, username string) ([]entity.TextSecret, error) {
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return nil, err
	}
	return s.repo.GetTextSecrets(ctx, userID)
}

// GetBinarySecrets returns every binary secret owned by the user.
func (s *UseCase) GetBinarySecrets(ctx context.Context, username string) ([]entity.BinarySecret, error) {
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return nil, err
	}
	return s.repo.GetBinarySecrets(ctx, userID)
}

// GetCardSecrets returns every card secret owned by the user.
func (s *UseCase) GetCardSecrets(ctx context.Context, username string) ([]entity.CardSecret, error) {
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return nil, err
	}
	return s.repo.GetCardSecrets(ctx, userID)
}

// GetAllSecrets fetches all secret types in a single call.
func (s *UseCase) GetAllSecrets(ctx context.Context, username string) (entity.AllSecrets, error) {
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return entity.AllSecrets{}, err
	}
	return s.repo.GetAllSecrets(ctx, userID)
}

// DeleteLoginPassword removes a login-password by its login identifier.
// Returns domain.ErrInvalidInput if the identifier is empty.
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

// DeleteTextSecret removes a text secret by its title.
// Returns domain.ErrInvalidInput if the title is empty.
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

// DeleteBinarySecret removes a binary secret by filename.
// Returns domain.ErrInvalidInput if the filename is empty.
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

// DeleteCardSecret removes a card secret by cardholder name.
// Returns domain.ErrInvalidInput if cardholder is empty.
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
