// Package auth implements the authentication business logic:
// user registration, login verification, and account deletion.
//
// Password hashing (argon2id) is delegated to the hash sub-package.
// The repository layer is accessed through the repo.AuthRepo interface,
// making this package fully testable with mocks.
package auth

import (
	"context"
	"errors"

	"github.com/Eanhain/gophkeeper/domain"
	"github.com/Eanhain/gophkeeper/internal/entity"
	"github.com/Eanhain/gophkeeper/internal/repo"
	"github.com/Eanhain/gophkeeper/internal/usecase/hash"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
)

// UseCase holds the dependencies needed for authentication operations.
type UseCase struct {
	repo repo.AuthRepo
	log  domain.LoggerI
}

// New creates a new auth UseCase with the given repository and logger.
func New(r repo.AuthRepo, log domain.LoggerI) *UseCase {
	return &UseCase{
		repo: r,
		log:  log,
	}
}

// AuthUser verifies the user's credentials and derives the per-user
// encryption key from the password and stored salt using Argon2id.
// Returns (true, cryptoKey, nil) when the credentials are valid.
// The cryptoKey is a hex-encoded 32-byte AES-256 key.
func (s *UseCase) AuthUser(ctx context.Context, user entity.UserInput) (bool, string, error) {
	tUser, err := s.repo.CheckUser(ctx, user)
	if err != nil {
		return false, "", err
	}
	ok := hash.VerifyUserHash(s.log, user, tUser)
	if !ok {
		return false, "", nil
	}
	cryptoKey := hash.DeriveEncryptionKey(user.Password, tUser.CryptoSalt)
	return true, cryptoKey, nil
}

// RegUser registers a new user. The password is hashed with argon2id
// and a random crypto salt is generated before being persisted.
// If the username already exists (PostgreSQL unique-constraint violation),
// domain.ErrConflict is returned.
func (s *UseCase) RegUser(ctx context.Context, user entity.UserInput) error {
	var pgErr *pgconn.PgError
	hashedUser := hash.CreateUserHash(s.log, user)
	err := s.repo.RegisterUser(ctx, hashedUser)

	if errors.As(err, &pgErr) && pgerrcode.IsIntegrityConstraintViolation(pgErr.Code) {
		err = domain.ErrConflict
		return err
	}
	if err != nil {
		return err
	}

	return nil
}

// DeleteUser removes the user account and all associated data.
// The user is identified by their login; the internal numeric ID
// is resolved via repo.GetUserID.
func (s *UseCase) DeleteUser(ctx context.Context, user entity.UserInput) error {
	userID, err := s.repo.GetUserID(ctx, user.Login)
	if err != nil {
		return err
	}
	return s.repo.DeleteUser(ctx, userID)
}
