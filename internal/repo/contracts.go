// Package repo defines repository interfaces for data access.
// Implementations live under repo/persistent and interact with PostgreSQL.
//
// The interfaces are consumed by the usecase layer, which never imports
// concrete repository types — this allows easy mocking in unit tests.
//
// cryptoKey parameters are hex-encoded per-user AES-256 encryption keys
// derived from user passwords via Argon2id. The repo encrypts/decrypts
// sensitive fields at the application level before storing in PostgreSQL.
package repo

import (
	"context"

	"github.com/Eanhain/gophkeeper/internal/entity"
)

//go:generate mockgen -source=contracts.go -destination=../usecase/mocks_repo_test.go -package=usecase_test

type (
	// AuthRepo provides user authentication and account management operations.
	AuthRepo interface {
		// RegisterUser inserts a new user record with a pre-hashed password and crypto salt.
		RegisterUser(ctx context.Context, users entity.User) error
		// CheckUser retrieves the stored user by login for password verification.
		CheckUser(ctx context.Context, users entity.UserInput) (entity.User, error)
		// GetUserID resolves a username string into the internal numeric user ID.
		GetUserID(ctx context.Context, user string) (int, error)
		// DeleteUser removes the user and all associated data by user ID.
		DeleteUser(ctx context.Context, userID int) error
	}

	// LoginPasswordRepo manages login-password secrets in the database.
	LoginPasswordRepo interface {
		CreateLoginPassword(ctx context.Context, lp entity.LoginPassword, cryptoKey string) error
		GetLoginPasswords(ctx context.Context, userID int, cryptoKey string) ([]entity.LoginPassword, error)
		DeleteLoginPassword(ctx context.Context, userID int, login string) error
	}

	// TextSecretRepo manages text-note secrets in the database.
	TextSecretRepo interface {
		CreateTextSecret(ctx context.Context, ts entity.TextSecret, cryptoKey string) error
		GetTextSecrets(ctx context.Context, userID int, cryptoKey string) ([]entity.TextSecret, error)
		DeleteTextSecret(ctx context.Context, userID int, title string) error
	}

	// BinarySecretRepo manages binary blob secrets in the database.
	BinarySecretRepo interface {
		CreateBinarySecret(ctx context.Context, bs entity.BinarySecret, cryptoKey string) error
		GetBinarySecrets(ctx context.Context, userID int, cryptoKey string) ([]entity.BinarySecret, error)
		DeleteBinarySecret(ctx context.Context, userID int, filename string) error
	}

	// CardSecretRepo manages bank card secrets in the database.
	CardSecretRepo interface {
		CreateCardSecret(ctx context.Context, cs entity.CardSecret, cryptoKey string) error
		GetCardSecrets(ctx context.Context, userID int, cryptoKey string) ([]entity.CardSecret, error)
		DeleteCardSecret(ctx context.Context, userID int, cardholder string) error
	}

	// SecretsRepo is the combined interface consumed by the secrets usecase.
	// It embeds all four per-type repos plus cross-cutting helpers.
	SecretsRepo interface {
		LoginPasswordRepo
		TextSecretRepo
		BinarySecretRepo
		CardSecretRepo
		// GetUserID resolves a username to its numeric ID.
		GetUserID(ctx context.Context, user string) (int, error)
		// GetAllSecrets returns every secret the user owns in a single call.
		GetAllSecrets(ctx context.Context, userID int, cryptoKey string) (entity.AllSecrets, error)
	}
)
