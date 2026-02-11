// Package usecase defines the business-logic interfaces consumed by
// the controller (handler) layer. Concrete implementations live in
// sub-packages: usecase/auth and usecase/secrets.
//
// The controller never depends on concrete types — only on these
// interfaces — enabling straightforward mock-based testing.
package usecase

import (
	"context"

	"github.com/Eanhain/gophkeeper/internal/controller/restapi/v1/request"
	"github.com/Eanhain/gophkeeper/internal/entity"
)

//go:generate mockgen -source=interfaces.go -destination=./mocks_usecase_test.go -package=usecase_test

type (
	// AuthUseCase covers user authentication, registration and deletion.
	AuthUseCase interface {
		// AuthUser checks credentials and returns (ok, cryptoKey, error).
		// cryptoKey is a hex-encoded per-user AES-256 encryption key
		// derived from the password via Argon2id.
		AuthUser(context.Context, entity.UserInput) (bool, string, error)
		// RegUser registers a new user. Returns domain.ErrConflict on duplicate.
		RegUser(context.Context, entity.UserInput) error
		// DeleteUser removes a user account by login.
		DeleteUser(context.Context, entity.UserInput) error
	}

	// LoginPasswordUseCase provides CRUD for login-password secrets.
	// cryptoKey is the hex-encoded per-user AES-256 encryption key.
	LoginPasswordUseCase interface {
		CreateLoginPassword(ctx context.Context, username, cryptoKey string, lp request.LoginPassword) error
		GetLoginPasswords(ctx context.Context, username, cryptoKey string) ([]entity.LoginPassword, error)
		DeleteLoginPassword(ctx context.Context, username, cryptoKey string, login string) error
	}

	// TextSecretUseCase provides CRUD for text-note secrets.
	TextSecretUseCase interface {
		CreateTextSecret(ctx context.Context, username, cryptoKey string, ts request.TextSecret) error
		GetTextSecrets(ctx context.Context, username, cryptoKey string) ([]entity.TextSecret, error)
		DeleteTextSecret(ctx context.Context, username, cryptoKey string, title string) error
	}

	// BinarySecretUseCase provides CRUD for binary blob secrets.
	BinarySecretUseCase interface {
		CreateBinarySecret(ctx context.Context, username, cryptoKey string, bs request.BinarySecret) error
		GetBinarySecrets(ctx context.Context, username, cryptoKey string) ([]entity.BinarySecret, error)
		DeleteBinarySecret(ctx context.Context, username, cryptoKey string, filename string) error
	}

	// CardSecretUseCase provides CRUD for bank card secrets.
	CardSecretUseCase interface {
		CreateCardSecret(ctx context.Context, username, cryptoKey string, cs request.CardSecret) error
		GetCardSecrets(ctx context.Context, username, cryptoKey string) ([]entity.CardSecret, error)
		DeleteCardSecret(ctx context.Context, username, cryptoKey string, cardholder string) error
	}

	// SecretsUseCase is the combined interface injected into the secret
	// handlers. It embeds all four per-type usecases plus GetAllSecrets.
	SecretsUseCase interface {
		LoginPasswordUseCase
		TextSecretUseCase
		BinarySecretUseCase
		CardSecretUseCase
		// GetAllSecrets returns every secret owned by the user in one call.
		GetAllSecrets(ctx context.Context, username, cryptoKey string) (entity.AllSecrets, error)
	}
)
