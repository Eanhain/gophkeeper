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
		// AuthUser checks credentials and returns true if they match.
		AuthUser(context.Context, entity.UserInput) (bool, error)
		// RegUser registers a new user. Returns domain.ErrConflict on duplicate.
		RegUser(context.Context, entity.UserInput) error
		// DeleteUser removes a user account by login.
		DeleteUser(context.Context, entity.UserInput) error
	}

	// LoginPasswordUseCase provides CRUD for login-password secrets.
	LoginPasswordUseCase interface {
		CreateLoginPassword(ctx context.Context, username string, lp request.LoginPassword) error
		GetLoginPasswords(ctx context.Context, username string) ([]entity.LoginPassword, error)
		DeleteLoginPassword(ctx context.Context, username string, login string) error
	}

	// TextSecretUseCase provides CRUD for text-note secrets.
	TextSecretUseCase interface {
		CreateTextSecret(ctx context.Context, username string, ts request.TextSecret) error
		GetTextSecrets(ctx context.Context, username string) ([]entity.TextSecret, error)
		DeleteTextSecret(ctx context.Context, username string, title string) error
	}

	// BinarySecretUseCase provides CRUD for binary blob secrets.
	BinarySecretUseCase interface {
		CreateBinarySecret(ctx context.Context, username string, bs request.BinarySecret) error
		GetBinarySecrets(ctx context.Context, username string) ([]entity.BinarySecret, error)
		DeleteBinarySecret(ctx context.Context, username string, filename string) error
	}

	// CardSecretUseCase provides CRUD for bank card secrets.
	CardSecretUseCase interface {
		CreateCardSecret(ctx context.Context, username string, cs request.CardSecret) error
		GetCardSecrets(ctx context.Context, username string) ([]entity.CardSecret, error)
		DeleteCardSecret(ctx context.Context, username string, cardholder string) error
	}

	// SecretsUseCase is the combined interface injected into the secret
	// handlers. It embeds all four per-type usecases plus GetAllSecrets.
	SecretsUseCase interface {
		LoginPasswordUseCase
		TextSecretUseCase
		BinarySecretUseCase
		CardSecretUseCase
		// GetAllSecrets returns every secret owned by the user in one call.
		GetAllSecrets(ctx context.Context, username string) (entity.AllSecrets, error)
	}
)
