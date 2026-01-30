// Package repo implements application outer layer logic. Each logic group in own file.
package repo

import (
	"context"

	"github.com/Eanhain/gophkeeper/internal/entity"
)

//go:generate mockgen -source=contracts.go -destination=../usecase/mocks_repo_test.go -package=usecase_test

type (
	// AuthRepo -.
	AuthRepo interface {
		RegisterUser(ctx context.Context, users entity.User) error
		CheckUser(ctx context.Context, users entity.UserInput) (entity.User, error)
		GetUserID(ctx context.Context, user string) (int, error)
		DeleteUser(ctx context.Context, userID int) error
	}

	// LoginPasswordRepo - репозиторий для работы с логинами/паролями
	LoginPasswordRepo interface {
		CreateLoginPassword(ctx context.Context, lp entity.LoginPassword) error
		GetLoginPasswords(ctx context.Context, userID int) ([]entity.LoginPassword, error)
		DeleteLoginPassword(ctx context.Context, userID int, login string) error
	}

	// TextSecretRepo - репозиторий для работы с текстовыми секретами
	TextSecretRepo interface {
		CreateTextSecret(ctx context.Context, ts entity.TextSecret) error
		GetTextSecrets(ctx context.Context, userID int) ([]entity.TextSecret, error)
		DeleteTextSecret(ctx context.Context, userID int, title string) error
	}

	// BinarySecretRepo - репозиторий для работы с бинарными секретами
	BinarySecretRepo interface {
		CreateBinarySecret(ctx context.Context, bs entity.BinarySecret) error
		GetBinarySecrets(ctx context.Context, userID int) ([]entity.BinarySecret, error)
		DeleteBinarySecret(ctx context.Context, userID int, filename string) error
	}

	// CardSecretRepo - репозиторий для работы с картами
	CardSecretRepo interface {
		CreateCardSecret(ctx context.Context, cs entity.CardSecret) error
		GetCardSecrets(ctx context.Context, userID int) ([]entity.CardSecret, error)
		DeleteCardSecret(ctx context.Context, userID int, cardholder string) error
	}

	// SecretsRepo - комбинированный интерфейс для usecase
	SecretsRepo interface {
		LoginPasswordRepo
		TextSecretRepo
		BinarySecretRepo
		CardSecretRepo
		GetUserID(ctx context.Context, user string) (int, error)
		GetAllSecrets(ctx context.Context, userID int) (entity.AllSecrets, error)
	}
)
