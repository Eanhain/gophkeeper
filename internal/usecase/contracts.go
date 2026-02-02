// Package usecase implements application business logic. Each logic group in own file.
package usecase

import (
	"context"

	"github.com/Eanhain/gophkeeper/internal/controller/restapi/v1/request"
	"github.com/Eanhain/gophkeeper/internal/entity"
)

//go:generate mockgen -source=interfaces.go -destination=./mocks_usecase_test.go -package=usecase_test

type (
	// AuthUseCase - сценарии аутентификации
	AuthUseCase interface {
		AuthUser(context.Context, entity.UserInput) (bool, error)
		RegUser(context.Context, entity.UserInput) error
		DeleteUser(context.Context, entity.UserInput) error
	}

	// LoginPasswordUseCase - сценарии для логинов/паролей
	LoginPasswordUseCase interface {
		CreateLoginPassword(ctx context.Context, username string, lp request.LoginPassword) error
		GetLoginPasswords(ctx context.Context, username string) ([]entity.LoginPassword, error)
		DeleteLoginPassword(ctx context.Context, username string, login string) error
	}

	// TextSecretUseCase - сценарии для текстовых секретов
	TextSecretUseCase interface {
		CreateTextSecret(ctx context.Context, username string, ts request.TextSecret) error
		GetTextSecrets(ctx context.Context, username string) ([]entity.TextSecret, error)
		DeleteTextSecret(ctx context.Context, username string, title string) error
	}

	// BinarySecretUseCase - сценарии для бинарных секретов
	BinarySecretUseCase interface {
		CreateBinarySecret(ctx context.Context, username string, bs request.BinarySecret) error
		GetBinarySecrets(ctx context.Context, username string) ([]entity.BinarySecret, error)
		DeleteBinarySecret(ctx context.Context, username string, filename string) error
	}

	// CardSecretUseCase - сценарии для карт
	CardSecretUseCase interface {
		CreateCardSecret(ctx context.Context, username string, cs request.CardSecret) error
		GetCardSecrets(ctx context.Context, username string) ([]entity.CardSecret, error)
		DeleteCardSecret(ctx context.Context, username string, cardholder string) error
	}

	// SecretsUseCase - комбинированный интерфейс
	SecretsUseCase interface {
		LoginPasswordUseCase
		TextSecretUseCase
		BinarySecretUseCase
		CardSecretUseCase
		GetAllSecrets(ctx context.Context, username string) (entity.AllSecrets, error)
	}
)
