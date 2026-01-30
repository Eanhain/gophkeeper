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

	PostRepo interface {
		PostLoginPassword(ctx context.Context, loginPassword entity.LoginPassword) error
		PostTextSecret(ctx context.Context, textSecret entity.TextSecret) error
		PostBinarySecret(ctx context.Context, binarySecret entity.BinarySecret) error
		PostCardSecret(ctx context.Context, cardSecret entity.CardSecret) error
	}

	GetRepo interface {
		GetLoginPassword(ctx context.Context, userID int, login string) ([]entity.LoginPassword, error)
		GetTextSecret(ctx context.Context, userID int, title string) ([]entity.TextSecret, error)
		GetBinarySecret(ctx context.Context, userID int, filename string) ([]entity.BinarySecret, error)
		GetCardSecret(ctx context.Context, userID int, cardholder string) ([]entity.CardSecret, error)
	}

	DeleteRepo interface {
		DeleteLoginPassword(ctx context.Context, userID int, login string) error
		DeleteTextSecret(ctx context.Context, userID int, title string) error
		DeleteBinarySecret(ctx context.Context, userID int, filename string) error
		DeleteCardSecret(ctx context.Context, userID int, cardholder string) error
	}

	ShareRepo interface {
		CheckUser(ctx context.Context, users entity.UserInput) (entity.User, error)
		GetUserID(ctx context.Context, user string) (int, error)
	}
)
