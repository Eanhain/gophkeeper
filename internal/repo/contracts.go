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
)
