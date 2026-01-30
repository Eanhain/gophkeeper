// Package usecase implements application business logic. Each logic group in own file.
package usecase

import (
	"context"

	"github.com/Eanhain/gophkeeper/internal/entity"
)

//go:generate mockgen -source=interfaces.go -destination=./mocks_usecase_test.go -package=usecase_test

type (
	// AuthUseCase -.
	AuthUseCase interface {
		AuthUser(context.Context, entity.UserInput) (bool, error)
		RegUser(context.Context, entity.UserInput) error
		DeleteUser(context.Context, entity.UserInput) error
	}
)
