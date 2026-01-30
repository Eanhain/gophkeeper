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

// UseCase -.
type UseCase struct {
	repo repo.AuthRepo
	log  domain.LoggerI
}

// New -.
func New(r repo.AuthRepo, log domain.LoggerI) *UseCase {
	return &UseCase{
		repo: r,
		log:  log,
	}
}

func (s *UseCase) AuthUser(ctx context.Context, user entity.UserInput) (bool, error) {
	tUser, err := s.repo.CheckUser(ctx, user)
	if err != nil {
		return false, err
	}
	ok := hash.VerifyUserHash(s.log, user, tUser)
	return ok, nil
}

func (s *UseCase) RegUser(ctx context.Context, user entity.UserInput) error {
	var pgErr *pgconn.PgError
	hashedUser := hash.CreateUserHash(s.log, user)
	err := s.repo.RegisterUser(ctx, hashedUser)

	if errors.As(err, &pgErr) && pgerrcode.IsIntegrityConstraintViolation(pgErr.Code) {
		err = domain.ErrConflict
		return err
	}
	_, err = s.repo.GetUserID(ctx, user.Login)
	if err != nil {
		return err
	}

	return err
}
