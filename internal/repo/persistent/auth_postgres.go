package persistent

import (
	"context"
	"fmt"

	"github.com/Eanhain/gophkeeper/domain"
	"github.com/Eanhain/gophkeeper/internal/entity"
	"github.com/Eanhain/gophkeeper/pkg/postgres"
	"github.com/Masterminds/squirrel"
)

// const _defaultEntityCap = 64

// AuthRepo -.
type AuthRepo struct {
	*postgres.Postgres
	log domain.LoggerI
}

// New -.
func New(pg *postgres.Postgres, log domain.LoggerI) *AuthRepo {
	return &AuthRepo{pg, log}
}

func (ps *AuthRepo) RegisterUser(ctx context.Context, user entity.User) error {
	sql, args, err := ps.Builder.
		Insert("users").
		Columns("username", "password_hash").
		Values(user.Login, user.Hash).
		ToSql()

	if err != nil {
		return fmt.Errorf("failed to build sql: %w", err)
	}

	tag, err := ps.Pool.Exec(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("can't register user %w, with user %v", err, user.Login)
	}

	ps.log.Info("User registered, rows affected: %d, user: %s", tag.RowsAffected(), user.Login)
	return nil
}

func (ps *AuthRepo) CheckUser(ctx context.Context, untrustedUser entity.UserInput) (entity.User, error) {
	var orUser entity.User

	sql, args, err := ps.Builder.
		Select("username", "password_hash").
		From("users").
		Where(squirrel.Eq{"username": untrustedUser.Login}).
		ToSql()

	if err != nil {
		return entity.User{}, fmt.Errorf("failed to build sql: %w", err)
	}

	row := ps.Pool.QueryRow(ctx, sql, args...)
	if err := row.Scan(&orUser.Login, &orUser.Hash); err != nil {
		return entity.User{}, err
	}

	ps.log.Info("Get trust user from db: %s", orUser.Login)
	return orUser, nil
}

func (ps *AuthRepo) GetUserID(ctx context.Context, username string) (int, error) {
	var id int

	sql, args, err := ps.Builder.
		Select("id").
		From("users").
		Where(squirrel.Eq{"username": username}).
		ToSql()

	if err != nil {
		return -1, fmt.Errorf("failed to build sql: %w", err)
	}

	row := ps.Pool.QueryRow(ctx, sql, args...)
	if err := row.Scan(&id); err != nil {
		return -1, err
	}
	return id, nil
}
