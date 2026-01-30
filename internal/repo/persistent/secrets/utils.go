package secrets

import (
	"context"
	"fmt"

	"github.com/Eanhain/gophkeeper/internal/entity"
	"github.com/Masterminds/squirrel"
)

func (ps *SecretsRepo) CheckUser(ctx context.Context, untrustedUser entity.UserInput) (entity.User, error) {
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

func (ps *SecretsRepo) GetUserID(ctx context.Context, username string) (int, error) {
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
