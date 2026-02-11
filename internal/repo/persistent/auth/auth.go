// Package auth implements the repo.AuthRepo interface backed by PostgreSQL.
//
// It uses squirrel as the SQL query builder and pgx as the PostgreSQL driver.
package auth

import (
	"context"
	"fmt"

	"github.com/Eanhain/gophkeeper/domain"
	"github.com/Eanhain/gophkeeper/internal/entity"
	"github.com/Eanhain/gophkeeper/pkg/postgres"
	"github.com/Masterminds/squirrel"
)

// AuthRepo is the PostgreSQL-backed implementation of repo.AuthRepo.
type AuthRepo struct {
	*postgres.Postgres
	log domain.LoggerI
}

// New creates a new AuthRepo with the given connection pool and logger.
func New(pg *postgres.Postgres, log domain.LoggerI) *AuthRepo {
	return &AuthRepo{pg, log}
}

// RegisterUser inserts a new user into the "users" table.
// The user's password must already be hashed (see usecase/hash).
// CryptoSalt is stored alongside the user for per-user encryption key derivation.
func (ps *AuthRepo) RegisterUser(ctx context.Context, user entity.User) error {
	sql, args, err := ps.Builder.
		Insert("users").
		Columns("username", "password_hash", "crypto_salt").
		Values(user.Login, user.Hash, user.CryptoSalt).
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

// CheckUser fetches the stored username, password hash and crypto salt by login.
// The caller (usecase/auth) then compares the hash with the provided password
// and derives the encryption key from password + salt.
func (ps *AuthRepo) CheckUser(ctx context.Context, untrustedUser entity.UserInput) (entity.User, error) {
	var orUser entity.User

	sql, args, err := ps.Builder.
		Select("username", "password_hash", "crypto_salt").
		From("users").
		Where(squirrel.Eq{"username": untrustedUser.Login}).
		ToSql()

	if err != nil {
		return entity.User{}, fmt.Errorf("failed to build sql: %w", err)
	}

	row := ps.Pool.QueryRow(ctx, sql, args...)
	if err := row.Scan(&orUser.Login, &orUser.Hash, &orUser.CryptoSalt); err != nil {
		return entity.User{}, err
	}

	ps.log.Info("Get trust user from db: %s", orUser.Login)
	return orUser, nil
}

// GetUserID resolves a username to the numeric "id" primary key.
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

// DeleteUser removes a user row by its numeric ID.
// Cascade deletion of related secrets is handled by the DB schema.
func (ps *AuthRepo) DeleteUser(ctx context.Context, userID int) error {
	sql, args, err := ps.Builder.
		Delete("users").
		Where(squirrel.Eq{"id": userID}).
		ToSql()
	if err != nil {
		return fmt.Errorf("failed to build sql: %w", err)
	}
	tag, err := ps.Pool.Exec(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("can't delete user %w, with user id %d", err, userID)
	}
	ps.log.Info("User deleted, rows affected: %d, user id: %d", tag.RowsAffected(), userID)
	return nil
}
