package delPostgres

import (
	"context"
	"fmt"

	"github.com/Eanhain/gophkeeper/domain"
	"github.com/Eanhain/gophkeeper/pkg/postgres"
	"github.com/Masterminds/squirrel"
)

// DeleteRepo -.
type DeleteRepo struct {
	*postgres.Postgres
	log domain.LoggerI
}

// New -.
func New(pg *postgres.Postgres, log domain.LoggerI) *DeleteRepo {
	return &DeleteRepo{pg, log}
}
func (ps *DeleteRepo) DeleteLoginPassword(ctx context.Context, userID int, login string) error {
	sql, args, err := ps.Builder.
		Delete("user_credentials").
		Where(squirrel.Eq{"user_id": userID, "login": login}).
		ToSql()
	if err != nil {
		return fmt.Errorf("failed to build sql: %w", err)
	}
	tag, err := ps.Pool.Exec(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("can't delete login password %w, with user id %d and login %s", err, userID, login)
	}
	ps.log.Info("Login password deleted, rows affected: %d, user id: %d, login: %s", tag.RowsAffected(), userID, login)
	return nil
}

func (ps *DeleteRepo) DeleteTextSecret(ctx context.Context, userID int, title string) error {
	sql, args, err := ps.Builder.
		Delete("user_text_items").
		Where(squirrel.Eq{"user_id": userID, "title": title}).
		ToSql()
	if err != nil {
		return fmt.Errorf("failed to build sql: %w", err)
	}
	tag, err := ps.Pool.Exec(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("can't delete text secret %w, with user id %d and title %s", err, userID, title)
	}
	ps.log.Info("Text secret deleted, rows affected: %d, user id: %d, title: %s", tag.RowsAffected(), userID, title)
	return nil
}

func (ps *DeleteRepo) DeleteBinarySecret(ctx context.Context, userID int, filename string) error {
	sql, args, err := ps.Builder.
		Delete("user_binary_items").
		Where(squirrel.Eq{"user_id": userID, "filename": filename}).
		ToSql()
	if err != nil {
		return fmt.Errorf("failed to build sql: %w", err)
	}
	tag, err := ps.Pool.Exec(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("can't delete binary secret %w, with user id %d and filename %s", err, userID, filename)
	}
	ps.log.Info("Binary secret deleted, rows affected: %d, user id: %d, filename: %s", tag.RowsAffected(), userID, filename)
	return nil
}

func (ps *DeleteRepo) DeleteCardSecret(ctx context.Context, userID int, cardholder string) error {
	sql, args, err := ps.Builder.
		Delete("user_cards").
		Where(squirrel.Eq{"user_id": userID, "cardholder": cardholder}).
		ToSql()
	if err != nil {
		return fmt.Errorf("failed to build sql: %w", err)
	}
	tag, err := ps.Pool.Exec(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("can't delete card secret %w, with user id %d and cardholder %s", err, userID, cardholder)
	}
	ps.log.Info("Card secret deleted, rows affected: %d, user id: %d, cardholder: %s", tag.RowsAffected(), userID, cardholder)
	return nil
}
