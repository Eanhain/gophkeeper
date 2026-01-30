package secrets

import (
	"context"
	"fmt"

	"github.com/Eanhain/gophkeeper/internal/entity"
)

func (ps *SecretsRepo) PostLoginPassword(ctx context.Context, loginPassword entity.LoginPassword) error {
	sql, args, err := ps.Builder.
		Insert("user_credentials").
		Columns("user_id", "login", "password_enc", "label").
		Values(loginPassword.UserID, loginPassword.Login, loginPassword.Password, loginPassword.Label).
		ToSql()
	if err != nil {
		return fmt.Errorf("failed to build sql: %w", err)
	}
	tag, err := ps.Pool.Exec(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("can't post login password %w, with login password %v", err, loginPassword)
	}
	ps.log.Info("Login password posted, rows affected: %d, login password: %s", tag.RowsAffected(), loginPassword.Login)
	return nil
}

func (ps *SecretsRepo) PostTextSecret(ctx context.Context, textSecret entity.TextSecret) error {
	sql, args, err := ps.Builder.
		Insert("user_text_items").
		Columns("user_id", "title", "body").
		Values(textSecret.UserID, textSecret.Title, textSecret.Body).
		ToSql()
	if err != nil {
		return fmt.Errorf("failed to build sql: %w", err)
	}
	tag, err := ps.Pool.Exec(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("can't post text secret %w, with text secret %v", err, textSecret)
	}
	ps.log.Info("Text secret posted, rows affected: %d, text secret: %s", tag.RowsAffected(), textSecret.Title)
	return nil
}

func (ps *SecretsRepo) PostBinarySecret(ctx context.Context, binarySecret entity.BinarySecret) error {
	sql, args, err := ps.Builder.
		Insert("user_binary_items").
		Columns("user_id", "filename", "mime_type", "data").
		Values(binarySecret.UserID, binarySecret.Filename, binarySecret.MimeType, binarySecret.Data).
		ToSql()
	if err != nil {
		return fmt.Errorf("failed to build sql: %w", err)
	}
	tag, err := ps.Pool.Exec(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("can't post binary secret %w, with binary secret %v", err, binarySecret)
	}
	ps.log.Info("Binary secret posted, rows affected: %d, binary secret: %s", tag.RowsAffected(), binarySecret.Filename)
	return nil
}

func (ps *SecretsRepo) PostCardSecret(ctx context.Context, cardSecret entity.CardSecret) error {
	sql, args, err := ps.Builder.
		Insert("user_cards").
		Columns("user_id", "cardholder", "pan_enc", "exp_month", "exp_year", "brand", "last4").
		Values(cardSecret.UserID, cardSecret.Cardholder, cardSecret.Pan, cardSecret.ExpMonth, cardSecret.ExpYear, cardSecret.Brand, cardSecret.Last4).
		ToSql()
	if err != nil {
		return fmt.Errorf("failed to build sql: %w", err)
	}
	tag, err := ps.Pool.Exec(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("can't post card secret %w, with card secret %v", err, cardSecret)
	}
	ps.log.Info("Card secret posted, rows affected: %d, card secret: %s", tag.RowsAffected(), cardSecret.Cardholder)
	return nil
}
