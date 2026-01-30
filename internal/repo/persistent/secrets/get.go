package secrets

import (
	"context"
	"fmt"

	"github.com/Eanhain/gophkeeper/internal/entity"
	"github.com/Masterminds/squirrel"
)


func (ps *SecretsRepo) GetLoginPassword(ctx context.Context, userID int) ([]entity.LoginPassword, error) {
	sql, args, err := ps.Builder.
		Select("user_id", "login", "password_enc", "label").
		From("user_credentials").
		Where(squirrel.Eq{"user_id": userID}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("failed to build sql: %w", err)
	}
	rows, err := ps.Pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("can't get login password %w, with user id %d", err, userID)
	}
	defer rows.Close()

	var result []entity.LoginPassword
	for rows.Next() {
		var loginPassword entity.LoginPassword
		err = rows.Scan(&loginPassword.UserID, &loginPassword.Login, &loginPassword.Password, &loginPassword.Label)
		if err != nil {
			return nil, fmt.Errorf("can't scan login password %w", err)
		}
		result = append(result, loginPassword)
	}
	return result, nil
}

func (ps *SecretsRepo) GetTextSecret(ctx context.Context, userID int) ([]entity.TextSecret, error) {
	sql, args, err := ps.Builder.
		Select("user_id", "title", "body").
		From("user_text_items").
		Where(squirrel.Eq{"user_id": userID}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("failed to build sql: %w", err)
	}
	rows, err := ps.Pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("can't get text secret %w, with user id %d", err, userID)
	}
	defer rows.Close()

	var result []entity.TextSecret
	for rows.Next() {
		var textSecret entity.TextSecret
		err = rows.Scan(&textSecret.UserID, &textSecret.Title, &textSecret.Body)
		if err != nil {
			return nil, fmt.Errorf("can't scan text secret %w", err)
		}
		result = append(result, textSecret)
	}
	return result, nil
}

func (ps *SecretsRepo) GetBinarySecret(ctx context.Context, userID int) ([]entity.BinarySecret, error) {
	sql, args, err := ps.Builder.
		Select("user_id", "filename", "mime_type", "data").
		From("user_binary_items").
		Where(squirrel.Eq{"user_id": userID}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("failed to build sql: %w", err)
	}
	rows, err := ps.Pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("can't get binary secret %w, with user id %d", err, userID)
	}
	defer rows.Close()

	var result []entity.BinarySecret
	for rows.Next() {
		var binarySecret entity.BinarySecret
		err = rows.Scan(&binarySecret.UserID, &binarySecret.Filename, &binarySecret.MimeType, &binarySecret.Data)
		if err != nil {
			return nil, fmt.Errorf("can't scan binary secret %w", err)
		}
		result = append(result, binarySecret)
	}
	return result, nil
}

func (ps *SecretsRepo) GetCardSecret(ctx context.Context, userID int) ([]entity.CardSecret, error) {
	sql, args, err := ps.Builder.
		Select("user_id", "cardholder", "pan_enc", "exp_month", "exp_year", "brand", "last4").
		From("user_cards").
		Where(squirrel.Eq{"user_id": userID}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("failed to build sql: %w", err)
	}
	rows, err := ps.Pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("can't get card secret %w, with user id %d", err, userID)
	}
	defer rows.Close()

	var result []entity.CardSecret
	for rows.Next() {
		var cardSecret entity.CardSecret
		err = rows.Scan(&cardSecret.UserID, &cardSecret.Cardholder, &cardSecret.Pan, &cardSecret.ExpMonth, &cardSecret.ExpYear, &cardSecret.Brand, &cardSecret.Last4)
		if err != nil {
			return nil, fmt.Errorf("can't scan card secret %w", err)
		}
		result = append(result, cardSecret)
	}
	return result, nil
}
