package secrets

import (
	"context"
	"fmt"

	"github.com/Eanhain/gophkeeper/domain"
	"github.com/Eanhain/gophkeeper/internal/entity"
	"github.com/Eanhain/gophkeeper/pkg/postgres"
	"github.com/Masterminds/squirrel"
)

// Repo реализует все интерфейсы секретов
type Repo struct {
	*postgres.Postgres
	log domain.LoggerI
}

// New создаёт новый репозиторий секретов
func New(pg *postgres.Postgres, log domain.LoggerI) *Repo {
	return &Repo{pg, log}
}

func (r *Repo) CreateLoginPassword(ctx context.Context, lp entity.LoginPassword) error {
	sql, args, err := r.Builder.
		Insert("user_credentials").
		Columns("user_id", "login", "password_enc", "label").
		Values(lp.UserID, lp.Login, lp.Password, lp.Label).
		ToSql()
	if err != nil {
		return fmt.Errorf("failed to build sql: %w", err)
	}
	tag, err := r.Pool.Exec(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("can't create login password: %w", err)
	}
	r.log.Info("Login password created, rows affected: %d, login: %s", tag.RowsAffected(), lp.Login)
	return nil
}

func (r *Repo) GetLoginPasswords(ctx context.Context, userID int) ([]entity.LoginPassword, error) {
	sql, args, err := r.Builder.
		Select("user_id", "login", "password_enc", "label").
		From("user_credentials").
		Where(squirrel.Eq{"user_id": userID}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("failed to build sql: %w", err)
	}
	rows, err := r.Pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("can't get login passwords: %w", err)
	}
	defer rows.Close()

	var result []entity.LoginPassword
	for rows.Next() {
		var lp entity.LoginPassword
		if err := rows.Scan(&lp.UserID, &lp.Login, &lp.Password, &lp.Label); err != nil {
			return nil, fmt.Errorf("can't scan login password: %w", err)
		}
		result = append(result, lp)
	}
	return result, nil
}

func (r *Repo) DeleteLoginPassword(ctx context.Context, userID int, login string) error {
	sql, args, err := r.Builder.
		Delete("user_credentials").
		Where(squirrel.Eq{"user_id": userID, "login": login}).
		ToSql()
	if err != nil {
		return fmt.Errorf("failed to build sql: %w", err)
	}
	tag, err := r.Pool.Exec(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("can't delete login password: %w", err)
	}
	r.log.Info("Login password deleted, rows affected: %d", tag.RowsAffected())
	return nil
}

func (r *Repo) CreateTextSecret(ctx context.Context, ts entity.TextSecret) error {
	sql, args, err := r.Builder.
		Insert("user_text_items").
		Columns("user_id", "title", "body").
		Values(ts.UserID, ts.Title, ts.Body).
		ToSql()
	if err != nil {
		return fmt.Errorf("failed to build sql: %w", err)
	}
	tag, err := r.Pool.Exec(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("can't create text secret: %w", err)
	}
	r.log.Info("Text secret created, rows affected: %d, title: %s", tag.RowsAffected(), ts.Title)
	return nil
}

func (r *Repo) GetTextSecrets(ctx context.Context, userID int) ([]entity.TextSecret, error) {
	sql, args, err := r.Builder.
		Select("user_id", "title", "body").
		From("user_text_items").
		Where(squirrel.Eq{"user_id": userID}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("failed to build sql: %w", err)
	}
	rows, err := r.Pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("can't get text secrets: %w", err)
	}
	defer rows.Close()

	var result []entity.TextSecret
	for rows.Next() {
		var ts entity.TextSecret
		if err := rows.Scan(&ts.UserID, &ts.Title, &ts.Body); err != nil {
			return nil, fmt.Errorf("can't scan text secret: %w", err)
		}
		result = append(result, ts)
	}
	return result, nil
}

func (r *Repo) DeleteTextSecret(ctx context.Context, userID int, title string) error {
	sql, args, err := r.Builder.
		Delete("user_text_items").
		Where(squirrel.Eq{"user_id": userID, "title": title}).
		ToSql()
	if err != nil {
		return fmt.Errorf("failed to build sql: %w", err)
	}
	tag, err := r.Pool.Exec(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("can't delete text secret: %w", err)
	}
	r.log.Info("Text secret deleted, rows affected: %d", tag.RowsAffected())
	return nil
}

func (r *Repo) CreateBinarySecret(ctx context.Context, bs entity.BinarySecret) error {
	sql, args, err := r.Builder.
		Insert("user_binary_items").
		Columns("user_id", "filename", "mime_type", "data").
		Values(bs.UserID, bs.Filename, bs.MimeType, bs.Data).
		ToSql()
	if err != nil {
		return fmt.Errorf("failed to build sql: %w", err)
	}
	tag, err := r.Pool.Exec(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("can't create binary secret: %w", err)
	}
	r.log.Info("Binary secret created, rows affected: %d, filename: %s", tag.RowsAffected(), bs.Filename)
	return nil
}

func (r *Repo) GetBinarySecrets(ctx context.Context, userID int) ([]entity.BinarySecret, error) {
	sql, args, err := r.Builder.
		Select("user_id", "filename", "mime_type", "data").
		From("user_binary_items").
		Where(squirrel.Eq{"user_id": userID}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("failed to build sql: %w", err)
	}
	rows, err := r.Pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("can't get binary secrets: %w", err)
	}
	defer rows.Close()

	var result []entity.BinarySecret
	for rows.Next() {
		var bs entity.BinarySecret
		if err := rows.Scan(&bs.UserID, &bs.Filename, &bs.MimeType, &bs.Data); err != nil {
			return nil, fmt.Errorf("can't scan binary secret: %w", err)
		}
		result = append(result, bs)
	}
	return result, nil
}

func (r *Repo) DeleteBinarySecret(ctx context.Context, userID int, filename string) error {
	sql, args, err := r.Builder.
		Delete("user_binary_items").
		Where(squirrel.Eq{"user_id": userID, "filename": filename}).
		ToSql()
	if err != nil {
		return fmt.Errorf("failed to build sql: %w", err)
	}
	tag, err := r.Pool.Exec(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("can't delete binary secret: %w", err)
	}
	r.log.Info("Binary secret deleted, rows affected: %d", tag.RowsAffected())
	return nil
}

func (r *Repo) CreateCardSecret(ctx context.Context, cs entity.CardSecret) error {
	sql, args, err := r.Builder.
		Insert("user_cards").
		Columns("user_id", "cardholder", "pan_enc", "exp_month", "exp_year", "brand", "last4").
		Values(cs.UserID, cs.Cardholder, cs.Pan, cs.ExpMonth, cs.ExpYear, cs.Brand, cs.Last4).
		ToSql()
	if err != nil {
		return fmt.Errorf("failed to build sql: %w", err)
	}
	tag, err := r.Pool.Exec(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("can't create card secret: %w", err)
	}
	r.log.Info("Card secret created, rows affected: %d, cardholder: %s", tag.RowsAffected(), cs.Cardholder)
	return nil
}

func (r *Repo) GetCardSecrets(ctx context.Context, userID int) ([]entity.CardSecret, error) {
	sql, args, err := r.Builder.
		Select("user_id", "cardholder", "pan_enc", "exp_month", "exp_year", "brand", "last4").
		From("user_cards").
		Where(squirrel.Eq{"user_id": userID}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("failed to build sql: %w", err)
	}
	rows, err := r.Pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("can't get card secrets: %w", err)
	}
	defer rows.Close()

	var result []entity.CardSecret
	for rows.Next() {
		var cs entity.CardSecret
		if err := rows.Scan(&cs.UserID, &cs.Cardholder, &cs.Pan, &cs.ExpMonth, &cs.ExpYear, &cs.Brand, &cs.Last4); err != nil {
			return nil, fmt.Errorf("can't scan card secret: %w", err)
		}
		result = append(result, cs)
	}
	return result, nil
}

func (r *Repo) DeleteCardSecret(ctx context.Context, userID int, cardholder string) error {
	sql, args, err := r.Builder.
		Delete("user_cards").
		Where(squirrel.Eq{"user_id": userID, "cardholder": cardholder}).
		ToSql()
	if err != nil {
		return fmt.Errorf("failed to build sql: %w", err)
	}
	tag, err := r.Pool.Exec(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("can't delete card secret: %w", err)
	}
	r.log.Info("Card secret deleted, rows affected: %d", tag.RowsAffected())
	return nil
}

func (r *Repo) GetUserID(ctx context.Context, username string) (int, error) {
	sql, args, err := r.Builder.
		Select("id").
		From("users").
		Where(squirrel.Eq{"username": username}).
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("failed to build sql: %w", err)
	}
	var userID int
	err = r.Pool.QueryRow(ctx, sql, args...).Scan(&userID)
	if err != nil {
		return 0, fmt.Errorf("can't get user id: %w", err)
	}
	return userID, nil
}

func (r *Repo) GetAllSecrets(ctx context.Context, userID int) (entity.AllSecrets, error) {
	loginPasswords, err := r.GetLoginPasswords(ctx, userID)
	if err != nil {
		return entity.AllSecrets{}, err
	}
	textSecrets, err := r.GetTextSecrets(ctx, userID)
	if err != nil {
		return entity.AllSecrets{}, err
	}
	binarySecrets, err := r.GetBinarySecrets(ctx, userID)
	if err != nil {
		return entity.AllSecrets{}, err
	}
	cardSecrets, err := r.GetCardSecrets(ctx, userID)
	if err != nil {
		return entity.AllSecrets{}, err
	}
	return entity.AllSecrets{
		LoginPassword: loginPasswords,
		TextSecret:    textSecrets,
		BinarySecret:  binarySecrets,
		CardSecret:    cardSecrets,
	}, nil
}
