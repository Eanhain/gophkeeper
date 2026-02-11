// Package secrets implements the repo.SecretsRepo interface backed by PostgreSQL.
//
// Sensitive fields (passwords, PAN, binary data, text bodies) are encrypted
// at the application level using AES-256-GCM with a per-user key derived
// from the user's password via Argon2id. Each user's data is encrypted with
// their own unique key, so compromising one key does not affect other users.
//
// SQL is built with squirrel; queries are executed via pgx connection pool.
package secrets

import (
	"context"
	"errors"
	"fmt"

	"github.com/Eanhain/gophkeeper/domain"
	"github.com/Eanhain/gophkeeper/internal/entity"
	"github.com/Eanhain/gophkeeper/pkg/crypto"
	"github.com/Eanhain/gophkeeper/pkg/postgres"
	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
)

// Repo is the PostgreSQL-backed secrets repository.
type Repo struct {
	*postgres.Postgres
	log domain.LoggerI
}

// New creates a Repo.
func New(pg *postgres.Postgres, log domain.LoggerI) *Repo {
	return &Repo{pg, log}
}

// wrapExecErr inspects a PostgreSQL error and maps data-exception codes
// (e.g. wrong data type) to domain.ErrInvalidInput. Other errors pass through.
func (r *Repo) wrapExecErr(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgerrcode.IsDataException(pgErr.Code) {
		return domain.ErrInvalidInput
	}
	return err
}

// --- LoginPassword ---

// CreateLoginPassword inserts a credential record. The password field
// is encrypted at the application level with AES-256-GCM using the per-user key.
func (r *Repo) CreateLoginPassword(ctx context.Context, lp entity.LoginPassword, cryptoKey string) error {
	encPassword, err := crypto.EncryptString(cryptoKey, lp.Password)
	if err != nil {
		return fmt.Errorf("encrypt password: %w", err)
	}

	sql, args, err := r.Builder.
		Insert("user_credentials").
		Columns("user_id", "login", "password_enc", "label").
		Values(lp.UserID, lp.Login, encPassword, lp.Label).
		ToSql()
	if err != nil {
		return fmt.Errorf("build sql: %w", err)
	}
	_, err = r.Pool.Exec(ctx, sql, args...)
	if err != nil {
		return r.wrapExecErr(err)
	}
	return nil
}

// GetLoginPasswords returns all credentials for the given user,
// decrypting passwords on the fly with the per-user key.
func (r *Repo) GetLoginPasswords(ctx context.Context, userID int, cryptoKey string) ([]entity.LoginPassword, error) {
	sql, args, err := r.Builder.
		Select("user_id", "login", "password_enc", "label").
		From("user_credentials").
		Where(squirrel.Eq{"user_id": userID}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("build sql: %w", err)
	}
	rows, err := r.Pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	var result []entity.LoginPassword
	for rows.Next() {
		var lp entity.LoginPassword
		var encPassword []byte
		if err := rows.Scan(&lp.UserID, &lp.Login, &encPassword, &lp.Label); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		lp.Password, err = crypto.DecryptString(cryptoKey, encPassword)
		if err != nil {
			return nil, fmt.Errorf("decrypt password: %w", err)
		}
		result = append(result, lp)
	}
	return result, nil
}

// DeleteLoginPassword removes a credential by user ID and login identifier.
// Returns domain.ErrNotFound if no rows were affected.
func (r *Repo) DeleteLoginPassword(ctx context.Context, userID int, login string) error {
	sql, args, err := r.Builder.
		Delete("user_credentials").
		Where(squirrel.Eq{"user_id": userID, "login": login}).
		ToSql()
	if err != nil {
		return fmt.Errorf("build sql: %w", err)
	}
	tag, err := r.Pool.Exec(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// --- TextSecret ---

// CreateTextSecret inserts a text note. The body is encrypted
// at the application level with AES-256-GCM using the per-user key.
func (r *Repo) CreateTextSecret(ctx context.Context, ts entity.TextSecret, cryptoKey string) error {
	encBody, err := crypto.EncryptString(cryptoKey, ts.Body)
	if err != nil {
		return fmt.Errorf("encrypt body: %w", err)
	}

	sql, args, err := r.Builder.
		Insert("user_text_items").
		Columns("user_id", "title", "body").
		Values(ts.UserID, ts.Title, encBody).
		ToSql()
	if err != nil {
		return fmt.Errorf("build sql: %w", err)
	}
	_, err = r.Pool.Exec(ctx, sql, args...)
	if err != nil {
		return r.wrapExecErr(err)
	}
	return nil
}

// GetTextSecrets returns all text notes for the given user,
// decrypting bodies on the fly with the per-user key.
func (r *Repo) GetTextSecrets(ctx context.Context, userID int, cryptoKey string) ([]entity.TextSecret, error) {
	sql, args, err := r.Builder.
		Select("user_id", "title", "body").
		From("user_text_items").
		Where(squirrel.Eq{"user_id": userID}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("build sql: %w", err)
	}
	rows, err := r.Pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	var result []entity.TextSecret
	for rows.Next() {
		var ts entity.TextSecret
		var encBody []byte
		if err := rows.Scan(&ts.UserID, &ts.Title, &encBody); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		ts.Body, err = crypto.DecryptString(cryptoKey, encBody)
		if err != nil {
			return nil, fmt.Errorf("decrypt body: %w", err)
		}
		result = append(result, ts)
	}
	return result, nil
}

// DeleteTextSecret removes a text note by user ID and title.
// Returns domain.ErrNotFound if no rows were affected.
func (r *Repo) DeleteTextSecret(ctx context.Context, userID int, title string) error {
	sql, args, err := r.Builder.
		Delete("user_text_items").
		Where(squirrel.Eq{"user_id": userID, "title": title}).
		ToSql()
	if err != nil {
		return fmt.Errorf("build sql: %w", err)
	}
	tag, err := r.Pool.Exec(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// --- BinarySecret ---

// CreateBinarySecret inserts a binary blob. The Data field (base64-encoded)
// is encrypted at the application level with AES-256-GCM using the per-user key.
func (r *Repo) CreateBinarySecret(ctx context.Context, bs entity.BinarySecret, cryptoKey string) error {
	encData, err := crypto.EncryptString(cryptoKey, bs.Data)
	if err != nil {
		return fmt.Errorf("encrypt data: %w", err)
	}

	sql, args, err := r.Builder.
		Insert("user_binary_items").
		Columns("user_id", "filename", "mime_type", "data").
		Values(bs.UserID, bs.Filename, bs.MimeType, encData).
		ToSql()
	if err != nil {
		return fmt.Errorf("build sql: %w", err)
	}
	_, err = r.Pool.Exec(ctx, sql, args...)
	if err != nil {
		return r.wrapExecErr(err)
	}
	return nil
}

// GetBinarySecrets returns all binary blobs for the given user,
// decrypting the data column on the fly with the per-user key.
func (r *Repo) GetBinarySecrets(ctx context.Context, userID int, cryptoKey string) ([]entity.BinarySecret, error) {
	sql, args, err := r.Builder.
		Select("user_id", "filename", "mime_type", "data").
		From("user_binary_items").
		Where(squirrel.Eq{"user_id": userID}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("build sql: %w", err)
	}
	rows, err := r.Pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	var result []entity.BinarySecret
	for rows.Next() {
		var bs entity.BinarySecret
		var encData []byte
		if err := rows.Scan(&bs.UserID, &bs.Filename, &bs.MimeType, &encData); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		bs.Data, err = crypto.DecryptString(cryptoKey, encData)
		if err != nil {
			return nil, fmt.Errorf("decrypt data: %w", err)
		}
		result = append(result, bs)
	}
	return result, nil
}

// DeleteBinarySecret removes a binary blob by user ID and filename.
// Returns domain.ErrNotFound if no rows were affected.
func (r *Repo) DeleteBinarySecret(ctx context.Context, userID int, filename string) error {
	sql, args, err := r.Builder.
		Delete("user_binary_items").
		Where(squirrel.Eq{"user_id": userID, "filename": filename}).
		ToSql()
	if err != nil {
		return fmt.Errorf("build sql: %w", err)
	}
	tag, err := r.Pool.Exec(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// --- CardSecret ---

// CreateCardSecret inserts a bank card. The PAN field is encrypted
// at the application level with AES-256-GCM using the per-user key.
func (r *Repo) CreateCardSecret(ctx context.Context, cs entity.CardSecret, cryptoKey string) error {
	encPan, err := crypto.EncryptString(cryptoKey, cs.Pan)
	if err != nil {
		return fmt.Errorf("encrypt pan: %w", err)
	}

	sql, args, err := r.Builder.
		Insert("user_cards").
		Columns("user_id", "cardholder", "pan_enc", "exp_month", "exp_year", "brand", "last4").
		Values(cs.UserID, cs.Cardholder, encPan, cs.ExpMonth, cs.ExpYear, cs.Brand, cs.Last4).
		ToSql()
	if err != nil {
		return fmt.Errorf("build sql: %w", err)
	}
	_, err = r.Pool.Exec(ctx, sql, args...)
	if err != nil {
		return r.wrapExecErr(err)
	}
	return nil
}

// GetCardSecrets returns all cards for the given user,
// decrypting the PAN column on the fly with the per-user key.
func (r *Repo) GetCardSecrets(ctx context.Context, userID int, cryptoKey string) ([]entity.CardSecret, error) {
	sql, args, err := r.Builder.
		Select("user_id", "cardholder", "pan_enc", "exp_month", "exp_year", "brand", "last4").
		From("user_cards").
		Where(squirrel.Eq{"user_id": userID}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("build sql: %w", err)
	}
	rows, err := r.Pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	var result []entity.CardSecret
	for rows.Next() {
		var cs entity.CardSecret
		var encPan []byte
		if err := rows.Scan(&cs.UserID, &cs.Cardholder, &encPan, &cs.ExpMonth, &cs.ExpYear, &cs.Brand, &cs.Last4); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		cs.Pan, err = crypto.DecryptString(cryptoKey, encPan)
		if err != nil {
			return nil, fmt.Errorf("decrypt pan: %w", err)
		}
		result = append(result, cs)
	}
	return result, nil
}

// DeleteCardSecret removes a card by user ID and cardholder name.
// Returns domain.ErrNotFound if no rows were affected.
func (r *Repo) DeleteCardSecret(ctx context.Context, userID int, cardholder string) error {
	sql, args, err := r.Builder.
		Delete("user_cards").
		Where(squirrel.Eq{"user_id": userID, "cardholder": cardholder}).
		ToSql()
	if err != nil {
		return fmt.Errorf("build sql: %w", err)
	}
	tag, err := r.Pool.Exec(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// --- Shared ---

// GetUserID resolves a username to the numeric "id" primary key.
func (r *Repo) GetUserID(ctx context.Context, username string) (int, error) {
	sql, args, err := r.Builder.
		Select("id").
		From("users").
		Where(squirrel.Eq{"username": username}).
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("build sql: %w", err)
	}
	var userID int
	err = r.Pool.QueryRow(ctx, sql, args...).Scan(&userID)
	if err != nil {
		return 0, fmt.Errorf("get user id: %w", err)
	}
	return userID, nil
}

// GetAllSecrets fetches all four secret types for a user in separate queries
// and returns them combined in a single entity.AllSecrets struct.
func (r *Repo) GetAllSecrets(ctx context.Context, userID int, cryptoKey string) (entity.AllSecrets, error) {
	lp, err := r.GetLoginPasswords(ctx, userID, cryptoKey)
	if err != nil {
		return entity.AllSecrets{}, err
	}
	ts, err := r.GetTextSecrets(ctx, userID, cryptoKey)
	if err != nil {
		return entity.AllSecrets{}, err
	}
	bs, err := r.GetBinarySecrets(ctx, userID, cryptoKey)
	if err != nil {
		return entity.AllSecrets{}, err
	}
	cs, err := r.GetCardSecrets(ctx, userID, cryptoKey)
	if err != nil {
		return entity.AllSecrets{}, err
	}
	return entity.AllSecrets{
		LoginPassword: lp,
		TextSecret:    ts,
		BinarySecret:  bs,
		CardSecret:    cs,
	}, nil
}
