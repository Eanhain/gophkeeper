package secrets

import (
	"context"
	"errors"
	"fmt"

	"github.com/Eanhain/gophkeeper/domain"
	"github.com/Eanhain/gophkeeper/internal/entity"
	"github.com/Eanhain/gophkeeper/pkg/postgres"
	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
)

type Repo struct {
	*postgres.Postgres
	log       domain.LoggerI
	cryptoKey string
}

func New(pg *postgres.Postgres, log domain.LoggerI, cryptoKey string) *Repo {
	if cryptoKey == "" {
		log.Fatal("secrets repo: CRYPTO_KEY is empty")
	}
	return &Repo{pg, log, cryptoKey}
}

func (r *Repo) wrapExecErr(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgerrcode.IsDataException(pgErr.Code) {
		return domain.ErrInvalidInput
	}
	return err
}

// --- LoginPassword ---

func (r *Repo) CreateLoginPassword(ctx context.Context, lp entity.LoginPassword) error {
	sql, args, err := r.Builder.
		Insert("user_credentials").
		Columns("user_id", "login", "password_enc", "label").
		Values(lp.UserID, lp.Login, squirrel.Expr("pgp_sym_encrypt(?, ?)", lp.Password, r.cryptoKey), lp.Label).
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

func (r *Repo) GetLoginPasswords(ctx context.Context, userID int) ([]entity.LoginPassword, error) {
	sql, args, err := r.Builder.
		Select("user_id", "login").
		Column("pgp_sym_decrypt(password_enc, ?) AS password_enc", r.cryptoKey).
		Column("label").
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
		if err := rows.Scan(&lp.UserID, &lp.Login, &lp.Password, &lp.Label); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
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

func (r *Repo) CreateTextSecret(ctx context.Context, ts entity.TextSecret) error {
	sql, args, err := r.Builder.
		Insert("user_text_items").
		Columns("user_id", "title", "body").
		Values(ts.UserID, ts.Title, squirrel.Expr("pgp_sym_encrypt(?, ?)", ts.Body, r.cryptoKey)).
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

func (r *Repo) GetTextSecrets(ctx context.Context, userID int) ([]entity.TextSecret, error) {
	sql, args, err := r.Builder.
		Select("user_id", "title").
		Column("pgp_sym_decrypt(body, ?) AS body", r.cryptoKey).
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
		if err := rows.Scan(&ts.UserID, &ts.Title, &ts.Body); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
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

func (r *Repo) CreateBinarySecret(ctx context.Context, bs entity.BinarySecret) error {
	sql, args, err := r.Builder.
		Insert("user_binary_items").
		Columns("user_id", "filename", "mime_type", "data").
		Values(bs.UserID, bs.Filename, bs.MimeType, squirrel.Expr("pgp_sym_encrypt(?, ?)", bs.Data, r.cryptoKey)).
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

func (r *Repo) GetBinarySecrets(ctx context.Context, userID int) ([]entity.BinarySecret, error) {
	sql, args, err := r.Builder.
		Select("user_id", "filename", "mime_type").
		Column("pgp_sym_decrypt(data, ?) AS data", r.cryptoKey).
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
		if err := rows.Scan(&bs.UserID, &bs.Filename, &bs.MimeType, &bs.Data); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
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

func (r *Repo) CreateCardSecret(ctx context.Context, cs entity.CardSecret) error {
	sql, args, err := r.Builder.
		Insert("user_cards").
		Columns("user_id", "cardholder", "pan_enc", "exp_month", "exp_year", "brand", "last4").
		Values(cs.UserID, cs.Cardholder, squirrel.Expr("pgp_sym_encrypt(?, ?)", cs.Pan, r.cryptoKey), cs.ExpMonth, cs.ExpYear, cs.Brand, cs.Last4).
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

func (r *Repo) GetCardSecrets(ctx context.Context, userID int) ([]entity.CardSecret, error) {
	sql, args, err := r.Builder.
		Select("user_id", "cardholder").
		Column("pgp_sym_decrypt(pan_enc, ?) AS pan_enc", r.cryptoKey).
		Column("exp_month").
		Column("exp_year").
		Column("brand").
		Column("last4").
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
		if err := rows.Scan(&cs.UserID, &cs.Cardholder, &cs.Pan, &cs.ExpMonth, &cs.ExpYear, &cs.Brand, &cs.Last4); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
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

func (r *Repo) GetAllSecrets(ctx context.Context, userID int) (entity.AllSecrets, error) {
	lp, err := r.GetLoginPasswords(ctx, userID)
	if err != nil {
		return entity.AllSecrets{}, err
	}
	ts, err := r.GetTextSecrets(ctx, userID)
	if err != nil {
		return entity.AllSecrets{}, err
	}
	bs, err := r.GetBinarySecrets(ctx, userID)
	if err != nil {
		return entity.AllSecrets{}, err
	}
	cs, err := r.GetCardSecrets(ctx, userID)
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
