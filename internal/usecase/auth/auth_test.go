package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Eanhain/gophkeeper/domain"
	"github.com/Eanhain/gophkeeper/internal/entity"
	"github.com/Eanhain/gophkeeper/internal/usecase/auth"
	"github.com/Eanhain/gophkeeper/internal/usecase/hash"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
)

type noopLogger struct{}

func (l *noopLogger) Debug(msg interface{}, args ...interface{}) {}
func (l *noopLogger) Info(msg string, args ...interface{})       {}
func (l *noopLogger) Warn(msg string, args ...interface{})       {}
func (l *noopLogger) Error(msg interface{}, args ...interface{}) {}
func (l *noopLogger) Fatal(msg interface{}, args ...interface{}) {}

type mockAuthRepo struct {
	registerUserFn func(ctx context.Context, user entity.User) error
	checkUserFn    func(ctx context.Context, user entity.UserInput) (entity.User, error)
	getUserIDFn    func(ctx context.Context, user string) (int, error)
	deleteUserFn   func(ctx context.Context, userID int) error
}

func (m *mockAuthRepo) RegisterUser(ctx context.Context, user entity.User) error {
	return m.registerUserFn(ctx, user)
}
func (m *mockAuthRepo) CheckUser(ctx context.Context, user entity.UserInput) (entity.User, error) {
	return m.checkUserFn(ctx, user)
}
func (m *mockAuthRepo) GetUserID(ctx context.Context, user string) (int, error) {
	return m.getUserIDFn(ctx, user)
}
func (m *mockAuthRepo) DeleteUser(ctx context.Context, userID int) error {
	return m.deleteUserFn(ctx, userID)
}

var log = &noopLogger{}

// --- AuthUser ---

func TestAuthUser_Success(t *testing.T) {
	input := entity.UserInput{Login: "testuser", Password: "secret123"}
	hashedUser := hash.CreateUserHash(log, input)

	repo := &mockAuthRepo{
		checkUserFn: func(_ context.Context, _ entity.UserInput) (entity.User, error) {
			return hashedUser, nil
		},
	}
	uc := auth.New(repo, log)

	ok, cryptoKey, err := uc.AuthUser(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected auth to succeed")
	}
	if cryptoKey == "" {
		t.Fatal("expected non-empty crypto key")
	}
}

func TestAuthUser_WrongPassword(t *testing.T) {
	input := entity.UserInput{Login: "testuser", Password: "secret123"}
	hashedUser := hash.CreateUserHash(log, input)

	repo := &mockAuthRepo{
		checkUserFn: func(_ context.Context, _ entity.UserInput) (entity.User, error) {
			return hashedUser, nil
		},
	}
	uc := auth.New(repo, log)

	ok, cryptoKey, err := uc.AuthUser(context.Background(), entity.UserInput{Login: "testuser", Password: "wrong"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected auth to fail with wrong password")
	}
	if cryptoKey != "" {
		t.Fatal("expected empty crypto key on failed auth")
	}
}

func TestAuthUser_RepoError(t *testing.T) {
	repo := &mockAuthRepo{
		checkUserFn: func(_ context.Context, _ entity.UserInput) (entity.User, error) {
			return entity.User{}, errors.New("db error")
		},
	}
	uc := auth.New(repo, log)

	_, _, err := uc.AuthUser(context.Background(), entity.UserInput{Login: "u", Password: "p"})
	if err == nil {
		t.Fatal("expected error")
	}
}

// --- RegUser ---

func TestRegUser_Success(t *testing.T) {
	repo := &mockAuthRepo{
		registerUserFn: func(_ context.Context, u entity.User) error {
			if len(u.CryptoSalt) == 0 {
				t.Fatal("expected non-empty crypto salt")
			}
			return nil
		},
	}
	uc := auth.New(repo, log)

	err := uc.RegUser(context.Background(), entity.UserInput{Login: "new", Password: "pass"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRegUser_Conflict(t *testing.T) {
	repo := &mockAuthRepo{
		registerUserFn: func(_ context.Context, _ entity.User) error {
			return &pgconn.PgError{Code: pgerrcode.UniqueViolation}
		},
	}
	uc := auth.New(repo, log)

	err := uc.RegUser(context.Background(), entity.UserInput{Login: "dup", Password: "pass"})
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
}

func TestRegUser_RegisterError(t *testing.T) {
	repo := &mockAuthRepo{
		registerUserFn: func(_ context.Context, _ entity.User) error { return errors.New("db") },
	}
	uc := auth.New(repo, log)

	err := uc.RegUser(context.Background(), entity.UserInput{Login: "u", Password: "p"})
	if err == nil {
		t.Fatal("expected error")
	}
}

// --- DeleteUser ---

func TestDeleteUser_Success(t *testing.T) {
	repo := &mockAuthRepo{
		getUserIDFn:  func(_ context.Context, _ string) (int, error) { return 1, nil },
		deleteUserFn: func(_ context.Context, _ int) error { return nil },
	}
	uc := auth.New(repo, log)

	err := uc.DeleteUser(context.Background(), entity.UserInput{Login: "testuser"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteUser_GetUserIDError(t *testing.T) {
	repo := &mockAuthRepo{
		getUserIDFn: func(_ context.Context, _ string) (int, error) { return 0, errors.New("not found") },
	}
	uc := auth.New(repo, log)

	err := uc.DeleteUser(context.Background(), entity.UserInput{Login: "unknown"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDeleteUser_RepoError(t *testing.T) {
	repo := &mockAuthRepo{
		getUserIDFn:  func(_ context.Context, _ string) (int, error) { return 1, nil },
		deleteUserFn: func(_ context.Context, _ int) error { return errors.New("db error") },
	}
	uc := auth.New(repo, log)

	err := uc.DeleteUser(context.Background(), entity.UserInput{Login: "testuser"})
	if err == nil {
		t.Fatal("expected error")
	}
}
