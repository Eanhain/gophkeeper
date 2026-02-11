package secrets_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Eanhain/gophkeeper/domain"
	"github.com/Eanhain/gophkeeper/internal/controller/restapi/v1/request"
	"github.com/Eanhain/gophkeeper/internal/entity"
	"github.com/Eanhain/gophkeeper/internal/usecase/secrets"
)

// --- noop logger ---

type noopLogger struct{}

func (l *noopLogger) Debug(msg interface{}, args ...interface{}) {}
func (l *noopLogger) Info(msg string, args ...interface{})       {}
func (l *noopLogger) Warn(msg string, args ...interface{})       {}
func (l *noopLogger) Error(msg interface{}, args ...interface{}) {}
func (l *noopLogger) Fatal(msg interface{}, args ...interface{}) {}

const testCryptoKey = "deadbeef" // dummy key for tests

// --- mock repo ---

type mockRepo struct {
	getUserIDFn           func(ctx context.Context, user string) (int, error)
	createLoginPasswordFn func(ctx context.Context, lp entity.LoginPassword, cryptoKey string) error
	getLoginPasswordsFn   func(ctx context.Context, userID int, cryptoKey string) ([]entity.LoginPassword, error)
	deleteLoginPasswordFn func(ctx context.Context, userID int, login string) error
	createTextSecretFn    func(ctx context.Context, ts entity.TextSecret, cryptoKey string) error
	getTextSecretsFn      func(ctx context.Context, userID int, cryptoKey string) ([]entity.TextSecret, error)
	deleteTextSecretFn    func(ctx context.Context, userID int, title string) error
	createBinarySecretFn  func(ctx context.Context, bs entity.BinarySecret, cryptoKey string) error
	getBinarySecretsFn    func(ctx context.Context, userID int, cryptoKey string) ([]entity.BinarySecret, error)
	deleteBinarySecretFn  func(ctx context.Context, userID int, filename string) error
	createCardSecretFn    func(ctx context.Context, cs entity.CardSecret, cryptoKey string) error
	getCardSecretsFn      func(ctx context.Context, userID int, cryptoKey string) ([]entity.CardSecret, error)
	deleteCardSecretFn    func(ctx context.Context, userID int, cardholder string) error
	getAllSecretsFn       func(ctx context.Context, userID int, cryptoKey string) (entity.AllSecrets, error)
}

func (m *mockRepo) GetUserID(ctx context.Context, user string) (int, error) {
	return m.getUserIDFn(ctx, user)
}
func (m *mockRepo) CreateLoginPassword(ctx context.Context, lp entity.LoginPassword, cryptoKey string) error {
	return m.createLoginPasswordFn(ctx, lp, cryptoKey)
}
func (m *mockRepo) GetLoginPasswords(ctx context.Context, userID int, cryptoKey string) ([]entity.LoginPassword, error) {
	return m.getLoginPasswordsFn(ctx, userID, cryptoKey)
}
func (m *mockRepo) DeleteLoginPassword(ctx context.Context, userID int, login string) error {
	return m.deleteLoginPasswordFn(ctx, userID, login)
}
func (m *mockRepo) CreateTextSecret(ctx context.Context, ts entity.TextSecret, cryptoKey string) error {
	return m.createTextSecretFn(ctx, ts, cryptoKey)
}
func (m *mockRepo) GetTextSecrets(ctx context.Context, userID int, cryptoKey string) ([]entity.TextSecret, error) {
	return m.getTextSecretsFn(ctx, userID, cryptoKey)
}
func (m *mockRepo) DeleteTextSecret(ctx context.Context, userID int, title string) error {
	return m.deleteTextSecretFn(ctx, userID, title)
}
func (m *mockRepo) CreateBinarySecret(ctx context.Context, bs entity.BinarySecret, cryptoKey string) error {
	return m.createBinarySecretFn(ctx, bs, cryptoKey)
}
func (m *mockRepo) GetBinarySecrets(ctx context.Context, userID int, cryptoKey string) ([]entity.BinarySecret, error) {
	return m.getBinarySecretsFn(ctx, userID, cryptoKey)
}
func (m *mockRepo) DeleteBinarySecret(ctx context.Context, userID int, filename string) error {
	return m.deleteBinarySecretFn(ctx, userID, filename)
}
func (m *mockRepo) CreateCardSecret(ctx context.Context, cs entity.CardSecret, cryptoKey string) error {
	return m.createCardSecretFn(ctx, cs, cryptoKey)
}
func (m *mockRepo) GetCardSecrets(ctx context.Context, userID int, cryptoKey string) ([]entity.CardSecret, error) {
	return m.getCardSecretsFn(ctx, userID, cryptoKey)
}
func (m *mockRepo) DeleteCardSecret(ctx context.Context, userID int, cardholder string) error {
	return m.deleteCardSecretFn(ctx, userID, cardholder)
}
func (m *mockRepo) GetAllSecrets(ctx context.Context, userID int, cryptoKey string) (entity.AllSecrets, error) {
	return m.getAllSecretsFn(ctx, userID, cryptoKey)
}

func okGetUserID() func(context.Context, string) (int, error) {
	return func(_ context.Context, _ string) (int, error) { return 1, nil }
}

func failGetUserID() func(context.Context, string) (int, error) {
	return func(_ context.Context, _ string) (int, error) { return 0, errors.New("user not found") }
}

// --- CreateLoginPassword ---

func TestCreateLoginPassword_Success(t *testing.T) {
	repo := &mockRepo{
		getUserIDFn: okGetUserID(),
		createLoginPasswordFn: func(_ context.Context, _ entity.LoginPassword, _ string) error { return nil },
	}
	uc := secrets.New(repo, &noopLogger{})

	err := uc.CreateLoginPassword(context.Background(), "user", testCryptoKey, request.LoginPassword{Login: "admin", Password: "p"})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestCreateLoginPassword_EmptyLogin(t *testing.T) {
	uc := secrets.New(&mockRepo{}, &noopLogger{})
	err := uc.CreateLoginPassword(context.Background(), "user", testCryptoKey, request.LoginPassword{})
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestCreateLoginPassword_GetUserIDErr(t *testing.T) {
	repo := &mockRepo{getUserIDFn: failGetUserID()}
	uc := secrets.New(repo, &noopLogger{})

	err := uc.CreateLoginPassword(context.Background(), "user", testCryptoKey, request.LoginPassword{Login: "a"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCreateLoginPassword_RepoErr(t *testing.T) {
	repo := &mockRepo{
		getUserIDFn: okGetUserID(),
		createLoginPasswordFn: func(_ context.Context, _ entity.LoginPassword, _ string) error { return errors.New("db") },
	}
	uc := secrets.New(repo, &noopLogger{})

	err := uc.CreateLoginPassword(context.Background(), "user", testCryptoKey, request.LoginPassword{Login: "a"})
	if err == nil {
		t.Fatal("expected error")
	}
}

// --- CreateTextSecret ---

func TestCreateTextSecret_Success(t *testing.T) {
	repo := &mockRepo{
		getUserIDFn:        okGetUserID(),
		createTextSecretFn: func(_ context.Context, _ entity.TextSecret, _ string) error { return nil },
	}
	uc := secrets.New(repo, &noopLogger{})

	err := uc.CreateTextSecret(context.Background(), "user", testCryptoKey, request.TextSecret{Title: "note", Body: "hi"})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestCreateTextSecret_EmptyTitle(t *testing.T) {
	uc := secrets.New(&mockRepo{}, &noopLogger{})
	err := uc.CreateTextSecret(context.Background(), "user", testCryptoKey, request.TextSecret{})
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestCreateTextSecret_GetUserIDErr(t *testing.T) {
	repo := &mockRepo{getUserIDFn: failGetUserID()}
	uc := secrets.New(repo, &noopLogger{})

	err := uc.CreateTextSecret(context.Background(), "user", testCryptoKey, request.TextSecret{Title: "t"})
	if err == nil {
		t.Fatal("expected error")
	}
}

// --- CreateBinarySecret ---

func TestCreateBinarySecret_Success(t *testing.T) {
	repo := &mockRepo{
		getUserIDFn:          okGetUserID(),
		createBinarySecretFn: func(_ context.Context, _ entity.BinarySecret, _ string) error { return nil },
	}
	uc := secrets.New(repo, &noopLogger{})

	err := uc.CreateBinarySecret(context.Background(), "user", testCryptoKey, request.BinarySecret{Filename: "f.bin"})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestCreateBinarySecret_EmptyFilename(t *testing.T) {
	uc := secrets.New(&mockRepo{}, &noopLogger{})
	err := uc.CreateBinarySecret(context.Background(), "user", testCryptoKey, request.BinarySecret{})
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

// --- CreateCardSecret ---

func TestCreateCardSecret_Success(t *testing.T) {
	repo := &mockRepo{
		getUserIDFn:        okGetUserID(),
		createCardSecretFn: func(_ context.Context, _ entity.CardSecret, _ string) error { return nil },
	}
	uc := secrets.New(repo, &noopLogger{})

	err := uc.CreateCardSecret(context.Background(), "user", testCryptoKey, request.CardSecret{Cardholder: "John"})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestCreateCardSecret_EmptyCardholder(t *testing.T) {
	uc := secrets.New(&mockRepo{}, &noopLogger{})
	err := uc.CreateCardSecret(context.Background(), "user", testCryptoKey, request.CardSecret{})
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

// --- Get methods ---

func TestGetLoginPasswords_Success(t *testing.T) {
	expected := []entity.LoginPassword{{Login: "a", Password: "b"}}
	repo := &mockRepo{
		getUserIDFn:         okGetUserID(),
		getLoginPasswordsFn: func(_ context.Context, _ int, _ string) ([]entity.LoginPassword, error) { return expected, nil },
	}
	uc := secrets.New(repo, &noopLogger{})

	result, err := uc.GetLoginPasswords(context.Background(), "user", testCryptoKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || result[0].Login != "a" {
		t.Fatal("data mismatch")
	}
}

func TestGetLoginPasswords_UserIDErr(t *testing.T) {
	repo := &mockRepo{getUserIDFn: failGetUserID()}
	uc := secrets.New(repo, &noopLogger{})

	_, err := uc.GetLoginPasswords(context.Background(), "user", testCryptoKey)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGetTextSecrets_Success(t *testing.T) {
	expected := []entity.TextSecret{{Title: "note", Body: "hi"}}
	repo := &mockRepo{
		getUserIDFn:      okGetUserID(),
		getTextSecretsFn: func(_ context.Context, _ int, _ string) ([]entity.TextSecret, error) { return expected, nil },
	}
	uc := secrets.New(repo, &noopLogger{})

	result, err := uc.GetTextSecrets(context.Background(), "user", testCryptoKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || result[0].Title != "note" {
		t.Fatal("data mismatch")
	}
}

func TestGetTextSecrets_UserIDErr(t *testing.T) {
	repo := &mockRepo{getUserIDFn: failGetUserID()}
	uc := secrets.New(repo, &noopLogger{})

	_, err := uc.GetTextSecrets(context.Background(), "user", testCryptoKey)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGetBinarySecrets_Success(t *testing.T) {
	expected := []entity.BinarySecret{{Filename: "file.bin"}}
	repo := &mockRepo{
		getUserIDFn:        okGetUserID(),
		getBinarySecretsFn: func(_ context.Context, _ int, _ string) ([]entity.BinarySecret, error) { return expected, nil },
	}
	uc := secrets.New(repo, &noopLogger{})

	result, err := uc.GetBinarySecrets(context.Background(), "user", testCryptoKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || result[0].Filename != "file.bin" {
		t.Fatal("data mismatch")
	}
}

func TestGetBinarySecrets_UserIDErr(t *testing.T) {
	repo := &mockRepo{getUserIDFn: failGetUserID()}
	uc := secrets.New(repo, &noopLogger{})

	_, err := uc.GetBinarySecrets(context.Background(), "user", testCryptoKey)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGetCardSecrets_Success(t *testing.T) {
	expected := []entity.CardSecret{{Cardholder: "John"}}
	repo := &mockRepo{
		getUserIDFn:      okGetUserID(),
		getCardSecretsFn: func(_ context.Context, _ int, _ string) ([]entity.CardSecret, error) { return expected, nil },
	}
	uc := secrets.New(repo, &noopLogger{})

	result, err := uc.GetCardSecrets(context.Background(), "user", testCryptoKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || result[0].Cardholder != "John" {
		t.Fatal("data mismatch")
	}
}

func TestGetCardSecrets_UserIDErr(t *testing.T) {
	repo := &mockRepo{getUserIDFn: failGetUserID()}
	uc := secrets.New(repo, &noopLogger{})

	_, err := uc.GetCardSecrets(context.Background(), "user", testCryptoKey)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGetAllSecrets_Success(t *testing.T) {
	expected := entity.AllSecrets{
		LoginPassword: []entity.LoginPassword{{Login: "a"}},
		TextSecret:    []entity.TextSecret{{Title: "t"}},
	}
	repo := &mockRepo{
		getUserIDFn:    okGetUserID(),
		getAllSecretsFn: func(_ context.Context, _ int, _ string) (entity.AllSecrets, error) { return expected, nil },
	}
	uc := secrets.New(repo, &noopLogger{})

	result, err := uc.GetAllSecrets(context.Background(), "user", testCryptoKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.LoginPassword) != 1 || len(result.TextSecret) != 1 {
		t.Fatal("data mismatch")
	}
}

func TestGetAllSecrets_UserIDErr(t *testing.T) {
	repo := &mockRepo{getUserIDFn: failGetUserID()}
	uc := secrets.New(repo, &noopLogger{})

	_, err := uc.GetAllSecrets(context.Background(), "user", testCryptoKey)
	if err == nil {
		t.Fatal("expected error")
	}
}

// --- Delete methods ---

func TestDeleteLoginPassword_Success(t *testing.T) {
	repo := &mockRepo{
		getUserIDFn:           okGetUserID(),
		deleteLoginPasswordFn: func(_ context.Context, _ int, _ string) error { return nil },
	}
	uc := secrets.New(repo, &noopLogger{})

	err := uc.DeleteLoginPassword(context.Background(), "user", testCryptoKey, "admin")
	if err != nil {
		t.Fatal(err)
	}
}

func TestDeleteLoginPassword_EmptyLogin(t *testing.T) {
	uc := secrets.New(&mockRepo{}, &noopLogger{})
	err := uc.DeleteLoginPassword(context.Background(), "user", testCryptoKey, "")
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestDeleteLoginPassword_GetUserIDErr(t *testing.T) {
	repo := &mockRepo{getUserIDFn: failGetUserID()}
	uc := secrets.New(repo, &noopLogger{})

	err := uc.DeleteLoginPassword(context.Background(), "user", testCryptoKey, "a")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDeleteLoginPassword_RepoErr(t *testing.T) {
	repo := &mockRepo{
		getUserIDFn:           okGetUserID(),
		deleteLoginPasswordFn: func(_ context.Context, _ int, _ string) error { return domain.ErrNotFound },
	}
	uc := secrets.New(repo, &noopLogger{})

	err := uc.DeleteLoginPassword(context.Background(), "user", testCryptoKey, "a")
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestDeleteTextSecret_Success(t *testing.T) {
	repo := &mockRepo{
		getUserIDFn:        okGetUserID(),
		deleteTextSecretFn: func(_ context.Context, _ int, _ string) error { return nil },
	}
	uc := secrets.New(repo, &noopLogger{})

	err := uc.DeleteTextSecret(context.Background(), "user", testCryptoKey, "note")
	if err != nil {
		t.Fatal(err)
	}
}

func TestDeleteTextSecret_EmptyTitle(t *testing.T) {
	uc := secrets.New(&mockRepo{}, &noopLogger{})
	err := uc.DeleteTextSecret(context.Background(), "user", testCryptoKey, "")
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestDeleteBinarySecret_Success(t *testing.T) {
	repo := &mockRepo{
		getUserIDFn:          okGetUserID(),
		deleteBinarySecretFn: func(_ context.Context, _ int, _ string) error { return nil },
	}
	uc := secrets.New(repo, &noopLogger{})

	err := uc.DeleteBinarySecret(context.Background(), "user", testCryptoKey, "f.bin")
	if err != nil {
		t.Fatal(err)
	}
}

func TestDeleteBinarySecret_EmptyFilename(t *testing.T) {
	uc := secrets.New(&mockRepo{}, &noopLogger{})
	err := uc.DeleteBinarySecret(context.Background(), "user", testCryptoKey, "")
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

func TestDeleteCardSecret_Success(t *testing.T) {
	repo := &mockRepo{
		getUserIDFn:        okGetUserID(),
		deleteCardSecretFn: func(_ context.Context, _ int, _ string) error { return nil },
	}
	uc := secrets.New(repo, &noopLogger{})

	err := uc.DeleteCardSecret(context.Background(), "user", testCryptoKey, "John")
	if err != nil {
		t.Fatal(err)
	}
}

func TestDeleteCardSecret_EmptyCardholder(t *testing.T) {
	uc := secrets.New(&mockRepo{}, &noopLogger{})
	err := uc.DeleteCardSecret(context.Background(), "user", testCryptoKey, "")
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}
