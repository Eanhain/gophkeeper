package v1_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Eanhain/gophkeeper/domain"
	"github.com/Eanhain/gophkeeper/internal/controller/restapi/v1/request"
	"github.com/Eanhain/gophkeeper/internal/entity"

	v1 "github.com/Eanhain/gophkeeper/internal/controller/restapi/v1"
	jwtware "github.com/gofiber/contrib/jwt"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

const testSecret = "test-jwt-secret"

type noopLogger struct{}

func (l *noopLogger) Debug(msg interface{}, args ...interface{}) {}
func (l *noopLogger) Info(msg string, args ...interface{})       {}
func (l *noopLogger) Warn(msg string, args ...interface{})       {}
func (l *noopLogger) Error(msg interface{}, args ...interface{}) {}
func (l *noopLogger) Fatal(msg interface{}, args ...interface{}) {}

func createToken(username string) string {
	claims := jwt.MapClaims{
		"login": username,
		"exp":   time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, _ := token.SignedString([]byte(testSecret))
	return s
}

func jwtConf() jwtware.Config {
	return jwtware.Config{
		SigningKey: jwtware.SigningKey{Key: []byte(testSecret)},
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			return c.Status(fiber.StatusUnauthorized).
				JSON(fiber.Map{"status": "error", "message": err.Error()})
		},
	}
}

// --- mock AuthUseCase ---

type mockAuthUC struct {
	authUserFn   func(ctx context.Context, user entity.UserInput) (bool, error)
	regUserFn    func(ctx context.Context, user entity.UserInput) error
	deleteUserFn func(ctx context.Context, user entity.UserInput) error
}

func (m *mockAuthUC) AuthUser(ctx context.Context, user entity.UserInput) (bool, error) {
	if m.authUserFn != nil {
		return m.authUserFn(ctx, user)
	}
	return true, nil
}
func (m *mockAuthUC) RegUser(ctx context.Context, user entity.UserInput) error {
	if m.regUserFn != nil {
		return m.regUserFn(ctx, user)
	}
	return nil
}
func (m *mockAuthUC) DeleteUser(ctx context.Context, user entity.UserInput) error {
	if m.deleteUserFn != nil {
		return m.deleteUserFn(ctx, user)
	}
	return nil
}

// --- mock SecretsUseCase ---

type mockSecretsUC struct {
	createLoginPasswordFn func(ctx context.Context, username string, lp request.LoginPassword) error
	getLoginPasswordsFn   func(ctx context.Context, username string) ([]entity.LoginPassword, error)
	deleteLoginPasswordFn func(ctx context.Context, username string, login string) error
	createTextSecretFn    func(ctx context.Context, username string, ts request.TextSecret) error
	getTextSecretsFn      func(ctx context.Context, username string) ([]entity.TextSecret, error)
	deleteTextSecretFn    func(ctx context.Context, username string, title string) error
	createBinarySecretFn  func(ctx context.Context, username string, bs request.BinarySecret) error
	getBinarySecretsFn    func(ctx context.Context, username string) ([]entity.BinarySecret, error)
	deleteBinarySecretFn  func(ctx context.Context, username string, filename string) error
	createCardSecretFn    func(ctx context.Context, username string, cs request.CardSecret) error
	getCardSecretsFn      func(ctx context.Context, username string) ([]entity.CardSecret, error)
	deleteCardSecretFn    func(ctx context.Context, username string, cardholder string) error
	getAllSecretsFn       func(ctx context.Context, username string) (entity.AllSecrets, error)
}

func (m *mockSecretsUC) CreateLoginPassword(ctx context.Context, u string, lp request.LoginPassword) error {
	if m.createLoginPasswordFn != nil {
		return m.createLoginPasswordFn(ctx, u, lp)
	}
	return nil
}
func (m *mockSecretsUC) GetLoginPasswords(ctx context.Context, u string) ([]entity.LoginPassword, error) {
	if m.getLoginPasswordsFn != nil {
		return m.getLoginPasswordsFn(ctx, u)
	}
	return nil, nil
}
func (m *mockSecretsUC) DeleteLoginPassword(ctx context.Context, u string, login string) error {
	if m.deleteLoginPasswordFn != nil {
		return m.deleteLoginPasswordFn(ctx, u, login)
	}
	return nil
}
func (m *mockSecretsUC) CreateTextSecret(ctx context.Context, u string, ts request.TextSecret) error {
	if m.createTextSecretFn != nil {
		return m.createTextSecretFn(ctx, u, ts)
	}
	return nil
}
func (m *mockSecretsUC) GetTextSecrets(ctx context.Context, u string) ([]entity.TextSecret, error) {
	if m.getTextSecretsFn != nil {
		return m.getTextSecretsFn(ctx, u)
	}
	return nil, nil
}
func (m *mockSecretsUC) DeleteTextSecret(ctx context.Context, u string, title string) error {
	if m.deleteTextSecretFn != nil {
		return m.deleteTextSecretFn(ctx, u, title)
	}
	return nil
}
func (m *mockSecretsUC) CreateBinarySecret(ctx context.Context, u string, bs request.BinarySecret) error {
	if m.createBinarySecretFn != nil {
		return m.createBinarySecretFn(ctx, u, bs)
	}
	return nil
}
func (m *mockSecretsUC) GetBinarySecrets(ctx context.Context, u string) ([]entity.BinarySecret, error) {
	if m.getBinarySecretsFn != nil {
		return m.getBinarySecretsFn(ctx, u)
	}
	return nil, nil
}
func (m *mockSecretsUC) DeleteBinarySecret(ctx context.Context, u string, filename string) error {
	if m.deleteBinarySecretFn != nil {
		return m.deleteBinarySecretFn(ctx, u, filename)
	}
	return nil
}
func (m *mockSecretsUC) CreateCardSecret(ctx context.Context, u string, cs request.CardSecret) error {
	if m.createCardSecretFn != nil {
		return m.createCardSecretFn(ctx, u, cs)
	}
	return nil
}
func (m *mockSecretsUC) GetCardSecrets(ctx context.Context, u string) ([]entity.CardSecret, error) {
	if m.getCardSecretsFn != nil {
		return m.getCardSecretsFn(ctx, u)
	}
	return nil, nil
}
func (m *mockSecretsUC) DeleteCardSecret(ctx context.Context, u string, cardholder string) error {
	if m.deleteCardSecretFn != nil {
		return m.deleteCardSecretFn(ctx, u, cardholder)
	}
	return nil
}
func (m *mockSecretsUC) GetAllSecrets(ctx context.Context, u string) (entity.AllSecrets, error) {
	if m.getAllSecretsFn != nil {
		return m.getAllSecretsFn(ctx, u)
	}
	return entity.AllSecrets{}, nil
}

// --- helpers ---

func parseJSON(t *testing.T, r io.Reader) map[string]interface{} {
	t.Helper()
	var result map[string]interface{}
	if err := json.NewDecoder(r).Decode(&result); err != nil {
		t.Fatalf("parse json: %v", err)
	}
	return result
}

// --- Auth handler tests ---

func TestLoginJWT_Success(t *testing.T) {
	app := fiber.New()
	uc := &mockAuthUC{
		authUserFn: func(_ context.Context, _ entity.UserInput) (bool, error) { return true, nil },
	}
	v1.NewAuthRoutes(app, uc, jwtConf(), &noopLogger{})

	body := `{"login":"user","password":"pass"}`
	req := httptest.NewRequest("POST", "/api/user/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	result := parseJSON(t, resp.Body)
	if result["token"] == nil || result["token"] == "" {
		t.Fatal("expected token in response")
	}
}

func TestLoginJWT_AuthFail(t *testing.T) {
	app := fiber.New()
	uc := &mockAuthUC{
		authUserFn: func(_ context.Context, _ entity.UserInput) (bool, error) { return false, nil },
	}
	v1.NewAuthRoutes(app, uc, jwtConf(), &noopLogger{})

	body := `{"login":"user","password":"wrong"}`
	req := httptest.NewRequest("POST", "/api/user/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestHandlerRegUser_Success(t *testing.T) {
	app := fiber.New()
	uc := &mockAuthUC{
		regUserFn:  func(_ context.Context, _ entity.UserInput) error { return nil },
		authUserFn: func(_ context.Context, _ entity.UserInput) (bool, error) { return true, nil },
	}
	v1.NewAuthRoutes(app, uc, jwtConf(), &noopLogger{})

	body := `{"login":"newuser","password":"pass"}`
	req := httptest.NewRequest("POST", "/api/user/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(b))
	}
}

func TestHandlerRegUser_Conflict(t *testing.T) {
	app := fiber.New()
	uc := &mockAuthUC{
		regUserFn: func(_ context.Context, _ entity.UserInput) error { return domain.ErrConflict },
	}
	v1.NewAuthRoutes(app, uc, jwtConf(), &noopLogger{})

	body := `{"login":"dup","password":"pass"}`
	req := httptest.NewRequest("POST", "/api/user/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	if resp.StatusCode != 409 {
		t.Fatalf("expected 409, got %d", resp.StatusCode)
	}
}

func TestDeleteUser_Success(t *testing.T) {
	app := fiber.New()
	uc := &mockAuthUC{}
	v1.NewAuthRoutes(app, uc, jwtConf(), &noopLogger{})

	tok := createToken("testuser")
	req := httptest.NewRequest("DELETE", "/api/user/delete-user", nil)
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, _ := app.Test(req)
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(b))
	}
}

func TestDeleteUser_NoToken(t *testing.T) {
	app := fiber.New()
	uc := &mockAuthUC{}
	v1.NewAuthRoutes(app, uc, jwtConf(), &noopLogger{})

	req := httptest.NewRequest("DELETE", "/api/user/delete-user", nil)
	resp, _ := app.Test(req)
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

// --- Secret handler tests ---

func setupSecretApp(uc *mockSecretsUC) *fiber.App {
	app := fiber.New()
	v1.NewSecretRoutes(app, uc, jwtConf(), &noopLogger{})
	return app
}

func TestPostLoginPassword_Success(t *testing.T) {
	app := setupSecretApp(&mockSecretsUC{})

	body := `{"login":"admin","password":"pass","label":"work"}`
	req := httptest.NewRequest("POST", "/api/user/secret/post-login-password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(b))
	}
}

func TestPostLoginPassword_ValidationError(t *testing.T) {
	uc := &mockSecretsUC{
		createLoginPasswordFn: func(_ context.Context, _ string, _ request.LoginPassword) error {
			return domain.ErrInvalidInput
		},
	}
	app := setupSecretApp(uc)

	body := `{"login":"","password":"pass"}`
	req := httptest.NewRequest("POST", "/api/user/secret/post-login-password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestGetLoginPassword_Success(t *testing.T) {
	uc := &mockSecretsUC{
		getLoginPasswordsFn: func(_ context.Context, _ string) ([]entity.LoginPassword, error) {
			return []entity.LoginPassword{{Login: "a", Password: "b", Label: "c"}}, nil
		},
	}
	app := setupSecretApp(uc)

	req := httptest.NewRequest("GET", "/api/user/secret/get-login-password", nil)
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestGetLoginPassword_Error(t *testing.T) {
	uc := &mockSecretsUC{
		getLoginPasswordsFn: func(_ context.Context, _ string) ([]entity.LoginPassword, error) {
			return nil, domain.ErrNotFound
		},
	}
	app := setupSecretApp(uc)

	req := httptest.NewRequest("GET", "/api/user/secret/get-login-password", nil)
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestDeleteLoginPassword_Success(t *testing.T) {
	app := setupSecretApp(&mockSecretsUC{})

	body := `{"login":"admin"}`
	req := httptest.NewRequest("DELETE", "/api/user/secret/delete-login-password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(b))
	}
}

func TestPostTextSecret_Success(t *testing.T) {
	app := setupSecretApp(&mockSecretsUC{})

	body := `{"title":"note","body":"hello"}`
	req := httptest.NewRequest("POST", "/api/user/secret/post-text-secret", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(b))
	}
}

func TestGetTextSecret_Success(t *testing.T) {
	uc := &mockSecretsUC{
		getTextSecretsFn: func(_ context.Context, _ string) ([]entity.TextSecret, error) {
			return []entity.TextSecret{{Title: "note", Body: "hi"}}, nil
		},
	}
	app := setupSecretApp(uc)

	req := httptest.NewRequest("GET", "/api/user/secret/get-text-secret", nil)
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestPostBinarySecret_Success(t *testing.T) {
	app := setupSecretApp(&mockSecretsUC{})

	body := `{"filename":"f.bin","mime_type":"application/octet-stream","data":"aGVsbG8="}`
	req := httptest.NewRequest("POST", "/api/user/secret/post-binary-secret", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(b))
	}
}

func TestGetBinarySecret_Success(t *testing.T) {
	uc := &mockSecretsUC{
		getBinarySecretsFn: func(_ context.Context, _ string) ([]entity.BinarySecret, error) {
			return []entity.BinarySecret{{Filename: "f.bin"}}, nil
		},
	}
	app := setupSecretApp(uc)

	req := httptest.NewRequest("GET", "/api/user/secret/get-binary-secret", nil)
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestPostCardSecret_Success(t *testing.T) {
	app := setupSecretApp(&mockSecretsUC{})

	body := `{"cardholder":"John","pan":"4111","exp_month":"12","exp_year":"2025","brand":"Visa","last4":"1111"}`
	req := httptest.NewRequest("POST", "/api/user/secret/post-card-secret", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(b))
	}
}

func TestGetCardSecret_Success(t *testing.T) {
	uc := &mockSecretsUC{
		getCardSecretsFn: func(_ context.Context, _ string) ([]entity.CardSecret, error) {
			return []entity.CardSecret{{Cardholder: "John"}}, nil
		},
	}
	app := setupSecretApp(uc)

	req := httptest.NewRequest("GET", "/api/user/secret/get-card-secret", nil)
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestGetAllSecrets_Success(t *testing.T) {
	uc := &mockSecretsUC{
		getAllSecretsFn: func(_ context.Context, _ string) (entity.AllSecrets, error) {
			return entity.AllSecrets{
				LoginPassword: []entity.LoginPassword{{Login: "a"}},
			}, nil
		},
	}
	app := setupSecretApp(uc)

	req := httptest.NewRequest("GET", "/api/user/secret/get-all-secrets", nil)
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestGetAllSecrets_Error(t *testing.T) {
	uc := &mockSecretsUC{
		getAllSecretsFn: func(_ context.Context, _ string) (entity.AllSecrets, error) {
			return entity.AllSecrets{}, domain.ErrNotFound
		},
	}
	app := setupSecretApp(uc)

	req := httptest.NewRequest("GET", "/api/user/secret/get-all-secrets", nil)
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestSecretEndpoint_NoToken(t *testing.T) {
	app := setupSecretApp(&mockSecretsUC{})

	req := httptest.NewRequest("GET", "/api/user/secret/get-all-secrets", nil)
	resp, _ := app.Test(req)
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestDeleteTextSecret_Success(t *testing.T) {
	app := setupSecretApp(&mockSecretsUC{})
	body := `{"title":"note"}`
	req := httptest.NewRequest("DELETE", "/api/user/secret/delete-text-secret", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(b))
	}
}

func TestDeleteBinarySecret_Success(t *testing.T) {
	app := setupSecretApp(&mockSecretsUC{})
	body := `{"filename":"f.bin"}`
	req := httptest.NewRequest("DELETE", "/api/user/secret/delete-binary-secret", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(b))
	}
}

func TestDeleteCardSecret_Success(t *testing.T) {
	app := setupSecretApp(&mockSecretsUC{})
	body := `{"cardholder":"John"}`
	req := httptest.NewRequest("DELETE", "/api/user/secret/delete-card-secret", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(b))
	}
}

// --- Additional error tests for 80%+ coverage ---

func TestPostLoginPassword_InternalError(t *testing.T) {
	uc := &mockSecretsUC{
		createLoginPasswordFn: func(_ context.Context, _ string, _ request.LoginPassword) error {
			return errors.New("db failure")
		},
	}
	app := setupSecretApp(uc)
	body := `{"login":"a","password":"b"}`
	req := httptest.NewRequest("POST", "/api/user/secret/post-login-password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 500 {
		t.Fatalf("expected 500, got %d", resp.StatusCode)
	}
}

func TestPostLoginPassword_Conflict(t *testing.T) {
	uc := &mockSecretsUC{
		createLoginPasswordFn: func(_ context.Context, _ string, _ request.LoginPassword) error {
			return domain.ErrAlreadyExists
		},
	}
	app := setupSecretApp(uc)
	body := `{"login":"a","password":"b"}`
	req := httptest.NewRequest("POST", "/api/user/secret/post-login-password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 409 {
		t.Fatalf("expected 409, got %d", resp.StatusCode)
	}
}

func TestPostTextSecret_Error(t *testing.T) {
	uc := &mockSecretsUC{
		createTextSecretFn: func(_ context.Context, _ string, _ request.TextSecret) error {
			return domain.ErrInvalidInput
		},
	}
	app := setupSecretApp(uc)
	body := `{"title":"","body":"hi"}`
	req := httptest.NewRequest("POST", "/api/user/secret/post-text-secret", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestPostBinarySecret_Error(t *testing.T) {
	uc := &mockSecretsUC{
		createBinarySecretFn: func(_ context.Context, _ string, _ request.BinarySecret) error {
			return domain.ErrInvalidInput
		},
	}
	app := setupSecretApp(uc)
	body := `{"filename":"","data":"x"}`
	req := httptest.NewRequest("POST", "/api/user/secret/post-binary-secret", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestPostCardSecret_Error(t *testing.T) {
	uc := &mockSecretsUC{
		createCardSecretFn: func(_ context.Context, _ string, _ request.CardSecret) error {
			return domain.ErrInvalidInput
		},
	}
	app := setupSecretApp(uc)
	body := `{"cardholder":"","pan":"x"}`
	req := httptest.NewRequest("POST", "/api/user/secret/post-card-secret", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestDeleteLoginPassword_Error(t *testing.T) {
	uc := &mockSecretsUC{
		deleteLoginPasswordFn: func(_ context.Context, _ string, _ string) error {
			return domain.ErrNotFound
		},
	}
	app := setupSecretApp(uc)
	body := `{"login":"x"}`
	req := httptest.NewRequest("DELETE", "/api/user/secret/delete-login-password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestDeleteTextSecret_Error(t *testing.T) {
	uc := &mockSecretsUC{
		deleteTextSecretFn: func(_ context.Context, _ string, _ string) error {
			return domain.ErrNotFound
		},
	}
	app := setupSecretApp(uc)
	body := `{"title":"x"}`
	req := httptest.NewRequest("DELETE", "/api/user/secret/delete-text-secret", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestDeleteBinarySecret_Error(t *testing.T) {
	uc := &mockSecretsUC{
		deleteBinarySecretFn: func(_ context.Context, _ string, _ string) error {
			return domain.ErrNotFound
		},
	}
	app := setupSecretApp(uc)
	body := `{"filename":"x"}`
	req := httptest.NewRequest("DELETE", "/api/user/secret/delete-binary-secret", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestDeleteCardSecret_Error(t *testing.T) {
	uc := &mockSecretsUC{
		deleteCardSecretFn: func(_ context.Context, _ string, _ string) error {
			return domain.ErrNotFound
		},
	}
	app := setupSecretApp(uc)
	body := `{"cardholder":"x"}`
	req := httptest.NewRequest("DELETE", "/api/user/secret/delete-card-secret", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestGetTextSecret_Error(t *testing.T) {
	uc := &mockSecretsUC{
		getTextSecretsFn: func(_ context.Context, _ string) ([]entity.TextSecret, error) {
			return nil, domain.ErrNotFound
		},
	}
	app := setupSecretApp(uc)
	req := httptest.NewRequest("GET", "/api/user/secret/get-text-secret", nil)
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestGetBinarySecret_Error(t *testing.T) {
	uc := &mockSecretsUC{
		getBinarySecretsFn: func(_ context.Context, _ string) ([]entity.BinarySecret, error) {
			return nil, domain.ErrNotFound
		},
	}
	app := setupSecretApp(uc)
	req := httptest.NewRequest("GET", "/api/user/secret/get-binary-secret", nil)
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestGetCardSecret_Error(t *testing.T) {
	uc := &mockSecretsUC{
		getCardSecretsFn: func(_ context.Context, _ string) ([]entity.CardSecret, error) {
			return nil, domain.ErrNotFound
		},
	}
	app := setupSecretApp(uc)
	req := httptest.NewRequest("GET", "/api/user/secret/get-card-secret", nil)
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestHandlerRegUser_BodyParseError(t *testing.T) {
	app := fiber.New()
	uc := &mockAuthUC{}
	v1.NewAuthRoutes(app, uc, jwtConf(), &noopLogger{})

	req := httptest.NewRequest("POST", "/api/user/register", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	if resp.StatusCode != 500 {
		t.Fatalf("expected 500, got %d", resp.StatusCode)
	}
}

func TestHandlerRegUser_AuthFailAfterReg(t *testing.T) {
	app := fiber.New()
	uc := &mockAuthUC{
		regUserFn:  func(_ context.Context, _ entity.UserInput) error { return nil },
		authUserFn: func(_ context.Context, _ entity.UserInput) (bool, error) { return false, nil },
	}
	v1.NewAuthRoutes(app, uc, jwtConf(), &noopLogger{})

	body := `{"login":"user","password":"pass"}`
	req := httptest.NewRequest("POST", "/api/user/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	if resp.StatusCode != 500 {
		t.Fatalf("expected 500, got %d", resp.StatusCode)
	}
}

func TestDeleteUser_InternalError(t *testing.T) {
	app := fiber.New()
	uc := &mockAuthUC{
		deleteUserFn: func(_ context.Context, _ entity.UserInput) error { return errors.New("fail") },
	}
	v1.NewAuthRoutes(app, uc, jwtConf(), &noopLogger{})

	tok := createToken("user")
	req := httptest.NewRequest("DELETE", "/api/user/delete-user", nil)
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, _ := app.Test(req)
	if resp.StatusCode != 500 {
		t.Fatalf("expected 500, got %d", resp.StatusCode)
	}
}

func TestPostLoginPassword_InvalidBody(t *testing.T) {
	app := setupSecretApp(&mockSecretsUC{})
	req := httptest.NewRequest("POST", "/api/user/secret/post-login-password", strings.NewReader("bad json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}
