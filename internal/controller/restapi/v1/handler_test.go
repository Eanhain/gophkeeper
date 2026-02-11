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
const testCryptoKey = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

type noopLogger struct{}

func (l *noopLogger) Debug(msg interface{}, args ...interface{}) {}
func (l *noopLogger) Info(msg string, args ...interface{})       {}
func (l *noopLogger) Warn(msg string, args ...interface{})       {}
func (l *noopLogger) Error(msg interface{}, args ...interface{}) {}
func (l *noopLogger) Fatal(msg interface{}, args ...interface{}) {}

// createToken создаёт JWT-токен с claim-ами login и crypto_key.
func createToken(username string) string {
	claims := jwt.MapClaims{
		"login":      username,
		"crypto_key": testCryptoKey,
		"exp":        time.Now().Add(time.Hour).Unix(),
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

// --- мок AuthUseCase ---

type mockAuthUC struct {
	// AuthUser теперь возвращает (bool, string, error) — ok, cryptoKey, err
	authUserFn   func(ctx context.Context, user entity.UserInput) (bool, string, error)
	regUserFn    func(ctx context.Context, user entity.UserInput) error
	deleteUserFn func(ctx context.Context, user entity.UserInput) error
}

func (m *mockAuthUC) AuthUser(ctx context.Context, user entity.UserInput) (bool, string, error) {
	if m.authUserFn != nil {
		return m.authUserFn(ctx, user)
	}
	return true, testCryptoKey, nil
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

// --- мок SecretsUseCase ---
// Все методы теперь принимают cryptoKey string (второй параметр после username).

type mockSecretsUC struct {
	createLoginPasswordFn func(ctx context.Context, username, cryptoKey string, lp request.LoginPassword) error
	getLoginPasswordsFn   func(ctx context.Context, username, cryptoKey string) ([]entity.LoginPassword, error)
	deleteLoginPasswordFn func(ctx context.Context, username, cryptoKey string, login string) error
	createTextSecretFn    func(ctx context.Context, username, cryptoKey string, ts request.TextSecret) error
	getTextSecretsFn      func(ctx context.Context, username, cryptoKey string) ([]entity.TextSecret, error)
	deleteTextSecretFn    func(ctx context.Context, username, cryptoKey string, title string) error
	createBinarySecretFn  func(ctx context.Context, username, cryptoKey string, bs request.BinarySecret) error
	getBinarySecretsFn    func(ctx context.Context, username, cryptoKey string) ([]entity.BinarySecret, error)
	deleteBinarySecretFn  func(ctx context.Context, username, cryptoKey string, filename string) error
	createCardSecretFn    func(ctx context.Context, username, cryptoKey string, cs request.CardSecret) error
	getCardSecretsFn      func(ctx context.Context, username, cryptoKey string) ([]entity.CardSecret, error)
	deleteCardSecretFn    func(ctx context.Context, username, cryptoKey string, cardholder string) error
	getAllSecretsFn       func(ctx context.Context, username, cryptoKey string) (entity.AllSecrets, error)
}

func (m *mockSecretsUC) CreateLoginPassword(ctx context.Context, u, ck string, lp request.LoginPassword) error {
	if m.createLoginPasswordFn != nil {
		return m.createLoginPasswordFn(ctx, u, ck, lp)
	}
	return nil
}
func (m *mockSecretsUC) GetLoginPasswords(ctx context.Context, u, ck string) ([]entity.LoginPassword, error) {
	if m.getLoginPasswordsFn != nil {
		return m.getLoginPasswordsFn(ctx, u, ck)
	}
	return nil, nil
}
func (m *mockSecretsUC) DeleteLoginPassword(ctx context.Context, u, ck string, login string) error {
	if m.deleteLoginPasswordFn != nil {
		return m.deleteLoginPasswordFn(ctx, u, ck, login)
	}
	return nil
}
func (m *mockSecretsUC) CreateTextSecret(ctx context.Context, u, ck string, ts request.TextSecret) error {
	if m.createTextSecretFn != nil {
		return m.createTextSecretFn(ctx, u, ck, ts)
	}
	return nil
}
func (m *mockSecretsUC) GetTextSecrets(ctx context.Context, u, ck string) ([]entity.TextSecret, error) {
	if m.getTextSecretsFn != nil {
		return m.getTextSecretsFn(ctx, u, ck)
	}
	return nil, nil
}
func (m *mockSecretsUC) DeleteTextSecret(ctx context.Context, u, ck string, title string) error {
	if m.deleteTextSecretFn != nil {
		return m.deleteTextSecretFn(ctx, u, ck, title)
	}
	return nil
}
func (m *mockSecretsUC) CreateBinarySecret(ctx context.Context, u, ck string, bs request.BinarySecret) error {
	if m.createBinarySecretFn != nil {
		return m.createBinarySecretFn(ctx, u, ck, bs)
	}
	return nil
}
func (m *mockSecretsUC) GetBinarySecrets(ctx context.Context, u, ck string) ([]entity.BinarySecret, error) {
	if m.getBinarySecretsFn != nil {
		return m.getBinarySecretsFn(ctx, u, ck)
	}
	return nil, nil
}
func (m *mockSecretsUC) DeleteBinarySecret(ctx context.Context, u, ck string, filename string) error {
	if m.deleteBinarySecretFn != nil {
		return m.deleteBinarySecretFn(ctx, u, ck, filename)
	}
	return nil
}
func (m *mockSecretsUC) CreateCardSecret(ctx context.Context, u, ck string, cs request.CardSecret) error {
	if m.createCardSecretFn != nil {
		return m.createCardSecretFn(ctx, u, ck, cs)
	}
	return nil
}
func (m *mockSecretsUC) GetCardSecrets(ctx context.Context, u, ck string) ([]entity.CardSecret, error) {
	if m.getCardSecretsFn != nil {
		return m.getCardSecretsFn(ctx, u, ck)
	}
	return nil, nil
}
func (m *mockSecretsUC) DeleteCardSecret(ctx context.Context, u, ck string, cardholder string) error {
	if m.deleteCardSecretFn != nil {
		return m.deleteCardSecretFn(ctx, u, ck, cardholder)
	}
	return nil
}
func (m *mockSecretsUC) GetAllSecrets(ctx context.Context, u, ck string) (entity.AllSecrets, error) {
	if m.getAllSecretsFn != nil {
		return m.getAllSecretsFn(ctx, u, ck)
	}
	return entity.AllSecrets{}, nil
}

// --- вспомогательные функции ---

func parseJSON(t *testing.T, r io.Reader) map[string]interface{} {
	t.Helper()
	var result map[string]interface{}
	if err := json.NewDecoder(r).Decode(&result); err != nil {
		t.Fatalf("ошибка парсинга json: %v", err)
	}
	return result
}

// --- Тесты хендлеров авторизации ---

func TestLoginJWT_Success(t *testing.T) {
	app := fiber.New()
	uc := &mockAuthUC{
		authUserFn: func(_ context.Context, _ entity.UserInput) (bool, string, error) {
			return true, testCryptoKey, nil
		},
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
		t.Fatalf("ожидали 200, получили %d", resp.StatusCode)
	}
	result := parseJSON(t, resp.Body)
	if result["token"] == nil || result["token"] == "" {
		t.Fatal("ожидали token в ответе")
	}
}

func TestLoginJWT_AuthFail(t *testing.T) {
	app := fiber.New()
	uc := &mockAuthUC{
		authUserFn: func(_ context.Context, _ entity.UserInput) (bool, string, error) {
			return false, "", nil
		},
	}
	v1.NewAuthRoutes(app, uc, jwtConf(), &noopLogger{})

	body := `{"login":"user","password":"wrong"}`
	req := httptest.NewRequest("POST", "/api/user/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	if resp.StatusCode != 401 {
		t.Fatalf("ожидали 401, получили %d", resp.StatusCode)
	}
}

func TestHandlerRegUser_Success(t *testing.T) {
	app := fiber.New()
	uc := &mockAuthUC{
		regUserFn: func(_ context.Context, _ entity.UserInput) error { return nil },
		authUserFn: func(_ context.Context, _ entity.UserInput) (bool, string, error) {
			return true, testCryptoKey, nil
		},
	}
	v1.NewAuthRoutes(app, uc, jwtConf(), &noopLogger{})

	body := `{"login":"newuser","password":"pass"}`
	req := httptest.NewRequest("POST", "/api/user/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("ожидали 200, получили %d: %s", resp.StatusCode, string(b))
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
		t.Fatalf("ожидали 409, получили %d", resp.StatusCode)
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
		t.Fatalf("ожидали 200, получили %d: %s", resp.StatusCode, string(b))
	}
}

func TestDeleteUser_NoToken(t *testing.T) {
	app := fiber.New()
	uc := &mockAuthUC{}
	v1.NewAuthRoutes(app, uc, jwtConf(), &noopLogger{})

	req := httptest.NewRequest("DELETE", "/api/user/delete-user", nil)
	resp, _ := app.Test(req)
	if resp.StatusCode != 401 {
		t.Fatalf("ожидали 401, получили %d", resp.StatusCode)
	}
}

// --- Тесты хендлеров секретов ---

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
		t.Fatalf("ожидали 200, получили %d: %s", resp.StatusCode, string(b))
	}
}

func TestPostLoginPassword_ValidationError(t *testing.T) {
	uc := &mockSecretsUC{
		createLoginPasswordFn: func(_ context.Context, _, _ string, _ request.LoginPassword) error {
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
		t.Fatalf("ожидали 400, получили %d", resp.StatusCode)
	}
}

func TestGetLoginPassword_Success(t *testing.T) {
	uc := &mockSecretsUC{
		getLoginPasswordsFn: func(_ context.Context, _, _ string) ([]entity.LoginPassword, error) {
			return []entity.LoginPassword{{Login: "a", Password: "b", Label: "c"}}, nil
		},
	}
	app := setupSecretApp(uc)

	req := httptest.NewRequest("GET", "/api/user/secret/get-login-password", nil)
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 200 {
		t.Fatalf("ожидали 200, получили %d", resp.StatusCode)
	}
}

func TestGetLoginPassword_Error(t *testing.T) {
	uc := &mockSecretsUC{
		getLoginPasswordsFn: func(_ context.Context, _, _ string) ([]entity.LoginPassword, error) {
			return nil, domain.ErrNotFound
		},
	}
	app := setupSecretApp(uc)

	req := httptest.NewRequest("GET", "/api/user/secret/get-login-password", nil)
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 404 {
		t.Fatalf("ожидали 404, получили %d", resp.StatusCode)
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
		t.Fatalf("ожидали 200, получили %d: %s", resp.StatusCode, string(b))
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
		t.Fatalf("ожидали 200, получили %d: %s", resp.StatusCode, string(b))
	}
}

func TestGetTextSecret_Success(t *testing.T) {
	uc := &mockSecretsUC{
		getTextSecretsFn: func(_ context.Context, _, _ string) ([]entity.TextSecret, error) {
			return []entity.TextSecret{{Title: "note", Body: "hi"}}, nil
		},
	}
	app := setupSecretApp(uc)

	req := httptest.NewRequest("GET", "/api/user/secret/get-text-secret", nil)
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 200 {
		t.Fatalf("ожидали 200, получили %d", resp.StatusCode)
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
		t.Fatalf("ожидали 200, получили %d: %s", resp.StatusCode, string(b))
	}
}

func TestGetBinarySecret_Success(t *testing.T) {
	uc := &mockSecretsUC{
		getBinarySecretsFn: func(_ context.Context, _, _ string) ([]entity.BinarySecret, error) {
			return []entity.BinarySecret{{Filename: "f.bin"}}, nil
		},
	}
	app := setupSecretApp(uc)

	req := httptest.NewRequest("GET", "/api/user/secret/get-binary-secret", nil)
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 200 {
		t.Fatalf("ожидали 200, получили %d", resp.StatusCode)
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
		t.Fatalf("ожидали 200, получили %d: %s", resp.StatusCode, string(b))
	}
}

func TestGetCardSecret_Success(t *testing.T) {
	uc := &mockSecretsUC{
		getCardSecretsFn: func(_ context.Context, _, _ string) ([]entity.CardSecret, error) {
			return []entity.CardSecret{{Cardholder: "John"}}, nil
		},
	}
	app := setupSecretApp(uc)

	req := httptest.NewRequest("GET", "/api/user/secret/get-card-secret", nil)
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 200 {
		t.Fatalf("ожидали 200, получили %d", resp.StatusCode)
	}
}

func TestGetAllSecrets_Success(t *testing.T) {
	uc := &mockSecretsUC{
		getAllSecretsFn: func(_ context.Context, _, _ string) (entity.AllSecrets, error) {
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
		t.Fatalf("ожидали 200, получили %d", resp.StatusCode)
	}
}

func TestGetAllSecrets_Error(t *testing.T) {
	uc := &mockSecretsUC{
		getAllSecretsFn: func(_ context.Context, _, _ string) (entity.AllSecrets, error) {
			return entity.AllSecrets{}, domain.ErrNotFound
		},
	}
	app := setupSecretApp(uc)

	req := httptest.NewRequest("GET", "/api/user/secret/get-all-secrets", nil)
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 404 {
		t.Fatalf("ожидали 404, получили %d", resp.StatusCode)
	}
}

func TestSecretEndpoint_NoToken(t *testing.T) {
	app := setupSecretApp(&mockSecretsUC{})

	req := httptest.NewRequest("GET", "/api/user/secret/get-all-secrets", nil)
	resp, _ := app.Test(req)
	if resp.StatusCode != 401 {
		t.Fatalf("ожидали 401, получили %d", resp.StatusCode)
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
		t.Fatalf("ожидали 200, получили %d: %s", resp.StatusCode, string(b))
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
		t.Fatalf("ожидали 200, получили %d: %s", resp.StatusCode, string(b))
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
		t.Fatalf("ожидали 200, получили %d: %s", resp.StatusCode, string(b))
	}
}

// --- Дополнительные тесты на ошибки для покрытия 80%+ ---

func TestPostLoginPassword_InternalError(t *testing.T) {
	uc := &mockSecretsUC{
		createLoginPasswordFn: func(_ context.Context, _, _ string, _ request.LoginPassword) error {
			return errors.New("ошибка БД")
		},
	}
	app := setupSecretApp(uc)
	body := `{"login":"a","password":"b"}`
	req := httptest.NewRequest("POST", "/api/user/secret/post-login-password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 500 {
		t.Fatalf("ожидали 500, получили %d", resp.StatusCode)
	}
}

func TestPostLoginPassword_Conflict(t *testing.T) {
	uc := &mockSecretsUC{
		createLoginPasswordFn: func(_ context.Context, _, _ string, _ request.LoginPassword) error {
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
		t.Fatalf("ожидали 409, получили %d", resp.StatusCode)
	}
}

func TestPostTextSecret_Error(t *testing.T) {
	uc := &mockSecretsUC{
		createTextSecretFn: func(_ context.Context, _, _ string, _ request.TextSecret) error {
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
		t.Fatalf("ожидали 400, получили %d", resp.StatusCode)
	}
}

func TestPostBinarySecret_Error(t *testing.T) {
	uc := &mockSecretsUC{
		createBinarySecretFn: func(_ context.Context, _, _ string, _ request.BinarySecret) error {
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
		t.Fatalf("ожидали 400, получили %d", resp.StatusCode)
	}
}

func TestPostCardSecret_Error(t *testing.T) {
	uc := &mockSecretsUC{
		createCardSecretFn: func(_ context.Context, _, _ string, _ request.CardSecret) error {
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
		t.Fatalf("ожидали 400, получили %d", resp.StatusCode)
	}
}

func TestDeleteLoginPassword_Error(t *testing.T) {
	uc := &mockSecretsUC{
		deleteLoginPasswordFn: func(_ context.Context, _, _ string, _ string) error {
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
		t.Fatalf("ожидали 404, получили %d", resp.StatusCode)
	}
}

func TestDeleteTextSecret_Error(t *testing.T) {
	uc := &mockSecretsUC{
		deleteTextSecretFn: func(_ context.Context, _, _ string, _ string) error {
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
		t.Fatalf("ожидали 404, получили %d", resp.StatusCode)
	}
}

func TestDeleteBinarySecret_Error(t *testing.T) {
	uc := &mockSecretsUC{
		deleteBinarySecretFn: func(_ context.Context, _, _ string, _ string) error {
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
		t.Fatalf("ожидали 404, получили %d", resp.StatusCode)
	}
}

func TestDeleteCardSecret_Error(t *testing.T) {
	uc := &mockSecretsUC{
		deleteCardSecretFn: func(_ context.Context, _, _ string, _ string) error {
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
		t.Fatalf("ожидали 404, получили %d", resp.StatusCode)
	}
}

func TestGetTextSecret_Error(t *testing.T) {
	uc := &mockSecretsUC{
		getTextSecretsFn: func(_ context.Context, _, _ string) ([]entity.TextSecret, error) {
			return nil, domain.ErrNotFound
		},
	}
	app := setupSecretApp(uc)
	req := httptest.NewRequest("GET", "/api/user/secret/get-text-secret", nil)
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 404 {
		t.Fatalf("ожидали 404, получили %d", resp.StatusCode)
	}
}

func TestGetBinarySecret_Error(t *testing.T) {
	uc := &mockSecretsUC{
		getBinarySecretsFn: func(_ context.Context, _, _ string) ([]entity.BinarySecret, error) {
			return nil, domain.ErrNotFound
		},
	}
	app := setupSecretApp(uc)
	req := httptest.NewRequest("GET", "/api/user/secret/get-binary-secret", nil)
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 404 {
		t.Fatalf("ожидали 404, получили %d", resp.StatusCode)
	}
}

func TestGetCardSecret_Error(t *testing.T) {
	uc := &mockSecretsUC{
		getCardSecretsFn: func(_ context.Context, _, _ string) ([]entity.CardSecret, error) {
			return nil, domain.ErrNotFound
		},
	}
	app := setupSecretApp(uc)
	req := httptest.NewRequest("GET", "/api/user/secret/get-card-secret", nil)
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 404 {
		t.Fatalf("ожидали 404, получили %d", resp.StatusCode)
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
		t.Fatalf("ожидали 500, получили %d", resp.StatusCode)
	}
}

func TestHandlerRegUser_AuthFailAfterReg(t *testing.T) {
	app := fiber.New()
	uc := &mockAuthUC{
		regUserFn: func(_ context.Context, _ entity.UserInput) error { return nil },
		authUserFn: func(_ context.Context, _ entity.UserInput) (bool, string, error) {
			return false, "", nil
		},
	}
	v1.NewAuthRoutes(app, uc, jwtConf(), &noopLogger{})

	body := `{"login":"user","password":"pass"}`
	req := httptest.NewRequest("POST", "/api/user/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	if resp.StatusCode != 500 {
		t.Fatalf("ожидали 500, получили %d", resp.StatusCode)
	}
}

func TestDeleteUser_InternalError(t *testing.T) {
	app := fiber.New()
	uc := &mockAuthUC{
		deleteUserFn: func(_ context.Context, _ entity.UserInput) error { return errors.New("ошибка") },
	}
	v1.NewAuthRoutes(app, uc, jwtConf(), &noopLogger{})

	tok := createToken("user")
	req := httptest.NewRequest("DELETE", "/api/user/delete-user", nil)
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, _ := app.Test(req)
	if resp.StatusCode != 500 {
		t.Fatalf("ожидали 500, получили %d", resp.StatusCode)
	}
}

func TestPostLoginPassword_InvalidBody(t *testing.T) {
	app := setupSecretApp(&mockSecretsUC{})
	req := httptest.NewRequest("POST", "/api/user/secret/post-login-password", strings.NewReader("bad json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+createToken("user"))

	resp, _ := app.Test(req)
	if resp.StatusCode != 400 {
		t.Fatalf("ожидали 400, получили %d", resp.StatusCode)
	}
}
