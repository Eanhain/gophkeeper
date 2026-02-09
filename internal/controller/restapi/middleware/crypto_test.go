package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := deriveKey("test-key")
	plain := []byte("hello world")

	enc, err := encrypt(key, plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	dec, err := decrypt(key, enc)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if string(dec) != string(plain) {
		t.Fatalf("expected %q, got %q", plain, dec)
	}
}

func TestDecryptWrongKey(t *testing.T) {
	k1 := deriveKey("k1")
	k2 := deriveKey("k2")

	enc, _ := encrypt(k1, []byte("data"))
	_, err := decrypt(k2, enc)
	if err == nil {
		t.Fatal("expected decrypt error with wrong key")
	}
}

func TestDecryptShortCiphertext(t *testing.T) {
	key := deriveKey("key")
	_, err := decrypt(key, []byte("short"))
	if err == nil {
		t.Fatal("expected error for short ciphertext")
	}
}

func TestCryptoMiddleware_Success(t *testing.T) {
	app := fiber.New()
	app.Use(CryptoMiddleware("test-secret"))
	app.Post("/test", func(c *fiber.Ctx) error {
		var body map[string]string
		if err := c.BodyParser(&body); err != nil {
			return fiber.NewError(400, "bad body")
		}
		return c.JSON(body)
	})

	key := deriveKey("test-secret")
	payload, _ := json.Marshal(map[string]string{"hello": "world"})
	enc, _ := encrypt(key, payload)

	req := httptest.NewRequest("POST", "/test", bytes.NewReader(enc))
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	dec, err := decrypt(key, body)
	if err != nil {
		t.Fatalf("decrypt response: %v", err)
	}

	var result map[string]string
	json.Unmarshal(dec, &result)
	if result["hello"] != "world" {
		t.Fatalf("expected world, got %s", result["hello"])
	}
}

func TestCryptoMiddleware_HandlerError(t *testing.T) {
	app := fiber.New()
	app.Use(CryptoMiddleware("test-secret"))
	app.Post("/fail", func(c *fiber.Ctx) error {
		return fiber.NewError(fiber.StatusBadRequest, "validation failed")
	})

	key := deriveKey("test-secret")
	enc, _ := encrypt(key, []byte(`{}`))

	req := httptest.NewRequest("POST", "/fail", bytes.NewReader(enc))
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	dec, _ := decrypt(key, body)

	var result map[string]string
	json.Unmarshal(dec, &result)
	if result["error"] != "validation failed" {
		t.Fatalf("expected 'validation failed', got %q", result["error"])
	}
}

func TestCryptoMiddleware_BadEncryption(t *testing.T) {
	app := fiber.New()
	app.Use(CryptoMiddleware("test-secret"))
	app.Post("/test", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"ok": true})
	})

	req := httptest.NewRequest("POST", "/test", bytes.NewReader([]byte("not encrypted data")))
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 for bad encryption, got %d", resp.StatusCode)
	}
}

func TestCryptoMiddleware_EmptyBody(t *testing.T) {
	app := fiber.New()
	app.Use(CryptoMiddleware("test-secret"))
	app.Get("/empty", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	key := deriveKey("test-secret")

	req := httptest.NewRequest("GET", "/empty", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	dec, err := decrypt(key, body)
	if err != nil {
		t.Fatalf("decrypt empty body response: %v", err)
	}

	var result map[string]string
	json.Unmarshal(dec, &result)
	if result["status"] != "ok" {
		t.Fatalf("expected ok, got %s", result["status"])
	}
}

func TestDeriveKey(t *testing.T) {
	k1 := deriveKey("abc")
	k2 := deriveKey("abc")
	if string(k1) != string(k2) {
		t.Fatal("same passphrase must produce same key")
	}
	k3 := deriveKey("xyz")
	if string(k1) == string(k3) {
		t.Fatal("different passphrases must produce different keys")
	}
	if len(k1) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(k1))
	}
}

func TestEncryptBadKey(t *testing.T) {
	_, err := encrypt([]byte("short"), []byte("data"))
	if err == nil {
		t.Fatal("expected error for invalid key length")
	}
}

func TestDecryptBadKey(t *testing.T) {
	_, err := decrypt([]byte("short"), []byte("some-ciphertext-that-is-long-enough-for-nonce-validation"))
	if err == nil {
		t.Fatal("expected error for invalid key length")
	}
}

func TestRecovery(t *testing.T) {
	l := &testLogger{}
	app := fiber.New()
	app.Use(Recovery(l))
	app.Get("/panic", func(c *fiber.Ctx) error {
		panic("test panic")
	})

	req := httptest.NewRequest("GET", "/panic", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 500 {
		t.Fatalf("expected 500, got %d", resp.StatusCode)
	}
	if !l.called {
		t.Fatal("expected logger to be called on panic")
	}
}

type testLogger struct {
	called bool
}

func (l *testLogger) Debug(msg interface{}, args ...interface{}) {}
func (l *testLogger) Info(msg string, args ...interface{})       {}
func (l *testLogger) Warn(msg string, args ...interface{})       {}
func (l *testLogger) Error(msg interface{}, args ...interface{}) { l.called = true }
func (l *testLogger) Fatal(msg interface{}, args ...interface{}) {}

func TestCryptoMiddleware_InternalServerError(t *testing.T) {
	app := fiber.New()
	app.Use(CryptoMiddleware("test-secret"))
	app.Post("/err500", func(c *fiber.Ctx) error {
		return fiber.ErrInternalServerError
	})

	key := deriveKey("test-secret")
	enc, _ := encrypt(key, []byte(`{}`))

	req := httptest.NewRequest("POST", "/err500", bytes.NewReader(enc))
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 500 {
		t.Fatalf("expected 500, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	dec, _ := decrypt(key, body)

	var result map[string]string
	json.Unmarshal(dec, &result)
	if result["error"] != "Internal Server Error" {
		t.Fatalf("expected 'Internal Server Error', got %q", result["error"])
	}
}

func TestCryptoMiddleware_GetWithEncryptedResponse(t *testing.T) {
	app := fiber.New()
	app.Use(CryptoMiddleware("test-secret"))
	app.Get("/data", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"items": []string{"a", "b"}})
	})

	key := deriveKey("test-secret")

	req := httptest.NewRequest("GET", "/data", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	dec, err := decrypt(key, body)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	var result map[string]interface{}
	json.Unmarshal(dec, &result)
	if result["items"] == nil {
		t.Fatal("expected items in response")
	}
}
