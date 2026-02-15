package middleware

import (
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
)

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
