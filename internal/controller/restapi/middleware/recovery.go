package middleware

import (
	"fmt"
	"runtime/debug"
	"strings"

	"github.com/Eanhain/gophkeeper/domain"
	"github.com/gofiber/fiber/v2"
	fiberRecover "github.com/gofiber/fiber/v2/middleware/recover"
)

// buildPanicMessage constructs a human-readable string that includes
// the client IP, HTTP method, URL, panic value and the full goroutine
// stack trace. This string is then handed to the logger.
func buildPanicMessage(ctx *fiber.Ctx, err any) string {
	var result strings.Builder

	result.WriteString(ctx.IP())
	result.WriteString(" - ")
	result.WriteString(ctx.Method())
	result.WriteString(" ")
	result.WriteString(ctx.OriginalURL())
	result.WriteString(" PANIC DETECTED: ")
	result.WriteString(fmt.Sprintf("%v\n%s\n", err, debug.Stack()))

	return result.String()
}

// logPanic returns a Fiber-compatible StackTraceHandler that logs
// the panic message via the application logger at ERROR level.
func logPanic(l domain.LoggerI) func(c *fiber.Ctx, err interface{}) {
	return func(ctx *fiber.Ctx, err interface{}) {
		l.Error(buildPanicMessage(ctx, err))
	}
}

// Recovery returns a Fiber middleware that catches panics in handlers,
// logs the stack trace and returns HTTP 500 to the client instead of
// crashing the entire server process.
func Recovery(l domain.LoggerI) func(c *fiber.Ctx) error {
	return fiberRecover.New(fiberRecover.Config{
		EnableStackTrace:  true,
		StackTraceHandler: logPanic(l),
	})
}
