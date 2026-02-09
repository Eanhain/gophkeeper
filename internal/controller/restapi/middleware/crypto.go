// Package middleware provides Fiber middleware for the GophKeeper server.
//
// CryptoMiddleware encrypts/decrypts every request and response body
// with AES-256-GCM so that all traffic between the client and server
// is protected even without TLS.
//
// Recovery middleware catches panics and logs the stack trace.
package middleware

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"github.com/gofiber/fiber/v2"
)

// deriveKey produces a 32-byte AES-256 key from an arbitrary passphrase
// by taking its SHA-256 hash. Both the client and the server must use
// the same passphrase.
func deriveKey(passphrase string) []byte {
	h := sha256.Sum256([]byte(passphrase))
	return h[:]
}

// encrypt wraps plaintext with AES-256-GCM.
// The returned byte slice is nonce || ciphertext.
func encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// decrypt reverses the output of encrypt.
// It expects the ciphertext in the form nonce || ciphertext.
func decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(ciphertext) < ns {
		return nil, fiber.ErrBadRequest
	}
	return gcm.Open(nil, ciphertext[:ns], ciphertext[ns:], nil)
}

// CryptoMiddleware returns a Fiber middleware that:
//  1. Decrypts the incoming request body (if present) and sets Content-Type
//     to application/json so downstream handlers can use BodyParser normally.
//  2. Calls the next handler in the chain.
//  3. If the handler returned an error (e.g. fiber.ErrBadRequest),
//     the error is serialised to {"error":"..."} JSON and the status code is set.
//  4. Encrypts the complete response body with AES-256-GCM and sets
//     Content-Type to application/octet-stream.
//
// This ensures that even error messages are transmitted encrypted.
func CryptoMiddleware(cryptoKey string) fiber.Handler {
	key := deriveKey(cryptoKey)

	return func(c *fiber.Ctx) error {
		// --- decrypt request ---
		if len(c.Body()) > 0 {
			plain, err := decrypt(key, c.Body())
			if err != nil {
				return fiber.ErrBadRequest
			}
			c.Request().SetBody(plain)
			c.Request().Header.SetContentType(fiber.MIMEApplicationJSON)
		}

		// --- execute handler ---
		err := c.Next()

		// --- format handler errors as JSON ---
		if err != nil {
			code := fiber.StatusInternalServerError
			msg := "internal server error"
			if fe, ok := err.(*fiber.Error); ok {
				code = fe.Code
				msg = fe.Message
			}
			c.Status(code)
			c.JSON(fiber.Map{"error": msg})
			err = nil
		}

		// --- encrypt response ---
		if resp := c.Response().Body(); len(resp) > 0 {
			enc, encErr := encrypt(key, resp)
			if encErr != nil {
				return fiber.ErrInternalServerError
			}
			c.Response().SetBody(enc)
			c.Response().Header.SetContentType(fiber.MIMEOctetStream)
		}

		return err
	}
}
