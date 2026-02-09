package middleware

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"github.com/gofiber/fiber/v2"
)

func deriveKey(passphrase string) []byte {
	h := sha256.Sum256([]byte(passphrase))
	return h[:]
}

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

func CryptoMiddleware(cryptoKey string) fiber.Handler {
	key := deriveKey(cryptoKey)

	return func(c *fiber.Ctx) error {
		if len(c.Body()) > 0 {
			plain, err := decrypt(key, c.Body())
			if err != nil {
				return fiber.ErrBadRequest
			}
			c.Request().SetBody(plain)
			c.Request().Header.SetContentType(fiber.MIMEApplicationJSON)
		}

		err := c.Next()

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
