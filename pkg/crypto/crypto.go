// Package crypto provides per-user encryption helpers.
//
// Key derivation uses Argon2id (RFC 9106) to produce a 32-byte AES-256 key
// from the user's plaintext password and a random per-user salt.
//
// Encryption uses AES-256-GCM. Ciphertext format: 12-byte nonce || GCM-sealed data.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// Argon2 parameters (recommended by RFC 9106 for interactive logins).
const (
	argonTime    = 1
	argonMemory  = 64 * 1024 // 64 MB
	argonThreads = 4
	argonKeyLen  = 32 // AES-256
	SaltLen      = 16
)

// GenerateSalt returns a cryptographically random salt of SaltLen bytes.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return salt, nil
}

// DeriveKey derives a 32-byte AES-256 key from a password and per-user salt
// using Argon2id. The result is returned as a hex-encoded string suitable
// for storage in JWT claims or passing to Encrypt/Decrypt.
func DeriveKey(password string, salt []byte) string {
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return hex.EncodeToString(key)
}

// Encrypt encrypts plaintext using AES-256-GCM.
// hexKey must be a 64-character hex string (32 bytes).
// Returns nonce || ciphertext.
func Encrypt(hexKey string, plaintext []byte) ([]byte, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("rand nonce: %w", err)
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt reverses Encrypt. It expects nonce || ciphertext.
// hexKey must be a 64-character hex string (32 bytes).
func Decrypt(hexKey string, ciphertext []byte) ([]byte, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}

	ns := gcm.NonceSize()
	if len(ciphertext) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}

	return gcm.Open(nil, ciphertext[:ns], ciphertext[ns:], nil)
}

// EncryptString is a convenience wrapper: encrypts a UTF-8 string
// and returns the raw bytes.
func EncryptString(hexKey, plaintext string) ([]byte, error) {
	return Encrypt(hexKey, []byte(plaintext))
}

// DecryptString decrypts raw bytes and returns the plaintext as a string.
func DecryptString(hexKey string, ciphertext []byte) (string, error) {
	plain, err := Decrypt(hexKey, ciphertext)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
