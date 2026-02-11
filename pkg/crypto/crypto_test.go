package crypto_test

import (
	"testing"

	"github.com/Eanhain/gophkeeper/pkg/crypto"
)

func TestGenerateSalt(t *testing.T) {
	salt, err := crypto.GenerateSalt()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(salt) != crypto.SaltLen {
		t.Fatalf("expected salt length %d, got %d", crypto.SaltLen, len(salt))
	}

	// Two salts should be different.
	salt2, _ := crypto.GenerateSalt()
	if string(salt) == string(salt2) {
		t.Fatal("expected different salts")
	}
}

func TestDeriveKey(t *testing.T) {
	salt := []byte("1234567890123456")
	key := crypto.DeriveKey("password", salt)
	if len(key) != 64 { // 32 bytes hex-encoded = 64 chars
		t.Fatalf("expected key length 64, got %d", len(key))
	}

	// Same password + salt produces the same key.
	key2 := crypto.DeriveKey("password", salt)
	if key != key2 {
		t.Fatal("expected deterministic key derivation")
	}

	// Different password produces a different key.
	key3 := crypto.DeriveKey("different", salt)
	if key == key3 {
		t.Fatal("expected different key for different password")
	}

	// Different salt produces a different key.
	salt2 := []byte("6543210987654321")
	key4 := crypto.DeriveKey("password", salt2)
	if key == key4 {
		t.Fatal("expected different key for different salt")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	salt := []byte("1234567890123456")
	hexKey := crypto.DeriveKey("testpassword", salt)

	plaintext := []byte("hello world, this is a secret message")
	ciphertext, err := crypto.Encrypt(hexKey, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if string(ciphertext) == string(plaintext) {
		t.Fatal("ciphertext should differ from plaintext")
	}

	decrypted, err := crypto.Decrypt(hexKey, ciphertext)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("expected %q, got %q", plaintext, decrypted)
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	salt := []byte("1234567890123456")
	key1 := crypto.DeriveKey("password1", salt)
	key2 := crypto.DeriveKey("password2", salt)

	ciphertext, _ := crypto.Encrypt(key1, []byte("secret"))

	_, err := crypto.Decrypt(key2, ciphertext)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong key")
	}
}

func TestDecrypt_TooShort(t *testing.T) {
	salt := []byte("1234567890123456")
	hexKey := crypto.DeriveKey("password", salt)

	_, err := crypto.Decrypt(hexKey, []byte("short"))
	if err == nil {
		t.Fatal("expected error for too-short ciphertext")
	}
}

func TestEncryptDecryptString(t *testing.T) {
	salt := []byte("1234567890123456")
	hexKey := crypto.DeriveKey("testpassword", salt)

	original := "sensitive data 日本語"
	ciphertext, err := crypto.EncryptString(hexKey, original)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	decrypted, err := crypto.DecryptString(hexKey, ciphertext)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if decrypted != original {
		t.Fatalf("expected %q, got %q", original, decrypted)
	}
}

func TestEncrypt_EmptyPlaintext(t *testing.T) {
	salt := []byte("1234567890123456")
	hexKey := crypto.DeriveKey("password", salt)

	ciphertext, err := crypto.Encrypt(hexKey, []byte{})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	decrypted, err := crypto.Decrypt(hexKey, ciphertext)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if len(decrypted) != 0 {
		t.Fatalf("expected empty decrypted, got %q", decrypted)
	}
}
