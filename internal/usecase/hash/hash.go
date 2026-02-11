// Package hash provides password hashing and verification helpers
// built on top of the argon2id algorithm, plus encryption key derivation.
//
// argon2id is the recommended password-hashing function (RFC 9106).
// Default parameters from the alexedwards/argon2id library are used:
// memory=64 MB, iterations=1, parallelism=2, salt=16 bytes, key=32 bytes.
//
// For per-user data encryption, a separate key is derived from the user's
// password and a random per-user salt using Argon2id via pkg/crypto.
package hash

import (
	"github.com/Eanhain/gophkeeper/domain"
	"github.com/Eanhain/gophkeeper/internal/entity"
	"github.com/Eanhain/gophkeeper/pkg/crypto"
	"github.com/alexedwards/argon2id"
)

// CreateUserHash hashes the user's plaintext password and generates a
// random crypto salt. Returns an entity.User ready for database insertion.
// If hashing fails, an empty User is returned and the error is logged.
func CreateUserHash(log domain.LoggerI, user entity.UserInput) entity.User {
	hash, err := argon2id.CreateHash(user.Password, argon2id.DefaultParams)
	if err != nil {
		log.Warn("Cannot create hash %s, %v", user.Login, err)
		return entity.User{}
	}
	salt, err := crypto.GenerateSalt()
	if err != nil {
		log.Warn("Cannot generate crypto salt %s, %v", user.Login, err)
		return entity.User{}
	}
	return entity.User{Login: user.Login, Hash: hash, CryptoSalt: salt}
}

// VerifyUserHash compares the plaintext password from user with the
// stored argon2id hash in tUser. Returns true when they match.
func VerifyUserHash(log domain.LoggerI, user entity.UserInput, tUser entity.User) bool {
	match, err := argon2id.ComparePasswordAndHash(user.Password, tUser.Hash)
	if err != nil {
		log.Warn("Cannot verify hash", user.Login, err)
	}
	log.Info("User %s match: %t", user.Login, match)
	return match
}

// DeriveEncryptionKey derives a per-user AES-256 encryption key from the
// user's password and their stored crypto salt using Argon2id.
// The returned hex string can be passed to pkg/crypto.Encrypt/Decrypt.
func DeriveEncryptionKey(password string, salt []byte) string {
	return crypto.DeriveKey(password, salt)
}
