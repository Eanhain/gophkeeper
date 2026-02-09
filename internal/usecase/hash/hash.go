// Package hash provides password hashing and verification helpers
// built on top of the argon2id algorithm.
//
// argon2id is the recommended password-hashing function (RFC 9106).
// Default parameters from the alexedwards/argon2id library are used:
// memory=64 MB, iterations=1, parallelism=2, salt=16 bytes, key=32 bytes.
package hash

import (
	"github.com/Eanhain/gophkeeper/domain"
	"github.com/Eanhain/gophkeeper/internal/entity"
	"github.com/alexedwards/argon2id"
)

// CreateUserHash hashes the user's plaintext password and returns an
// entity.User ready for database insertion. If hashing fails, an empty
// User is returned and the error is logged at WARN level.
func CreateUserHash(log domain.LoggerI, user entity.UserInput) entity.User {
	hash, err := argon2id.CreateHash(user.Password, argon2id.DefaultParams)
	if err != nil {
		log.Warn("Cannot create hash %s, %v", user.Login, err)
		return entity.User{}
	}
	return entity.User{Login: user.Login, Hash: hash}
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
