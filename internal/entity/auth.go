// Package entity defines core domain models that are shared between
// the repository, usecase, and controller layers.
// Each logical group of entities lives in its own file.
package entity

// User represents a registered user record stored in the database.
// Hash contains the argon2id-hashed password — the plaintext password
// is never persisted. CryptoSalt is used with Argon2 to derive a
// per-user encryption key from the user's password.
type User struct {
	Login      string `json:"login" db:"username"`
	Hash       string `json:"hash" db:"password_hash"`
	CryptoSalt []byte `json:"-" db:"crypto_salt"`
}

// UserInput is the raw credentials submitted by the client
// during login or registration. The Password field is plaintext
// and must be hashed before storage.
type UserInput struct {
	Login    string `json:"login" db:"login"`
	Password string `json:"password" db:"password"`
}
