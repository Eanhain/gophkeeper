package hash

import (
	"github.com/Eanhain/gophkeeper/domain"
	"github.com/Eanhain/gophkeeper/internal/entity"
	"github.com/alexedwards/argon2id"
)

func CreateUserHash(log domain.LoggerI, user entity.UserInput) entity.User {
	hash, err := argon2id.CreateHash(user.Password, argon2id.DefaultParams)
	if err != nil {
		log.Warn("Cannot create hash %s, %v", user.Login, err)
		return entity.User{}
	}
	return entity.User{Login: user.Login, Hash: hash}
}

func VerifyUserHash(log domain.LoggerI, user entity.UserInput, tUser entity.User) bool {
	match, err := argon2id.ComparePasswordAndHash(user.Password, tUser.Hash)
	if err != nil {
		log.Warn("Cannot verify hash", user.Login, err)
	}
	log.Info("User %s match: %t", user.Login, match)
	return match
}
