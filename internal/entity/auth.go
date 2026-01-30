// Package entity defines main entities for business logic (services), data base mapping and
// HTTP response objects if suitable. Each logic group entities in own file.
package entity

// Аутентификация пользователя (прием на сервер)
// POST /api/user/login.
type UserInput struct {
	Login    string `json:"login" db:"login"`
	Password string `json:"password" db:"password"`
}

type User struct {
	Login string `json:"login" db:"username"`
	Hash  string `json:"hash" db:"hash"`
}
