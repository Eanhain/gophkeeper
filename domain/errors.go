// Package domain contains shared types, interfaces and sentinel errors
// used across all layers of the application (usecase, repo, controller).
package domain

import (
	"errors"
)

// Sentinel errors returned by the repository and usecase layers.
// Handlers map these to appropriate HTTP status codes.
var (
	// ErrUserExist indicates that a user with the given login already exists.
	ErrUserExist = errors.New("user exists")
	// ErrOrderExist indicates that the order was already created by this user.
	ErrOrderExist = errors.New("user already create order")
	// ErrOrderExistWrongUser indicates the order belongs to a different user.
	ErrOrderExistWrongUser = errors.New("order create for another user")
	// ErrJWTToken indicates a failure while creating a JWT token.
	ErrJWTToken = errors.New("can't create jwt token")
	// ErrAuthUser indicates that the user could not be authenticated.
	ErrAuthUser = errors.New("can't auth user")
	// ErrConflict indicates a data integrity conflict (e.g. duplicate username on registration).
	ErrConflict = errors.New("data conflict")
	// ErrOrderInvalid indicates the order number is not valid.
	ErrOrderInvalid = errors.New("order is not valid")
	// ErrGetAccrualOrders indicates a failure fetching accrual orders.
	ErrGetAccrualOrders = errors.New("can't get accrual orders")
	// ErrUnmarshalAccrualOrders indicates a failure unmarshalling accrual data.
	ErrUnmarshalAccrualOrders = errors.New("can't get unmarshal accrual orders to json")
	// ErrBalanceWithdrawn indicates insufficient balance for withdrawal.
	ErrBalanceWithdrawn = errors.New("not enough bonuses on balance")
	// ErrRequestCount indicates rate-limiting on the accrual service.
	ErrRequestCount = errors.New("no more than N requests per minute allowed on accural service, try later")
	// ErrEmptyOrdersList indicates that the user has no orders.
	ErrEmptyOrdersList = errors.New("order list is empty")

	// ErrNotFound indicates that the requested resource was not found.
	// Mapped to HTTP 404 by the handler layer.
	ErrNotFound = errors.New("not found")
	// ErrAlreadyExists indicates that a resource with the same identifier already exists.
	// Mapped to HTTP 409 by the handler layer.
	ErrAlreadyExists = errors.New("already exists")
	// ErrInvalidInput indicates that the request contains missing or invalid fields.
	// Mapped to HTTP 400 by the handler layer.
	ErrInvalidInput = errors.New("invalid input")
)
