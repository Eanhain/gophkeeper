package domain

import (
	"errors"
)

var (
	ErrUserExist              = errors.New("user exists")
	ErrOrderExist             = errors.New("user already create order")
	ErrOrderExistWrongUser    = errors.New("order create for another user")
	ErrJWTToken               = errors.New("can't create jwt token")
	ErrAuthUser               = errors.New("can't auth user")
	ErrConflict               = errors.New("data conflict")
	ErrOrderInvalid           = errors.New("order is not valid")
	ErrGetAccrualOrders       = errors.New("can't get accrual orders")
	ErrUnmarshalAccrualOrders = errors.New("can't get unmarshal accrual orders to json")
	ErrBalanceWithdrawn       = errors.New("not enough bonuses on balance")
	ErrRequestCount           = errors.New("no more than N requests per minute allowed on accural service, try later")
	ErrEmptyOrdersList        = errors.New("order list is empty")
)
