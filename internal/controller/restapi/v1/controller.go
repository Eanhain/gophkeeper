package v1

import (
	"github.com/Eanhain/gophkeeper/domain"
	"github.com/Eanhain/gophkeeper/internal/usecase"
	"github.com/go-playground/validator/v10"
	jwtware "github.com/gofiber/contrib/jwt"
)

// V1 -.
type V1 struct {
	t       usecase.AuthUseCase
	l       domain.LoggerI
	v       *validator.Validate
	jwtConf jwtware.Config
}
