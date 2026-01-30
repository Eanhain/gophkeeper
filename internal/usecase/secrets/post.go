package secrets

import (
	"context"

	"github.com/Eanhain/gophkeeper/internal/controller/restapi/v1/request"
	"github.com/Eanhain/gophkeeper/internal/entity"
)

func (s *SecretsUseCase) PostLoginPassword(ctx context.Context, loginPassword request.LoginPassword) error {
	userID, err := s.repo.GetUserID(ctx, loginPassword.Login)
	if err != nil {
		return err
	}
	return s.repo.PostLoginPassword(ctx, entity.LoginPassword{
		UserID:   userID,
		Login:    loginPassword.Login,
		Password: loginPassword.Password,
		Label:    loginPassword.Label,
	})
}
