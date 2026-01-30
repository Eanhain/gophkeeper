package secrets

import (
	"context"

	"github.com/Eanhain/gophkeeper/internal/controller/restapi/v1/request"

	"github.com/Eanhain/gophkeeper/internal/entity"
)

func (s *SecretsUseCase) PostLoginPassword(ctx context.Context, username string, loginPassword request.LoginPassword) error {
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return err
	}
	return s.repo.CreateLoginPassword(ctx, entity.LoginPassword{
		UserID:   userID,
		Login:    loginPassword.Login,
		Password: loginPassword.Password,
		Label:    loginPassword.Label,
	})
}

func (s *SecretsUseCase) PostTextSecret(ctx context.Context, username string, textSecret request.TextSecret) error {
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return err
	}
	return s.repo.CreateTextSecret(ctx, entity.TextSecret{
		UserID: userID,
		Title:  textSecret.Title,
		Body:   textSecret.Body,
	})
}

func (s *SecretsUseCase) PostBinarySecret(ctx context.Context, username string, binarySecret request.BinarySecret) error {
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return err
	}
	return s.repo.CreateBinarySecret(ctx, entity.BinarySecret{
		UserID:   userID,
		Filename: binarySecret.Filename,
		MimeType: binarySecret.MimeType,
		Data:     binarySecret.Data,
	})
}

func (s *SecretsUseCase) PostCardSecret(ctx context.Context, username string, cardSecret request.CardSecret) error {
	userID, err := s.repo.GetUserID(ctx, username)
	if err != nil {
		return err
	}
	return s.repo.CreateCardSecret(ctx, entity.CardSecret{
		UserID:     userID,
		Cardholder: cardSecret.Cardholder,
		Pan:        cardSecret.Pan,
		ExpMonth:   cardSecret.ExpMonth,
		ExpYear:    cardSecret.ExpYear,
		Brand:      cardSecret.Brand,
		Last4:      cardSecret.Last4,
	})
}
