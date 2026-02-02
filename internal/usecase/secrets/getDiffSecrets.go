package secrets

import "github.com/Eanhain/gophkeeper/internal/usecase"

func (s *UseCase) GetUserLoginPasswordsUseCase() usecase.LoginPasswordUseCase {
	return s.repo.LoginPasswordUseCase
}
