package response

import "github.com/Eanhain/gophkeeper/internal/entity"

// LoginPassword represents a stored login-password pair in API responses.
type LoginPassword struct {
	Login    string `json:"login" example:"admin@example.com"`
	Password string `json:"password" example:"myP@ssw0rd"`
	Label    string `json:"label" example:"work email"`
}

// TextSecret represents a stored text note in API responses.
type TextSecret struct {
	Title string `json:"title" example:"API key"`
	Body  string `json:"body" example:"sk-proj-abc123..."`
}

// BinarySecret represents a stored binary file in API responses.
type BinarySecret struct {
	Filename string `json:"filename" example:"certificate.pem"`
	MimeType string `json:"mime_type" example:"application/x-pem-file"`
	Data     string `json:"data" example:"LS0tLS1CRUdJTi..."`
}

// CardSecret represents a stored bank card in API responses.
type CardSecret struct {
	Cardholder string `json:"cardholder" example:"John Doe"`
	Pan        string `json:"pan" example:"4111111111111111"`
	ExpMonth   string `json:"exp_month" example:"12"`
	ExpYear    string `json:"exp_year" example:"2027"`
	Brand      string `json:"brand" example:"Visa"`
	Last4      string `json:"last4" example:"1111"`
}

// AllSecrets contains all secret types for a user.
type AllSecrets struct {
	LoginPassword []LoginPassword `json:"login_password"`
	TextSecret    []TextSecret    `json:"text_secret"`
	BinarySecret  []BinarySecret  `json:"binary_secret"`
	CardSecret    []CardSecret    `json:"card_secret"`
}

func FromLoginPassword(value entity.LoginPassword) LoginPassword {
	return LoginPassword{
		Login:    value.Login,
		Password: value.Password,
		Label:    value.Label,
	}
}

func FromTextSecret(value entity.TextSecret) TextSecret {
	return TextSecret{
		Title: value.Title,
		Body:  value.Body,
	}
}

func FromBinarySecret(value entity.BinarySecret) BinarySecret {
	return BinarySecret{
		Filename: value.Filename,
		MimeType: value.MimeType,
		Data:     value.Data,
	}
}

func FromCardSecret(value entity.CardSecret) CardSecret {
	return CardSecret{
		Cardholder: value.Cardholder,
		Pan:        value.Pan,
		ExpMonth:   value.ExpMonth,
		ExpYear:    value.ExpYear,
		Brand:      value.Brand,
		Last4:      value.Last4,
	}
}

func FromLoginPasswords(values []entity.LoginPassword) []LoginPassword {
	result := make([]LoginPassword, 0, len(values))
	for _, value := range values {
		result = append(result, FromLoginPassword(value))
	}
	return result
}

func FromTextSecrets(values []entity.TextSecret) []TextSecret {
	result := make([]TextSecret, 0, len(values))
	for _, value := range values {
		result = append(result, FromTextSecret(value))
	}
	return result
}

func FromBinarySecrets(values []entity.BinarySecret) []BinarySecret {
	result := make([]BinarySecret, 0, len(values))
	for _, value := range values {
		result = append(result, FromBinarySecret(value))
	}
	return result
}

func FromCardSecrets(values []entity.CardSecret) []CardSecret {
	result := make([]CardSecret, 0, len(values))
	for _, value := range values {
		result = append(result, FromCardSecret(value))
	}
	return result
}

func FromAllSecrets(values entity.AllSecrets) AllSecrets {
	return AllSecrets{
		LoginPassword: FromLoginPasswords(values.LoginPassword),
		TextSecret:    FromTextSecrets(values.TextSecret),
		BinarySecret:  FromBinarySecrets(values.BinarySecret),
		CardSecret:    FromCardSecrets(values.CardSecret),
	}
}
