package request

// UserInput represents user authentication credentials.
type UserInput struct {
	Login    string `json:"login" example:"john_doe"`
	Password string `json:"password" example:"s3cureP@ss"`
}

// LoginPassword represents a stored login-password pair.
type LoginPassword struct {
	Login    string `json:"login" example:"admin@example.com"`
	Password string `json:"password" example:"myP@ssw0rd"`
	Label    string `json:"label" example:"work email"`
}

// TextSecret represents a stored text note.
type TextSecret struct {
	Title string `json:"title" example:"API key"`
	Body  string `json:"body" example:"sk-proj-abc123..."`
}

// BinarySecret represents a stored binary file (base64-encoded).
type BinarySecret struct {
	Filename string `json:"filename" example:"certificate.pem"`
	MimeType string `json:"mime_type" example:"application/x-pem-file"`
	Data     string `json:"data" example:"LS0tLS1CRUdJTi..."`
}

// CardSecret represents a stored bank card.
type CardSecret struct {
	Cardholder string `json:"cardholder" example:"John Doe"`
	Pan        string `json:"pan" example:"4111111111111111"`
	ExpMonth   string `json:"exp_month" example:"12"`
	ExpYear    string `json:"exp_year" example:"2027"`
	Brand      string `json:"brand" example:"Visa"`
	Last4      string `json:"last4" example:"1111"`
}

// Secret is a combined object for multi-type requests.
type Secret struct {
	Login  LoginPassword `json:"login"`
	Text   TextSecret    `json:"text"`
	Binary BinarySecret  `json:"binary"`
	Card   CardSecret    `json:"card"`
}

// DeleteLoginPassword identifies a login-password to delete.
type DeleteLoginPassword struct {
	Login string `json:"login" example:"admin@example.com"`
}

// DeleteTextSecret identifies a text secret to delete.
type DeleteTextSecret struct {
	Title string `json:"title" example:"API key"`
}

// DeleteBinarySecret identifies a binary secret to delete.
type DeleteBinarySecret struct {
	Filename string `json:"filename" example:"certificate.pem"`
}

// DeleteCardSecret identifies a card secret to delete.
type DeleteCardSecret struct {
	Cardholder string `json:"cardholder" example:"John Doe"`
}

// GetLoginPassword query for filtering login-passwords.
type GetLoginPassword struct {
	Login string `json:"login"`
}

// GetTextSecret query for filtering text secrets.
type GetTextSecret struct {
	Title string `json:"title"`
}

// GetBinarySecret query for filtering binary secrets.
type GetBinarySecret struct {
	Filename string `json:"filename"`
}

// GetCardSecret query for filtering card secrets.
type GetCardSecret struct {
	Cardholder string `json:"cardholder"`
}
