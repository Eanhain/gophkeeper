package response

import (
	"testing"

	"github.com/Eanhain/gophkeeper/internal/entity"
)

func TestFromLoginPassword(t *testing.T) {
	lp := entity.LoginPassword{Login: "user", Password: "pass", Label: "work"}
	r := FromLoginPassword(lp)
	if r.Login != "user" || r.Password != "pass" || r.Label != "work" {
		t.Fatal("mismatch")
	}
}

func TestFromTextSecret(t *testing.T) {
	ts := entity.TextSecret{Title: "note", Body: "hello"}
	r := FromTextSecret(ts)
	if r.Title != "note" || r.Body != "hello" {
		t.Fatal("mismatch")
	}
}

func TestFromBinarySecret(t *testing.T) {
	bs := entity.BinarySecret{Filename: "f.bin", MimeType: "app/oct", Data: "data"}
	r := FromBinarySecret(bs)
	if r.Filename != "f.bin" || r.MimeType != "app/oct" || r.Data != "data" {
		t.Fatal("mismatch")
	}
}

func TestFromCardSecret(t *testing.T) {
	cs := entity.CardSecret{Cardholder: "John", Pan: "4111", ExpMonth: "12", ExpYear: "2025", Brand: "Visa", Last4: "1111"}
	r := FromCardSecret(cs)
	if r.Cardholder != "John" || r.Pan != "4111" || r.ExpMonth != "12" || r.ExpYear != "2025" || r.Brand != "Visa" || r.Last4 != "1111" {
		t.Fatal("mismatch")
	}
}

func TestFromLoginPasswords(t *testing.T) {
	input := []entity.LoginPassword{{Login: "a"}, {Login: "b"}}
	result := FromLoginPasswords(input)
	if len(result) != 2 || result[0].Login != "a" || result[1].Login != "b" {
		t.Fatal("mismatch")
	}
}

func TestFromTextSecrets(t *testing.T) {
	input := []entity.TextSecret{{Title: "a"}, {Title: "b"}}
	result := FromTextSecrets(input)
	if len(result) != 2 {
		t.Fatal("mismatch")
	}
}

func TestFromBinarySecrets(t *testing.T) {
	input := []entity.BinarySecret{{Filename: "a"}, {Filename: "b"}}
	result := FromBinarySecrets(input)
	if len(result) != 2 {
		t.Fatal("mismatch")
	}
}

func TestFromCardSecrets(t *testing.T) {
	input := []entity.CardSecret{{Cardholder: "a"}, {Cardholder: "b"}}
	result := FromCardSecrets(input)
	if len(result) != 2 {
		t.Fatal("mismatch")
	}
}

func TestFromAllSecrets(t *testing.T) {
	input := entity.AllSecrets{
		LoginPassword: []entity.LoginPassword{{Login: "a"}},
		TextSecret:    []entity.TextSecret{{Title: "t"}},
		BinarySecret:  []entity.BinarySecret{{Filename: "f"}},
		CardSecret:    []entity.CardSecret{{Cardholder: "c"}},
	}
	result := FromAllSecrets(input)
	if len(result.LoginPassword) != 1 || len(result.TextSecret) != 1 ||
		len(result.BinarySecret) != 1 || len(result.CardSecret) != 1 {
		t.Fatal("mismatch")
	}
}

func TestFromLoginPasswordsEmpty(t *testing.T) {
	result := FromLoginPasswords(nil)
	if len(result) != 0 {
		t.Fatal("expected empty")
	}
}

func TestFromAllSecretsEmpty(t *testing.T) {
	result := FromAllSecrets(entity.AllSecrets{})
	if len(result.LoginPassword) != 0 || len(result.TextSecret) != 0 {
		t.Fatal("expected empty")
	}
}
