package datatoken

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestBase64(t *testing.T) {
	key := []byte("sekret key! shhh do not share")
	message := []byte("oh hai")

	tokenizer := Base64{
		Encoding: base64.URLEncoding,
		Hash:     sha256.New,
		Key:      key,
	}

	// should write token
	token, err := tokenizer.Tokenize(message)
	if err != nil {
		t.Error(err)
	}

	// token should have exactly one "." in it
	if strings.Count(string(token), ".") != 1 {
		t.Errorf("expected exactly 1 . not %d", strings.Count(string(token), "."))
	}

	// should be able to read message back into original message
	m, err := tokenizer.DetokenizeUnverified(token)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(m, message) {
		t.Errorf("expected m to be %s not %s", message, m)
	}

	// should be able to verify signature while reading back original message
	m, err = tokenizer.Detokenize(token)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(m, message) {
		t.Errorf("expected m to be %s not %s", message, m)
	}

	// should get an error if reading back with bad key
	badtokenizer := Base64{
		Encoding: base64.URLEncoding,
		Hash:     sha256.New,
		Key:      []byte("wrong key"),
	}
	_, err = badtokenizer.Detokenize(token)
	if err != ErrInvalidSignature {
		t.Errorf("expected invalid signature error, not %s", err)
	}

	// should still be able to read unverified content with bad key
	m, err = badtokenizer.DetokenizeUnverified(token)
	if err != nil {
		t.Errorf("expected no error, but received: %s", err)
	}
	if !bytes.Equal(m, message) {
		t.Errorf("expected m to be %s not %s", message, m)
	}
}
