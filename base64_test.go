package datatoken

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
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

func ExampleBase64() {
	message := []byte(`{"arbitrary":"message"}`)

	// serverTokenizer knows the hash and key functions
	serverTokenizer := Base64{
		Encoding: base64.URLEncoding,
		Hash:     sha256.New,
		Key:      []byte("sekret"),
	}

	token, err := serverTokenizer.Tokenize(message)
	if err != nil {
		panic(err)
	}

	// send token to client, which can read the payload
	clientTokenizer := Base64{
		Encoding: base64.URLEncoding,
	}
	parsedMessage, err := clientTokenizer.DetokenizeUnverified(token)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(parsedMessage, message) {
		panic(fmt.Errorf("parsedMessage doesn't equal original message"))
	}

	// serverTokenizer can read token and verify that signature is valid
	parsedMessage, err := serverTokenizer.Detokenize(token)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(parsedMessage, message) {
		panic(fmt.Errorf("parsedMessage doesn't equal original message"))
	}
}
