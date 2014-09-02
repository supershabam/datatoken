package datatoken

import (
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strings"
)

// ErrMalformedToken is returned if the token cannot be decoded
var ErrMalformedToken = errors.New("malformed token")

// Base64 is a Tokenizer that uses base64 encoding to create the token
type Base64 struct {
	Encoding *base64.Encoding
	Hash     func() hash.Hash
	Key      []byte
}

// Tokenize writes the in bytes into a Base64 datatoken that can then be Detokenized
// to retreive the original bytes. The signature is computed on the Base64 encoded
// payload so that detokenizing can validate the signature before starting the
// Base64 decoding process.
func (b Base64) Tokenize(in []byte) ([]byte, error) {
	b64in := b.Encoding.EncodeToString(in)
	mac := hmac.New(b.Hash, b.Key)
	mac.Write([]byte(b64in))
	b64sig := b.Encoding.EncodeToString(mac.Sum(nil))
	return []byte(fmt.Sprintf("%s.%s", b64in, b64sig)), nil
}

// Detokenize reads the in bytes, verifies that the signature matches the payload,
// and then returns the base64 decoded payload. If the signature doesn't match,
// the error will be non-nil
func (b Base64) Detokenize(in []byte) ([]byte, error) {
	parts := strings.Split(string(in), ".")
	if len(parts) != 2 {
		return []byte{}, ErrMalformedToken
	}

	b64payload := parts[0]
	b64sig := parts[1]

	mac := hmac.New(b.Hash, b.Key)
	mac.Write([]byte(b64payload))
	computedSig := mac.Sum(nil)

	sig, err := b.Encoding.DecodeString(b64sig)
	if err != nil {
		return []byte{}, err
	}

	if !hmac.Equal(computedSig, sig) {
		return []byte{}, ErrInvalidSignature
	}

	return b.Encoding.DecodeString(b64payload)
}

// DetokenizeUnverified reads the token and returns the base64 decoded payload
// without verifying the key.
func (b Base64) DetokenizeUnverified(in []byte) ([]byte, error) {
	parts := strings.Split(string(in), ".")
	if len(parts) != 2 {
		return []byte{}, ErrMalformedToken
	}

	b64payload := parts[0]

	return b.Encoding.DecodeString(b64payload)
}
