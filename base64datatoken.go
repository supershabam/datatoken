package datatoken

import (
	"crypto/hmac"
	"encoding/base64"
	"fmt"
	"hash"
	"strings"
)

// Base64Datatoken creates a signature verified token that you can give to clients
// to read the data but can't modify
type Base64Datatoken struct {
	Encoding *base64.Encoding
	Hash     func() hash.Hash
	Key      []byte
	Value    []byte
}

// MarshalText creates a token
// {base64Encoded(value)}.{base64Encoded(signature(base64Encoded(value)))}
// we sign the base64 encoded value so that on the decoding end we can verify
// the signature before even attempting to start base64 decoding
func (d Base64Datatoken) MarshalText() ([]byte, error) {
	base64payload := d.Encoding.EncodeToString(d.Value)

	mac := hmac.New(d.Hash, d.Key)
	mac.Write([]byte(base64payload))
	base64signature := d.Encoding.EncodeToString(mac.Sum(nil))

	return []byte(fmt.Sprintf("%s.%s", base64payload, base64signature)), nil
}

// UnmarshalText reads a marshalled datatoken and returns an error
// if the signature is invalid or unmarshalling was unsuccessful (bad base64)
func (d *Base64Datatoken) UnmarshalText(text []byte) error {
	parts := strings.Split(fmt.Sprintf("%s", text), ".")
	if len(parts) != 2 {
		return fmt.Errorf("expected text to have exactly one .")
	}

	base64payload := parts[0]
	base64signature := parts[1]

	mac := hmac.New(d.Hash, d.Key)
	mac.Write([]byte(base64payload))
	computedSignature := mac.Sum(nil)

	signature, err := d.Encoding.DecodeString(base64signature)
	if err != nil {
		return err
	}

	if !hmac.Equal(computedSignature, signature) {
		return fmt.Errorf("signature is invalid")
	}

	value, err := d.Encoding.DecodeString(base64payload)
	if err != nil {
		return err
	}
	d.Value = value
	return nil
}
