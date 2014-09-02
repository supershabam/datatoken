package datatoken

import (
	"encoding/base64"
	"hash"
)

type Base64 struct {
	Encoding *base64.Encoding
	Hash     func() hash.Hash
	Key      []byte
}

func (b Base64) Tokenize(in []byte) ([]byte, error) {
	return []byte{}, nil
}

func (b Base64) Detokenize(in []byte) ([]byte, error) {
	return []byte{}, nil
}

func (b Base64) DetokenizeUnverified(in []byte) ([]byte, error) {
	return []byte{}, nil
}
