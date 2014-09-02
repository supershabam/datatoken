package datatoken

import "errors"

type Tokenizer interface {
	Tokenize([]byte) ([]byte, error)
	Detokenize([]byte) ([]byte, error)
	DetokenizeUnverified([]byte) ([]byte, error)
}

var ErrInvalidSignature = errors.New("invalid signature")
