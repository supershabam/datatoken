// Package datatoken is an interface for creating signed tokens that can be verified by
// the keyholder, but the payload is parsable and readable by non-key holding
// consumers of the token.
//
// This is similar to signed cookies.
//
// You can read more on how to use such a token here:
// http://lucumr.pocoo.org/2013/11/17/my-favorite-database/
package datatoken

import "errors"

// A Tokenizer can be given some arbitrary bytes to tokenize which can then be
// Detokenized and DetokenizeUnverified to retreive the original bytes.
type Tokenizer interface {
	Tokenize([]byte) ([]byte, error)
	Detokenize([]byte) ([]byte, error)
	DetokenizeUnverified([]byte) ([]byte, error)
}

// ErrInvalidSignature is returned if the token being detokenized has a bad
// signature
var ErrInvalidSignature = errors.New("invalid signature")
