package datatoken

type Tokenizer interface {
	Tokenize([]byte) ([]byte, error)
	Detokenize([]byte) ([]byte, error)
	DetokenizeUnverified([]byte) ([]byte, error)
}

type ErrInvalidSignature struct {
	error
}
