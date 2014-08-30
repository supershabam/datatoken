package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/supershabam/datatoken"
)

func main() {
	dt1 := datatoken.Base64Datatoken{
		Encoding: base64.URLEncoding,
		Hash:     sha256.New,
		Key:      []byte("12345"),
		Value:    []byte("sekret"),
	}
	token, err := dt1.MarshalText()
	if err != nil {
		panic(err)
	}

	fmt.Printf("token: %s\n", token)

	dt2 := datatoken.Base64Datatoken{
		Encoding: base64.URLEncoding,
		Hash:     sha256.New,
		Key:      []byte("12345"),
	}
	err = dt2.UnmarshalText(token)
	if err != nil {
		panic(err)
	}

	fmt.Printf("value: %s\n", dt2.Value)
}
