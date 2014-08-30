datatoken
=========

A datatoken is a signed piece of data readable by the client and server, but cannot be modified without invalidating the token. It's like a signed cookie. This is just an interface wrapping that idea.

Base64Datatoken
---------------

The Base64Datatoken writes `[]byte` as `{base64Encode(input)}.{signature(base64Encode(input)}`

This lets you share Base64 encoded information with a client without allowing them to alter the information.

```golang
dt := datatoken.Base64Datatoken{
		Encoding: base64.URLEncoding,
		Hash:     sha256.New,
		Key:      []byte("sekret"),
		Value:    []byte("message"),
	}
	token, err := dt1.MarshalText()
	
	// token is "bWVzc2FnZQ==.lGm_Ymsc9Q0JzhHurDKNDDhwRD0aU_MxG-uQvqW-t5M="
	// base64 encoded "message" is "bWVzc2FnZQ==" (you can verify this)
	// so the client can see what the payload is, but they can't change it without invalidating the signature
```

This helps me write tokens I can share with the client that authenticate them AND allow me to share data with them.

[my favorite database is the network](http://lucumr.pocoo.org/2013/11/17/my-favorite-database/)
