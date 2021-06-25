package jwt

import "github.com/lestrrat-go/jwx/jwa"

type SignatureAlgorithm string

const (
	RS256 = SignatureAlgorithm(jwa.RS256)
	HS256 = SignatureAlgorithm(jwa.HS256)
)
