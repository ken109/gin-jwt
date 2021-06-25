package jwt

import (
	"crypto/rsa"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

type Claims map[string]interface{}

type Option struct {
	Realm string

	SigningAlgorithm SignatureAlgorithm

	SecretKey []byte

	PrivKeyFile  string
	PrivKeyBytes []byte
	privKey      *rsa.PrivateKey

	Timeout time.Duration

	Issuer  string
	Subject string
}

var options = make(map[string]Option)

func IssueToken(realm string, claims Claims) ([]byte, error) {
	var err error

	option, ok := options[realm]
	if !ok {
		return nil, errors.New("it is an unknown realm. please use the set up")
	}

	t := jwt.New()

	_ = t.Set(jwt.IssuedAtKey, time.Now().Unix())
	_ = t.Set(jwt.IssuerKey, option.Issuer)
	_ = t.Set(jwt.SubjectKey, option.Subject)
	_ = t.Set(jwt.ExpirationKey, time.Now().Add(option.Timeout).Unix())

	for k, v := range claims {
		err = t.Set(k, v)
		if err != nil {
			return nil, err
		}
	}

	var realKey jwk.Key
	if option.SigningAlgorithm == RS256 {
		realKey, err = jwk.New(option.privKey)
	} else if option.SigningAlgorithm == HS256 {
		realKey, err = jwk.New(option.SecretKey)
	} else {
		return nil, errors.New("not set signing algorithm")
	}
	if err != nil {
		return nil, err
	}
	_ = realKey.Set(jwk.KeyIDKey, option.Realm)

	signed, err := jwt.Sign(t, jwa.SignatureAlgorithm(option.SigningAlgorithm), realKey)
	if err != nil {
		return nil, err
	}
	return signed, nil
}

func Verify(realm string) func(c *gin.Context) {
	option, ok := options[realm]
	if !ok {
		panic("it is an unknown realm. please use the set up")
	}
	return func(c *gin.Context) {
		var err error

		if len(c.GetHeader("Authorization")) <= 7 {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		tokenBytes := []byte(c.GetHeader("Authorization")[7:])

		var token jwt.Token
		var realKey jwk.Key
		if option.SigningAlgorithm == RS256 {
			realKey, err = jwk.New(option.privKey.PublicKey)
		} else if option.SigningAlgorithm == HS256 {
			realKey, err = jwk.New(option.SecretKey)
		} else {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		_ = realKey.Set(jwk.KeyIDKey, option.Realm)

		keySet := jwk.NewSet()
		keySet.Add(realKey)

		token, err = jwt.Parse(tokenBytes, jwt.WithKeySet(keySet))
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		c.Set("claims", token.PrivateClaims())
		c.Next()
		return
	}
}

func GetClaims(c *gin.Context) Claims {
	if claims, ok := c.Get("claims"); ok {
		return claims.(map[string]interface{})
	} else {
		return nil
	}
}
