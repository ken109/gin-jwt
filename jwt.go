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

const (
	authorizationHeader = "Authorization"

	refreshTokenKeyIDSuffix = "-refresh"
)

type Claims map[string]interface{}

type Option struct {
	Realm string

	SigningAlgorithm SignatureAlgorithm

	SecretKey []byte

	PrivKeyFile  string
	PrivKeyBytes []byte
	privKey      *rsa.PrivateKey

	Timeout        time.Duration
	RefreshTimeout time.Duration

	Issuer  string
	Subject string
}

var options = make(map[string]Option)

func issueToken(realm string, timeout time.Duration, claims Claims, refresh bool) (string, error) {
	var err error

	option, ok := options[realm]
	if !ok {
		return "", errors.New("it is an unknown realm. please use the set up")
	}

	token := jwt.New()

	_ = token.Set(jwt.IssuedAtKey, time.Now().Unix())
	_ = token.Set(jwt.IssuerKey, option.Issuer)
	_ = token.Set(jwt.SubjectKey, option.Subject)
	_ = token.Set(jwt.ExpirationKey, time.Now().Add(timeout).Unix())

	for k, v := range claims {
		err = token.Set(k, v)
		if err != nil {
			return "", err
		}
	}

	var realKey jwk.Key
	if option.SigningAlgorithm == RS256 {
		realKey, err = jwk.New(option.privKey)
	} else if option.SigningAlgorithm == HS256 {
		realKey, err = jwk.New(option.SecretKey)
	} else {
		return "", errors.New("not set signing algorithm")
	}
	if err != nil {
		return "", err
	}

	if !refresh {
		_ = realKey.Set(jwk.KeyIDKey, option.Realm)
	} else {
		_ = realKey.Set(jwk.KeyIDKey, option.Realm+refreshTokenKeyIDSuffix)
	}

	signed, err := jwt.Sign(token, jwa.SignatureAlgorithm(option.SigningAlgorithm), realKey)
	if err != nil {
		return "", err
	}
	return string(signed), nil
}

func IssueToken(realm string, claims Claims) (token string, refreshToken string, err error) {
	option, ok := options[realm]
	if !ok {
		return "", "", errors.New("it is an unknown realm. please use the set up")
	}

	token, err = issueToken(realm, option.Timeout, claims, false)
	if err != nil {
		return "", "", errors.New("failed to issue token")
	}

	refreshToken, err = issueToken(realm, option.RefreshTimeout, claims, true)
	if err != nil {
		return "", "", errors.New("failed to issue refresh token")
	}
	return
}

func RefreshToken(realm string, refreshToken string) (ok bool, newToken string, newRefreshToken string, err error) {
	token, err := verify(realm, []byte(refreshToken), true)
	if err != nil {
		return false, "", "", err
	}
	if token == nil {
		return false, "", "", nil
	}
	newToken, newRefreshToken, err = IssueToken(realm, token.PrivateClaims())
	return true, newToken, newRefreshToken, err
}

func verify(realm string, tokenBytes []byte, refresh bool) (token jwt.Token, err error) {
	option, ok := options[realm]
	if !ok {
		panic("it is an unknown realm. please use the set up")
	}

	var realKey jwk.Key
	if option.SigningAlgorithm == RS256 {
		realKey, err = jwk.New(option.privKey.PublicKey)
	} else if option.SigningAlgorithm == HS256 {
		realKey, err = jwk.New(option.SecretKey)
	} else {
		return nil, errors.New("not set signing algorithm")
	}
	if err != nil {
		return nil, err
	}

	if !refresh {
		_ = realKey.Set(jwk.KeyIDKey, option.Realm)
	} else {
		_ = realKey.Set(jwk.KeyIDKey, option.Realm+refreshTokenKeyIDSuffix)
	}

	keySet := jwk.NewSet()
	keySet.Add(realKey)

	token, err = jwt.Parse(tokenBytes, jwt.WithKeySet(keySet))
	if err != nil || token.Expiration().UnixNano() < time.Now().UnixNano() {
		return nil, nil
	}
	return
}

func Verify(realm string) func(c *gin.Context) {
	return func(c *gin.Context) {
		var err error

		if len(c.GetHeader(authorizationHeader)) <= 7 {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		tokenBytes := []byte(c.GetHeader(authorizationHeader)[7:])

		token, err := verify(realm, tokenBytes, false)
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		if token == nil {
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
