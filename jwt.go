package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"net/http"
	"time"
)

type Option struct {
	privateKey *rsa.PrivateKey
	Issuer     string
	Subject    string
	KeyId      string
	Expiration time.Duration
}

var options Option

func SetUp(pemBytes []byte, option Option) error {
	setOption(option)
	if err := setRsaPrivateKey(pemBytes); err != nil {
		return err
	}
	return nil
}

func setRsaPrivateKey(pemBytes []byte) error {
	var err error
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return errors.New("invalid private key data")
	}

	var key *rsa.PrivateKey
	if block.Type == "RSA PRIVATE KEY" {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
	} else if block.Type == "PRIVATE KEY" {
		keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		var ok bool
		key, ok = keyInterface.(*rsa.PrivateKey)
		if !ok {
			return errors.New("not RSA private key")
		}
	} else {
		return fmt.Errorf("invalid private key type : %s", block.Type)
	}

	key.Precompute()

	if err := key.Validate(); err != nil {
		return err
	}

	options.privateKey = key
	return nil
}

func setOption(option Option) {
	if option.Issuer == "" {
		option.Issuer = "test@example.com"
	}
	if option.Subject == "" {
		option.Subject = "test@example.com"
	}
	if option.KeyId == "" {
		option.KeyId = "example"
	}
	if option.Expiration == 0 {
		option.Expiration = time.Hour * 1
	}
	options = option
}

func GetToken(claims map[string]interface{}) ([]byte, error) {
	var err error

	t := jwt.New()

	_ = t.Set(jwt.IssuerKey, options.Issuer)
	_ = t.Set(jwt.SubjectKey, options.Subject)
	_ = t.Set(jwt.ExpirationKey, time.Now().Add(options.Expiration).Unix())
	_ = t.Set(jwt.IssuedAtKey, time.Now().Unix())

	for k, v := range claims {
		err = t.Set(k, v)
		if err != nil {
			return nil, err
		}
	}

	realKey, err := jwk.New(options.privateKey)
	if err != nil {
		return nil, err
	}
	_ = realKey.Set(jwk.KeyIDKey, options.KeyId)

	signed, err := jwt.Sign(t, jwa.RS256, realKey)
	if err != nil {
		return nil, err
	}

	return signed, nil
}

func Verify(c *gin.Context) {
	pubKey, err := jwk.New(options.privateKey.PublicKey)
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	_ = pubKey.Set(jwk.KeyIDKey, options.KeyId)

	keySet := jwk.NewSet()
	keySet.Add(pubKey)

	token, err := jwt.Parse([]byte(c.GetHeader("Authorization")[7:]), jwt.WithKeySet(keySet))
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	c.Set("claims", token.PrivateClaims())
	c.Next()
	return
}
