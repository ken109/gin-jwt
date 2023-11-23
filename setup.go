package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"
)

func SetUp(option Option) error {
	if option.Realm == "" {
		return errors.New("not set realm")
	}

	if option.Timeout == 0 {
		option.Timeout = time.Hour * 1
	}

	if option.RefreshTimeout == 0 {
		option.RefreshTimeout = time.Hour * 24 * 90
	}

	if option.SigningAlgorithm == RS256 {
		if err := setRsaPrivateKey(&option); err != nil {
			return err
		}
	} else if option.SigningAlgorithm == HS256 {
		if len(option.SecretKey) == 0 {
			return errors.New("not set secret key")
		}
	} else {
		return errors.New("not set signing algorithm")
	}

	if _, ok := options[option.Realm]; ok {
		return fmt.Errorf("realm is already exists: %s", option.Realm)
	}
	options[option.Realm] = option
	return nil
}

func setRsaPrivateKey(option *Option) error {
	var err error

	var privKeyBytes []byte
	if len(option.PrivKeyBytes) > 0 {
		privKeyBytes = option.PrivKeyBytes
	} else if option.PrivKeyFile != "" {
		privKeyBytes, err = os.ReadFile(option.PrivKeyFile)
		if err != nil {
			return fmt.Errorf("failed to read file: %s", option.PrivKeyFile)
		}
	} else {
		return errors.New("not set private key")
	}

	block, _ := pem.Decode(privKeyBytes)
	if block == nil {
		return errors.New("invalid private key data")
	}

	var privKey *rsa.PrivateKey
	if block.Type == "RSA PRIVATE KEY" {
		privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
	} else if block.Type == "PRIVATE KEY" || block.Type == "ENCRYPTED PRIVATE KEY" {
		keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		var ok bool
		privKey, ok = keyInterface.(*rsa.PrivateKey)
		if !ok {
			return errors.New("not RSA private key")
		}
	} else {
		return fmt.Errorf("invalid private key type : %s", block.Type)
	}

	privKey.Precompute()

	if err := privKey.Validate(); err != nil {
		return err
	}

	option.privKey = privKey
	return nil
}
