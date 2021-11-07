package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/assert/v2"
)

var rsRealm = "rs"
var rsRealm2 = "rs2"

var hsRealm = "hs"
var hsRealm2 = "hs2"

var refreshRealm = "refresh"

func TestMain(m *testing.M) {
	gin.SetMode(gin.ReleaseMode)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	privateKey := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	privateKeyBytes := pem.EncodeToMemory(privateKey)

	if err := SetUp(Option{Realm: rsRealm, SigningAlgorithm: RS256, PrivKeyBytes: privateKeyBytes}); err != nil {
		panic(fmt.Errorf("failed to set up: %w", err))
		return
	}

	if err := SetUp(Option{Realm: rsRealm2, SigningAlgorithm: RS256, PrivKeyBytes: privateKeyBytes}); err != nil {
		panic(fmt.Errorf("failed to set up: %w", err))
		return
	}

	if err := SetUp(Option{Realm: hsRealm, SigningAlgorithm: HS256, SecretKey: []byte("secret")}); err != nil {
		panic(fmt.Errorf("failed to set up: %w", err))
		return
	}

	if err := SetUp(Option{Realm: hsRealm2, SigningAlgorithm: HS256, SecretKey: []byte("secret")}); err != nil {
		panic(fmt.Errorf("failed to set up: %w", err))
		return
	}

	if err := SetUp(
		Option{
			Realm:            refreshRealm,
			SigningAlgorithm: HS256,
			SecretKey:        []byte("refresh"),
			Timeout:          time.Second,
		},
	); err != nil {
		panic(fmt.Errorf("failed to set up: %w", err))
		return
	}

	os.Exit(m.Run())
}

func testVerifyToken(t *testing.T, realm string) {
	res := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(res)

	c.Request, _ = http.NewRequest("GET", "/", nil)

	MustVerify(realm)(c)

	assert.Equal(t, res.Code, http.StatusUnauthorized)
}

func TestVerifyRS256EmptyToken(t *testing.T) {
	testVerifyToken(t, rsRealm)
}

func TestVerifyHS256EmptyToken(t *testing.T) {
	testVerifyToken(t, hsRealm)
}

func testVerifyInvalidToken(t *testing.T, realm string) {
	res := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(res)
	c.Request, _ = http.NewRequest("GET", "/", nil)
	c.Request.Header.Add("Authorization", "invalid_token")

	MustVerify(realm)(c)

	assert.Equal(t, res.Code, http.StatusUnauthorized)
}

func TestVerifyRS256InvalidToken(t *testing.T) {
	testVerifyInvalidToken(t, rsRealm)
}

func TestVerifyHS256InvalidToken(t *testing.T) {
	testVerifyInvalidToken(t, hsRealm)
}

func testVerifyValidToken(t *testing.T, realm string) {
	token, _, err := IssueToken(realm, Claims{})
	if err != nil {
		t.Errorf("failed to issue token: %s", err.Error())
		return
	}

	res := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(res)
	c.Request, _ = http.NewRequest("GET", "/", nil)
	c.Request.Header.Add("Authorization", "bearer "+token)

	MustVerify(realm)(c)

	assert.Equal(t, res.Code, http.StatusOK)
	assert.Equal(t, GetClaims(c), Claims{})
}

func TestVerifyRS256ValidToken(t *testing.T) {
	testVerifyValidToken(t, rsRealm)
}

func TestVerifyHS256ValidToken(t *testing.T) {
	testVerifyValidToken(t, hsRealm)
}

func testVerifyWrongRealm(t *testing.T, realm1 string, realm2 string) {
	token, _, err := IssueToken(realm1, Claims{})
	if err != nil {
		t.Errorf("failed to issue token: %s", err.Error())
		return
	}

	res := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(res)
	c.Request, _ = http.NewRequest("GET", "/", nil)
	c.Request.Header.Add("Authorization", "bearer "+token)

	MustVerify(realm2)(c)

	assert.Equal(t, res.Code, http.StatusUnauthorized)
}

func TestVerifyRS256WrongRealm(t *testing.T) {
	testVerifyWrongRealm(t, rsRealm, rsRealm2)
}

func TestVerifyHS256WrongRealm(t *testing.T) {
	testVerifyWrongRealm(t, hsRealm, hsRealm2)
}

func TestRefreshToken(t *testing.T) {
	token, refreshToken, err := IssueToken(refreshRealm, Claims{"admin": true})
	if err != nil {
		t.Errorf("failed to issue token: %s", err.Error())
		return
	}

	time.Sleep(time.Second * 2)

	res := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(res)
	c.Request, _ = http.NewRequest("GET", "/", nil)
	c.Request.Header.Add("Authorization", "bearer "+token)

	MustVerify(refreshRealm)(c)

	assert.Equal(t, res.Code, http.StatusUnauthorized)

	_, token, _, err = RefreshToken(refreshRealm, refreshToken)
	if err != nil {
		t.Errorf("failed to issue token: %s", err.Error())
		return
	}

	res = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(res)
	c.Request, _ = http.NewRequest("GET", "/", nil)
	c.Request.Header.Add("Authorization", "bearer "+token)

	MustVerify(refreshRealm)(c)

	assert.Equal(t, res.Code, http.StatusOK)
	assert.Equal(t, GetClaims(c)["admin"].(bool), true)
}

func TestGetClaim(t *testing.T) {
	type args struct {
		key   string
		value interface{}
	}
	tests := []struct {
		name      string
		args      args
		wantValue interface{}
		wantOk    bool
	}{
		{
			name:      "boolean",
			args:      args{key: "admin", value: true},
			wantValue: true,
			wantOk:    true,
		},
		{
			name:      "uint",
			args:      args{key: "id", value: 1},
			wantValue: 1,
			wantOk:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(res)
			c.Request, _ = http.NewRequest("GET", "/", nil)

			c.Set("claims", map[string]interface{}{
				tt.args.key: tt.args.value,
			})

			gotValue, gotOk := GetClaim(c, tt.args.key)
			if !reflect.DeepEqual(gotValue, tt.wantValue) {
				t.Errorf("GetClaim() gotValue = %v, want %v", gotValue, tt.wantValue)
			}
			if gotOk != tt.wantOk {
				t.Errorf("GetClaim() gotOk = %v, want %v", gotOk, tt.wantOk)
			}
		})
	}
}
