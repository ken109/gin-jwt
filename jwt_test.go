package jwt_test

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

	jwt "github.com/ken109/gin-jwt"
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

	if err := jwt.SetUp(jwt.Option{Realm: rsRealm, SigningAlgorithm: jwt.RS256, PrivKeyBytes: privateKeyBytes}); err != nil {
		panic(fmt.Errorf("failed to set up: %w", err))
	}

	if err := jwt.SetUp(jwt.Option{Realm: rsRealm2, SigningAlgorithm: jwt.RS256, PrivKeyBytes: privateKeyBytes}); err != nil {
		panic(fmt.Errorf("failed to set up: %w", err))
	}

	if err := jwt.SetUp(jwt.Option{Realm: hsRealm, SigningAlgorithm: jwt.HS256, SecretKey: []byte("secret")}); err != nil {
		panic(fmt.Errorf("failed to set up: %w", err))
	}

	if err := jwt.SetUp(jwt.Option{Realm: hsRealm2, SigningAlgorithm: jwt.HS256, SecretKey: []byte("secret")}); err != nil {
		panic(fmt.Errorf("failed to set up: %w", err))
	}

	if err := jwt.SetUp(
		jwt.Option{
			Realm:            refreshRealm,
			SigningAlgorithm: jwt.HS256,
			SecretKey:        []byte("refresh"),
			Timeout:          time.Second,
		},
	); err != nil {
		panic(fmt.Errorf("failed to set up: %w", err))
	}

	os.Exit(m.Run())
}

func TestVerify(t *testing.T) {
	type args struct {
		realm       string
		mustVerify  bool
		makeRequest func(c *gin.Context, realm string)
	}
	tests := []struct {
		name string
		args args
		want func(c *gin.Context, res *httptest.ResponseRecorder)
	}{
		{
			name: "RS256/EmptyToken/MustVerify",
			args: args{
				realm:      rsRealm,
				mustVerify: true,
				makeRequest: func(c *gin.Context, realm string) {
					c.Request, _ = http.NewRequest("GET", "/", nil)
				},
			},
			want: func(c *gin.Context, res *httptest.ResponseRecorder) {
				assert.Equal(t, res.Code, http.StatusUnauthorized)
			},
		},
		{
			name: "HS256/EmptyToken/MustVerify",
			args: args{
				realm:      hsRealm,
				mustVerify: true,
				makeRequest: func(c *gin.Context, realm string) {
					c.Request, _ = http.NewRequest("GET", "/", nil)
				},
			},
			want: func(c *gin.Context, res *httptest.ResponseRecorder) {
				assert.Equal(t, res.Code, http.StatusUnauthorized)
			},
		},
		{
			name: "RS256/EmptyToken/TryVerify",
			args: args{
				realm:      rsRealm,
				mustVerify: false,
				makeRequest: func(c *gin.Context, realm string) {
					c.Request, _ = http.NewRequest("GET", "/", nil)
				},
			},
			want: func(c *gin.Context, res *httptest.ResponseRecorder) {
				assert.Equal(t, res.Code, http.StatusOK)
			},
		},
		{
			name: "HS256/EmptyToken/TryVerify",
			args: args{
				realm:      hsRealm,
				mustVerify: false,
				makeRequest: func(c *gin.Context, realm string) {
					c.Request, _ = http.NewRequest("GET", "/", nil)
				},
			},
			want: func(c *gin.Context, res *httptest.ResponseRecorder) {
				assert.Equal(t, res.Code, http.StatusOK)
			},
		},
		{
			name: "RS256/InvalidToken/MustVerify",
			args: args{
				realm:      rsRealm,
				mustVerify: true,
				makeRequest: func(c *gin.Context, realm string) {
					c.Request, _ = http.NewRequest("GET", "/", nil)
					c.Request.Header.Add("Authorization", "invalid_token")
				},
			},
			want: func(c *gin.Context, res *httptest.ResponseRecorder) {
				assert.Equal(t, res.Code, http.StatusUnauthorized)
			},
		},
		{
			name: "HS256/InvalidToken/MustVerify",
			args: args{
				realm:      hsRealm,
				mustVerify: true,
				makeRequest: func(c *gin.Context, realm string) {
					c.Request, _ = http.NewRequest("GET", "/", nil)
					c.Request.Header.Add("Authorization", "invalid_token")
				},
			},
			want: func(c *gin.Context, res *httptest.ResponseRecorder) {
				assert.Equal(t, res.Code, http.StatusUnauthorized)
			},
		},
		{
			name: "RS256/InvalidToken/TryVerify",
			args: args{
				realm:      rsRealm,
				mustVerify: false,
				makeRequest: func(c *gin.Context, realm string) {
					c.Request, _ = http.NewRequest("GET", "/", nil)
					c.Request.Header.Add("Authorization", "invalid_token")
				},
			},
			want: func(c *gin.Context, res *httptest.ResponseRecorder) {
				assert.Equal(t, res.Code, http.StatusOK)
			},
		},
		{
			name: "HS256/InvalidToken/TryVerify",
			args: args{
				realm:      hsRealm,
				mustVerify: false,
				makeRequest: func(c *gin.Context, realm string) {
					c.Request, _ = http.NewRequest("GET", "/", nil)
					c.Request.Header.Add("Authorization", "invalid_token")
				},
			},
			want: func(c *gin.Context, res *httptest.ResponseRecorder) {
				assert.Equal(t, res.Code, http.StatusOK)
			},
		},
		{
			name: "RS256/ValidToken/MustVerify",
			args: args{
				realm:      rsRealm,
				mustVerify: true,
				makeRequest: func(c *gin.Context, realm string) {
					token, _, err := jwt.IssueToken(realm, jwt.Claims{})
					if err != nil {
						t.Errorf("failed to issue token: %s", err.Error())
						return
					}

					c.Request, _ = http.NewRequest("GET", "/", nil)
					c.Request.Header.Add("Authorization", "bearer "+token)
				},
			},
			want: func(c *gin.Context, res *httptest.ResponseRecorder) {
				assert.Equal(t, res.Code, http.StatusOK)
				assert.Equal(t, jwt.GetClaims(c), jwt.Claims{})
			},
		},
		{
			name: "HS256/ValidToken/MustVerify",
			args: args{
				realm:      hsRealm,
				mustVerify: true,
				makeRequest: func(c *gin.Context, realm string) {
					token, _, err := jwt.IssueToken(realm, jwt.Claims{})
					if err != nil {
						t.Errorf("failed to issue token: %s", err.Error())
						return
					}

					c.Request, _ = http.NewRequest("GET", "/", nil)
					c.Request.Header.Add("Authorization", "bearer "+token)
				},
			},
			want: func(c *gin.Context, res *httptest.ResponseRecorder) {
				assert.Equal(t, res.Code, http.StatusOK)
				assert.Equal(t, jwt.GetClaims(c), jwt.Claims{})
			},
		},
		{
			name: "RS256/ValidToken/TryVerify",
			args: args{
				realm:      rsRealm,
				mustVerify: false,
				makeRequest: func(c *gin.Context, realm string) {
					token, _, err := jwt.IssueToken(realm, jwt.Claims{})
					if err != nil {
						t.Errorf("failed to issue token: %s", err.Error())
						return
					}

					c.Request, _ = http.NewRequest("GET", "/", nil)
					c.Request.Header.Add("Authorization", "bearer "+token)
				},
			},
			want: func(c *gin.Context, res *httptest.ResponseRecorder) {
				assert.Equal(t, res.Code, http.StatusOK)
				assert.Equal(t, jwt.GetClaims(c), jwt.Claims{})
			},
		},
		{
			name: "HS256/ValidToken/TryVerify",
			args: args{
				realm:      hsRealm,
				mustVerify: false,
				makeRequest: func(c *gin.Context, realm string) {
					token, _, err := jwt.IssueToken(realm, jwt.Claims{})
					if err != nil {
						t.Errorf("failed to issue token: %s", err.Error())
						return
					}

					c.Request, _ = http.NewRequest("GET", "/", nil)
					c.Request.Header.Add("Authorization", "bearer "+token)
				},
			},
			want: func(c *gin.Context, res *httptest.ResponseRecorder) {
				assert.Equal(t, res.Code, http.StatusOK)
				assert.Equal(t, jwt.GetClaims(c), jwt.Claims{})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(res)

			tt.args.makeRequest(c, tt.args.realm)

			if tt.args.mustVerify {
				jwt.MustVerify(tt.args.realm)(c)
			} else {
				jwt.TryVerify(tt.args.realm)(c)
			}

			tt.want(c, res)
		})
	}
}

func TestVerifyWrongRealm(t *testing.T) {
	type args struct {
		requestRealm string
		verifyRealm  string
		mustVerify   bool
		makeRequest  func(c *gin.Context, realm string)
	}
	tests := []struct {
		name string
		args args
		want func(c *gin.Context, res *httptest.ResponseRecorder)
	}{
		{
			name: "RS256/MustVerify",
			args: args{
				requestRealm: rsRealm,
				verifyRealm:  rsRealm2,
				mustVerify:   true,
				makeRequest: func(c *gin.Context, realm string) {
					c.Request, _ = http.NewRequest("GET", "/", nil)
				},
			},
			want: func(c *gin.Context, res *httptest.ResponseRecorder) {
				assert.Equal(t, res.Code, http.StatusUnauthorized)
			},
		},
		{
			name: "HS256/MustVerify",
			args: args{
				requestRealm: hsRealm,
				verifyRealm:  hsRealm2,
				mustVerify:   true,
				makeRequest: func(c *gin.Context, realm string) {
					c.Request, _ = http.NewRequest("GET", "/", nil)
				},
			},
			want: func(c *gin.Context, res *httptest.ResponseRecorder) {
				assert.Equal(t, res.Code, http.StatusUnauthorized)
			},
		},
		{
			name: "RS256/TryVerify",
			args: args{
				requestRealm: rsRealm,
				verifyRealm:  rsRealm2,
				mustVerify:   false,
				makeRequest: func(c *gin.Context, realm string) {
					c.Request, _ = http.NewRequest("GET", "/", nil)
				},
			},
			want: func(c *gin.Context, res *httptest.ResponseRecorder) {
				assert.Equal(t, res.Code, http.StatusOK)
			},
		},
		{
			name: "HS256/TryVerify",
			args: args{
				requestRealm: hsRealm,
				verifyRealm:  hsRealm2,
				mustVerify:   false,
				makeRequest: func(c *gin.Context, realm string) {
					c.Request, _ = http.NewRequest("GET", "/", nil)
				},
			},
			want: func(c *gin.Context, res *httptest.ResponseRecorder) {
				assert.Equal(t, res.Code, http.StatusOK)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(res)

			tt.args.makeRequest(c, tt.args.requestRealm)

			if tt.args.mustVerify {
				jwt.MustVerify(tt.args.verifyRealm)(c)
			} else {
				jwt.TryVerify(tt.args.verifyRealm)(c)
			}

			tt.want(c, res)
		})
	}
}

func TestRefreshToken(t *testing.T) {
	token, refreshToken, err := jwt.IssueToken(refreshRealm, jwt.Claims{"admin": true})
	if err != nil {
		t.Errorf("failed to issue token: %s", err.Error())
		return
	}

	time.Sleep(time.Second * 2)

	res := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(res)
	c.Request, _ = http.NewRequest("GET", "/", nil)
	c.Request.Header.Add("Authorization", "bearer "+token)

	jwt.MustVerify(refreshRealm)(c)

	assert.Equal(t, res.Code, http.StatusUnauthorized)

	_, token, _, err = jwt.RefreshToken(refreshRealm, refreshToken)
	if err != nil {
		t.Errorf("failed to issue token: %s", err.Error())
		return
	}

	res = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(res)
	c.Request, _ = http.NewRequest("GET", "/", nil)
	c.Request.Header.Add("Authorization", "bearer "+token)

	jwt.MustVerify(refreshRealm)(c)

	assert.Equal(t, res.Code, http.StatusOK)
	assert.Equal(t, jwt.GetClaims(c)["admin"].(bool), true)
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

			gotValue, gotOk := jwt.GetClaim(c, tt.args.key)
			if !reflect.DeepEqual(gotValue, tt.wantValue) {
				t.Errorf("GetClaim() gotValue = %v, want %v", gotValue, tt.wantValue)
			}
			if gotOk != tt.wantOk {
				t.Errorf("GetClaim() gotOk = %v, want %v", gotOk, tt.wantOk)
			}
		})
	}
}
