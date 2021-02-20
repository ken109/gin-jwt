package jwt

import (
	"github.com/gin-gonic/gin"
	"github.com/go-playground/assert/v2"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerifyEmptyToken(t *testing.T) {
	res := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(res)

	c.Request, _ = http.NewRequest("GET", "/", nil)

	Verify(c)

	assert.Equal(t, res.Code, http.StatusUnauthorized)
}

func TestVerifyInvalidToken(t *testing.T) {
	pemBytes, err := ioutil.ReadFile("private.key")
	if err != nil {
		panic(err)
	}

	if err := SetUp(pemBytes, Option{}); err != nil {
		panic(err)
	}

	res := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(res)

	c.Request, _ = http.NewRequest("GET", "/", nil)
	c.Request.Header.Add("Authorization", "test")

	Verify(c)

	assert.Equal(t, res.Code, http.StatusUnauthorized)
}

func TestVerifyValidToken(t *testing.T) {
	pemBytes, err := ioutil.ReadFile("private.key")
	if err != nil {
		panic(err)
	}

	if err := SetUp(pemBytes, Option{}); err != nil {
		panic(err)
	}

	res := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(res)

	c.Request, _ = http.NewRequest("GET", "/", nil)

	token, err := IssueToken(Claims{})

	c.Request.Header.Add("Authorization", "bearer "+string(token))

	Verify(c)

	assert.Equal(t, res.Code, http.StatusOK)
	assert.Equal(t, GetClaims(c), Claims{})
}
