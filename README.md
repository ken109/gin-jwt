# Overview

1. Issue private key

```bash
openssl genrsa -out private.key 2048
```

2. Example main.go

```go
package main

import (
	"github.com/gin-gonic/gin"
	"github.com/ken109/gin-jwt"
	"fmt"
	"net/http"
)

const MyRealm = "my-realm"

func main() {
	// setup
	_ = jwt.SetUp(
		jwt.Option{
			Realm:            MyRealm,
			SigningAlgorithm: jwt.RS256,
			PrivKeyFile:      "private.key",
		},
	)

	r := gin.New()
	r.POST("/login", Login)
	r.GET("/refresh", RefreshToken)

	auth := r.Group("/api")

	// Set the middleware on the route you want to authenticate
	auth.Use(jwt.MustVerify(MyRealm))

	auth.GET(
		"/hello", func(c *gin.Context) {
			claims := jwt.GetClaims(c)

			fmt.Println(claims["admin"].(bool)) // true

			c.JSON(http.StatusOK, claims)
		},
	)

	if err := r.Run(":8080"); err != nil {
		panic(err)
	}
}

func Login(c *gin.Context) {
	password := "test"

	if password != "test" {

		c.JSON(http.StatusForbidden, "login failed")

		return
	} else {
		// Issue Token
		token, refreshToken, _ := jwt.IssueToken(
			MyRealm,
			jwt.Claims{
				"admin": true,
			},
		)

		c.JSON(
			http.StatusOK, gin.H{
				"token":         token,
				"refresh_token": refreshToken,
			},
		)
	}
}

func RefreshToken(c *gin.Context) {
	ok, token, refreshToken, _ := jwt.RefreshToken(MyRealm, c.Query("refresh_token"))
	if !ok {
		c.Status(http.StatusUnauthorized)
		return
	}

	c.JSON(
		http.StatusOK, gin.H{
			"token":         token,
			"refresh_token": refreshToken,
		},
	)
}
```
