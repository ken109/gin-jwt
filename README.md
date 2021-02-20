# Example
Click here for an implementation example.

https://github.com/ken109/gin-jwt-example

# Overview
1. Issuance of private key
```bash
openssl genrsa -out private.key 2048
```

2. Example Main.go
```go
package main

import (
	"github.com/gin-gonic/gin"
	"github.com/ken109/gin-jwt"
	"io/ioutil"
	"net/http"
)

func main() {
	pemBytes, err := ioutil.ReadFile("private.key")
	if err != nil {
		panic(err)
	}

	// setup
	if err = jwt.SetUp(pemBytes, jwt.Option{}); err != nil {
		panic(err)
	}

	r := gin.New()
	r.POST("/login", Login)

	auth := r.Group("/api")
	// Set the middleware on the route you want to authenticate
	auth.Use(jwt.Verify)
	auth.GET("/hello", func(c *gin.Context) {
		claims := jwt.GetClaims(c)

		// claims["admin"].(bool)) -> true
		
		c.JSON(http.StatusOK, claims)
	})

	if err = r.Run(":8080"); err != nil {
		panic(err)
	}
}

func Login(c *gin.Context) {
	password := "test"

	if password == "test" {
		c.JSON(http.StatusForbidden, "login failed")
		return
	} else {
		// Issue Token
		token, _ := jwt.IssueToken(jwt.Claims{
			"admin": true,
		})
		
		c.JSON(http.StatusOK, string(token))
	}
}
```
