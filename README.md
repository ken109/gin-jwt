# Example
Click here for an implementation example.

https://github.com/ken109/gin-jwt-example

# Overview
1. Issuance of private key
```bash
openssl genrsa -out private.key 2048
```

3. Add Import
```go
import (
    "github.com/ken109/gin-jwt"
)
```

2. Set private key, Issuer, etc.
```go
func main() {
    pemBytes, err := ioutil.ReadFile("private.key")
    if err != nil {
        panic(err)
    }

    // here
    err := jwt.SetUp(pemBytes, jwt.Option{
        Issuer: "test@test.com",
        Subject: "test@test.com",
        KeyId: "test",
        Expiration: time.Hour * 1,
    })
    
    if err != nil {
        panic(err)
    }

    r := gin.New()
  
        :
        :
}
```

3. Issue a signed token
```go
func Login(c *gin.Context) {
    user := "user"
    password := "password"
    
    if user == "user" && password == "password" {
        // here
        token, err := jwt.GetToken(jwt.Claims{
            "admin": true,
        })
        
        if err != nil {
            c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed"})
            return
        }
        
        c.JSON(http.StatusOK, map[string]interface{}{"token": string(token)})
        return
    }
    
    c.JSON(http.StatusForbidden, map[string]string{"error": "login failed"})
    return
}
```

4. Set the middleware on the route you want to authenticate 
```go
func main() {
    :
    
    auth := r.Group("/api")

    // here
    auth.Use(jwt.Verify)
    
    :
}
```

5. Receive private claims
```go
func main() {
    :
    
    auth.Use(jwt.Verify)
    
    auth.GET("/hello", func(c *gin.Context) {
        // here
        claims := jwt.GetClaims(c)
        
        fmt.Println(claims["admin"].(bool)) // true
        
        c.JSON(http.StatusOK, claims)
    })
    
    :
}
```
