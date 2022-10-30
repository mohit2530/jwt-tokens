package types

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

// Credentials stores user provided username and password
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// initialize to create token with claims
func (c *Claims) initialize(credentials Credentials, expiryTime time.Time) (string, error) {
	c.Username = credentials.Username
	c.StandardClaims = jwt.StandardClaims{
		ExpiresAt: expiryTime.Unix(),
	}

	// sign with claims and signing method
	// using uuid as a jwtKey to obscure the secret key
	// need a way to use this behind the scenes
	var jwtKey = []byte(uuid.New().String())
	secretKey := fmt.Sprintf("%x", jwtKey)
	fmt.Printf("the secret key - %+v", secretKey)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	tokenStr, err := token.SignedString(jwtKey)
	if err != nil {
		log.Printf("unable to decode token. err - %+v", err)
		return "", err
	}
	return tokenStr, nil
}

// createJwt creates a jwt token for a valid user
func CreateJwt(w http.ResponseWriter, r *http.Request, creds Credentials) {

	var claims Claims

	expTime := time.Now().Add(7 * time.Minute) // every seven minutes
	tokenStr, err := claims.initialize(creds, expTime)
	if err != nil {
		log.Printf("unable to initialize token. err - %+v", err)
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenStr,
		Expires: expTime,
	})
	w.WriteHeader(http.StatusOK)
	log.Printf("generated json web token - %+v", tokenStr)
}
