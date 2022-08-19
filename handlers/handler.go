package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

var jwtKey = []byte(uuid.New().String())

var fakeUsers = map[string]string{
	"john doe":     "likeAKitten$$",
	"alice walker": "batmanCave1$",
}

// Credentials ...
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Claims ...
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// initialize function will set values and sign the token
func (c *Claims) initialize(creds Credentials, expirationTime time.Time) (string, error) {
	c.Username = creds.Username
	c.StandardClaims = jwt.StandardClaims{
		ExpiresAt: expirationTime.Unix()}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	tokenStr, err := token.SignedString(jwtKey)
	if err != nil {
		return "", errors.New("unable to sign key")
	}
	return tokenStr, nil
}

// createJwt to create the jwt token
func createJwt(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		fmt.Printf("unable to decode request body. details - %+v", err)
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	expectedPwd, ok := fakeUsers[creds.Username]
	// if pwd exists && is same as the users actual password
	// storing pwd is probably not ideal; need to look for better solutions
	if !ok || expectedPwd != creds.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// every seven minutes
	expirationTime := time.Now().Add(7 * time.Minute)
	claims := &Claims{}
	tokenStr, err := claims.initialize(creds, expirationTime)
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//setting jwt token as cookie
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenStr,
		Expires: expirationTime,
	})
}

// refreshToken - to refresh the token if within 30 seconds of expiration
func refreshToken(w http.ResponseWriter, r *http.Request) error {

	claims := &Claims{}
	// controls jwt token; prevents refresh requests if > 30 seconds of expiry
	if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 30*time.Second {
		return errors.New("subject is within the timeframe of the jwt")
	}
	// adding again 7 minutes of time
	expirationTime := time.Now().Add(7 * time.Minute)
	claims.ExpiresAt = expirationTime.Unix()
	createJwt(w, r)

	return nil
}

// validateCookie to validate the jwt is valid and correct
func validateCookie(w http.ResponseWriter, r *http.Request) error {
	c, err := r.Cookie("token")
	fmt.Println(r)
	if err != nil {
		return err
	}

	tokenStr := c.Value
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		return err
	}
	if !token.Valid {
		return err
	}
	return nil
}

// cookieValidation - validates jwt token passed in
func cookieValidation(w http.ResponseWriter, r *http.Request) error {
	err := validateCookie(w, r)
	if err != nil {
		return err
	}
	return nil
}

// LogIn - method to sign in the user; user must have a valid username
// and password. there might be a better way to do that.
func LogIn(w http.ResponseWriter, r *http.Request) {
	createJwt(w, r)
	err := cookieValidation(w, r)
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.Write([]byte(fmt.Sprintf("Welcome")))
}

// RefreshToken method to execute the refresh token command. this will refresh
// the token if the expiration date time has not been crossed yet.
func RefreshToken(w http.ResponseWriter, r *http.Request) {
	err := cookieValidation(w, r)
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	err = refreshToken(w, r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
}
