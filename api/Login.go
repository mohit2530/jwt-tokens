package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/mohit2530/jwt-tokens/types"
)

// Login method will try to validate username / password and create JWT
func Login(w http.ResponseWriter, r *http.Request) {

	creds, err := verifyUser(w, r)
	if err != nil {
		log.Printf("unable to decode the request body. err - %+v", err)
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	types.CreateJwt(w, r, creds)
}

// RefreshToken method will try to refresh the token and create JWT
func RefreshToken(w http.ResponseWriter, r *http.Request) {

	creds, err := verifyUser(w, r)
	if err != nil {
		log.Printf("unable to decode the request body. err - %+v", err)
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	err = refreshToken(w, r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	types.CreateJwt(w, r, creds)
}

// verifyUser method verify if the user has the correct password or not
func verifyUser(w http.ResponseWriter, r *http.Request) (types.Credentials, error) {

	var credentials types.Credentials
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		log.Printf("unable to decode the request body. err - %+v", err)
		return types.Credentials{}, err
	}

	var fakeUsers = map[string]string{
		"john doe":           "likeAKitten$$",
		"alice walker":       "batmanCave1$",
		"testuser@gmail.com": "testuserpassword1",
	}

	// verify if password exists; this obv should improve
	// if pwd exists && is same as the users actual password
	// storing pwd is probably not ideal; need to look for better solutions
	expectedPwd, ok := fakeUsers[credentials.Username]
	if !ok || expectedPwd != credentials.Password {
		err := errors.New("unable to verify password ")
		return types.Credentials{}, err
	}

	return credentials, nil
}

// refreshToken method to refresh if the token is under 30 seconds
func refreshToken(w http.ResponseWriter, r *http.Request) error {

	claims := &types.Claims{}
	// control jwt token; prevent refresh if > 30 seconds of expiry
	if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 30*time.Second {
		return errors.New(" subject within jwt time limit")
	}
	// adds extra seven minutes
	expTime := time.Now().Add(7 * time.Minute)
	claims.ExpiresAt = expTime.Unix()
	return nil
}
