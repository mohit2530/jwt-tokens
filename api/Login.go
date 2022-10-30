package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/mohit2530/jwt-tokens/types"
)

func Login(w http.ResponseWriter, r *http.Request) {

	var creds types.Credentials
	creds, err := verifyUser(w, r, creds)
	if err != nil {
		log.Printf("unable to decode the request body. err - %+v", err)
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	types.CreateJwt(w, r, creds)
}

// verifyUser method verify if the user has the correct password or not
func verifyUser(w http.ResponseWriter, r *http.Request, credentials types.Credentials) (types.Credentials, error) {

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
