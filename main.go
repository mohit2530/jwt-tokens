package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/mohit2530/jwt-tokens/api"
)

func main() {

	router := mux.NewRouter()
	router.HandleFunc("/validate", api.Login).Methods(http.MethodPost)
	router.HandleFunc("/refreshToken", api.RefreshToken).Methods(http.MethodPost)

	log.Printf("secure is warming up ")
	http.ListenAndServe(":3007", router)
}
