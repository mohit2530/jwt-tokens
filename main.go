package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/mohit2530/jwt-tokens/api"
)

func main() {

	router := mux.NewRouter()
	router.HandleFunc("/login", api.Login).Methods(http.MethodPost)

	log.Printf("application is up and running ")
	http.ListenAndServe(":8080", router)
}

