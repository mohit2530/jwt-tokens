package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/mohit2530/jwt-tokens/handlers"
)

func main() {

	router := mux.NewRouter()

	router.HandleFunc("/login", handlers.LogIn).Methods(http.MethodPost)
	router.HandleFunc("/refreshToken", handlers.RefreshToken).Methods(http.MethodGet)

	fmt.Printf("server is running ... ")
	http.ListenAndServe(":8000", router)
}
