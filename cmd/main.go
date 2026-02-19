package main

import (
	"log"
	"net/http"
	"github.com/joho/godotenv"
    "webtest/internal/handler"
)

func main() {
	_ = godotenv.Load()

	http.HandleFunc("/", handler.MainHandler)

	log.Println("Server running at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
