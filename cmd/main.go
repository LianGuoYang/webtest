package main

import (
	"log"
	"net/http"
	"time"
	"github.com/joho/godotenv"
	"webtest/internal/handler"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found (production mode)")
	}

	http.HandleFunc("/", handler.MainHandler)

	http.Handle("/static/",
		http.StripPrefix("/static/",
			http.FileServer(http.Dir("./static")),
		),
	)

	server := &http.Server{
		Addr:         ":8080",
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 5 * time.Minute,
		IdleTimeout:  60 * time.Second,
	}

	log.Println("Server running at http://localhost:8080")
	log.Fatal(server.ListenAndServe())
}
