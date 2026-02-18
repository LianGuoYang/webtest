package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"log"
)

func computeSHA256(file io.Reader) (string, []byte, error) {
	data, err := io.ReadAll(file)
	if err != nil {
		return "", nil, err
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), data, nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(payload)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	log.Printf("HTTP %d: %s", status, msg)

	writeJSON(w, status, map[string]any{"error": msg})
}
