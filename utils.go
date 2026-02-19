package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"log"
)

// computeSHA256 reads the entire file into memory and returns its SHA256 hash
// along with the raw file bytes for further processing.
func computeSHA256(file io.Reader) (string, []byte, error) {
	data, err := io.ReadAll(file)
	if err != nil {
		return "", nil, err
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), data, nil
}

// writeJSON writes a JSON response with the provided HTTP status code.
func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(payload)
}

// writeJSONError logs the error server-side and returns a standardized
// JSON error response to the client.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	log.Printf("HTTP %d: %s", status, msg)
	writeJSON(w, status, map[string]any{"error": msg})
}
