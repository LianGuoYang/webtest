package utils

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
func ComputeSHA256(file io.Reader) (string, error) {
    hasher := sha256.New()

    _, err := io.Copy(hasher, file)
    if err != nil {
        return "", err
    }

    return hex.EncodeToString(hasher.Sum(nil)), nil
}

// writeJSON writes a JSON response with the provided HTTP status code.
func WriteJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("JSON encode failed: %v", err)
	}
}

// writeJSONError logs the error server-side and returns a standardized
// JSON error response to the client.
func WriteJSONError(w http.ResponseWriter, status int, msg string) {
	log.Printf("HTTP %d: %s", status, msg)
	WriteJSON(w, status, map[string]any{"error": msg})
}

// Detect MIME from magic bytes.
func DetectMimeType(file io.ReadSeeker) (string, error) {
	buf := make([]byte, 512)

	n, err := file.Read(buf)
	if err != nil && err != io.EOF {
		return "", err
	}

	mimeType := http.DetectContentType(buf[:n])

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}

	return mimeType, nil
}
