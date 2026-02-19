package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"time"
)

func mainHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		processScan(w, r)
		return
	}
	renderPage(w)
}

func processScan(w http.ResponseWriter, r *http.Request) {
	// Load API keys from environment
	vtKey := os.Getenv("VT_API_KEY")
	geminiKey := os.Getenv("GEMINI_API_KEY")

	if vtKey == "" {
		writeJSONError(w, http.StatusInternalServerError,
			"Server configuration error: missing VirusTotal API key")
		return
	}

	if geminiKey == "" {
		writeJSONError(w, http.StatusInternalServerError,
			"Server configuration error: missing Gemini API key")
		return
	}

	// Configure upload limits
	const maxUploadSize = 650 << 20  // 650MB absolute limit
	const maxDirectUpload = 32 << 20 // 32MB direct VT upload limit

	// Protect server from oversized uploads
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)

	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		writeJSONError(w, http.StatusBadRequest,
			"File larger than 650MB or invalid form data")
		return
	}

	// Retrieve uploaded file
	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "File missing")
		return
	}
	defer file.Close()

	// Store file temporarily (memory-safe for large uploads)
	tmpFile, err := os.CreateTemp("", "upload-*")
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError,
			"Failed to create temporary file")
		return
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	size, err := io.Copy(tmpFile, file)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError,
			"Failed to store uploaded file")
		return
	}

	// Reset file pointer for hashing
	if _, err := tmpFile.Seek(0, 0); err != nil {
		writeJSONError(w, http.StatusInternalServerError,
			"Failed to reset file pointer")
		return
	}

	// Compute SHA256 hash for VT lookup
	hasher := sha256.New()
	if _, err := io.Copy(hasher, tmpFile); err != nil {
		writeJSONError(w, http.StatusInternalServerError,
			"Hash computation failed")
		return
	}
	hash := hex.EncodeToString(hasher.Sum(nil))

	// Reset file pointer again before uploading
	if _, err := tmpFile.Seek(0, 0); err != nil {
		writeJSONError(w, http.StatusInternalServerError,
			"Failed to reset file pointer")
		return
	}

	// Check if file already exists in VirusTotal database
	stats, status, found, err := getFileReport(vtKey, hash)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// If not found, upload file for analysis
	if !found {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
		defer cancel()

		var analysisID string

		if size <= maxDirectUpload {
			// Direct upload (≤32MB)
			analysisID, err = uploadToVirusTotal(vtKey, header.Filename, tmpFile)
		} else {
			// Large file upload (32MB–650MB)
			var uploadURL string
			uploadURL, err = getLargeUploadURL(ctx, vtKey)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError,
					"Failed to obtain upload URL")
				return
			}
			analysisID, err = uploadLargeFile(ctx, uploadURL, header.Filename, tmpFile)
		}

		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		// Poll VT until analysis completes
		stats, status, err = pollAnalysis(vtKey, analysisID)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError,
				"Analysis polling failed")
			return
		}
	}

	// Extract detection statistics
	malicious := stats["malicious"]
	suspicious := stats["suspicious"]
	harmless := stats["harmless"]
	undetected := stats["undetected"]

	// Derive simple verdict
	verdict := "Likely Safe"
	if malicious > 0 {
		verdict = "Malicious File Detected"
	} else if suspicious > 0 {
		verdict = "Potentially Suspicious"
	}

	// Generate AI explanation
	aiText := generateGeminiExplanation(
		geminiKey,
		header.Filename,
		malicious,
		suspicious,
		harmless,
		undetected,
	)

	// Return structured JSON response
	writeJSON(w, http.StatusOK, map[string]any{
		"filename":       header.Filename,
		"status":         status,
		"malicious":      malicious,
		"suspicious":     suspicious,
		"harmless":       harmless,
		"undetected":     undetected,
		"verdict":        verdict,
		"ai_explanation": aiText,
	})
}
