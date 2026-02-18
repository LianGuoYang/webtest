package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
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
	// 1. Save API Keys
	vtKey := os.Getenv("VT_API_KEY")
	geminiKey := os.Getenv("GEMINI_API_KEY")

	if vtKey == "" {
		writeJSONError(w, 500, "Server configuration error: Empty VirusTotal API KEY ")
		return
	}

	if geminiKey == "" {
		writeJSONError(w, 500, "Server configuration error: Empty Gemini API KEY")
		return
	}
	
	// Ensure file size 
	const maxUploadSize = 650 << 20
	const maxDirectUpload = 32 << 20

	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)

	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		writeJSONError(w, 400, "File larger than 650MB or invalid form data")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSONError(w, 400, "File missing")
		return
	}
	defer file.Close()


	// Temp file for large files (memory safe)
	tmpFile, err := os.CreateTemp("", "upload-*")
	if err != nil {
		writeJSONError(w, 500, "Failed to create temp file")
		return
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	size, err := io.Copy(tmpFile, file)
	if err != nil {
		writeJSONError(w, 500, "Failed to store file")
		return
	}

	if _, err := tmpFile.Seek(0, 0); err != nil {
		writeJSONError(w, 500, "File seek failed")
		return
	}

	// Check hash of the file for quick look up
	hasher := sha256.New()
	if _, err := io.Copy(hasher, tmpFile); err != nil {
		writeJSONError(w, 500, "Hashing failed")
		return
	}
	hash := hex.EncodeToString(hasher.Sum(nil))

	if _, err := tmpFile.Seek(0, 0); err != nil {
		writeJSONError(w, 500, "File seek failed")
		return
	}

	stats, status, found, err := getFileReport(vtKey, hash)
	if err != nil {
		writeJSONError(w, 500, err.Error())
		return
	}

	if !found {

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
		defer cancel()

		// Upload file to VirusTotal for full scan
		var analysisID string

		if size <= maxDirectUpload {
			analysisID, err = uploadToVirusTotal(vtKey, header.Filename, tmpFile)
		} else {
			uploadURL, err := getLargeUploadURL(ctx, vtKey)
			if err != nil {
				writeJSONError(w, 500, "Failed to get upload URL")
				return
			}
			analysisID, err = uploadLargeFile(ctx, uploadURL, header.Filename, tmpFile)
		}
		log.Println(analysisID)
		stats, status, err = pollAnalysis(vtKey, analysisID)
		if err != nil {
			writeJSONError(w, 500, "Polling failed")
			return
		}
	}

	malicious := stats["malicious"]
	suspicious := stats["suspicious"]
	harmless := stats["harmless"]
	undetected := stats["undetected"]
	verdict := "Likely Safe"
	if malicious > 0 {
		verdict = "Malicious File Detected"
	} else if suspicious > 0 {
		verdict = "Potentially Suspicious"
	}

	// 3. Generate AI Explanation
	aiText := generateGeminiExplanation(
		geminiKey,
		header.Filename,
		malicious,
		suspicious,
		harmless,
		undetected,
	)

	writeJSON(w, 200, map[string]any{
		"filename":       header.Filename,
		"status":         status,
		"malicious":      malicious,
		"suspicious":     suspicious,
		"harmless":       harmless,
		"undetected":     undetected,
		"verdict":		  verdict,
		"ai_explanation": aiText,
	})
}
