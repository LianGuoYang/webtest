package main

import (
	"bytes"
	"net/http"
	"os"
)

func mainHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		processScan(w, r)
		return
	}
	renderPage(w)
}

func processScan(w http.ResponseWriter, r *http.Request) {

	vtKey := os.Getenv("VT_API_KEY")
	geminiKey := os.Getenv("GEMINI_API_KEY")

	const maxUploadSize = 10 << 20
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)

	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		writeJSONError(w, 400, "Invalid form data")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSONError(w, 400, "File missing")
		return
	}
	defer file.Close()

	hash, fileBytes, err := computeSHA256(file)
	if err != nil {
		writeJSONError(w, 500, "Failed to compute hash")
		return
	}

	stats, status, found, err := getFileReport(vtKey, hash)
	if err != nil {
		writeJSONError(w, 500, err.Error())
		return
	}

	if !found {
		analysisID, err := uploadToVirusTotal(vtKey, header.Filename, bytes.NewReader(fileBytes))
		if err != nil {
			writeJSONError(w, 500, "Upload failed")
			return
		}

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
		"verdict":        verdict,
		"ai_explanation": aiText,
	})
}
