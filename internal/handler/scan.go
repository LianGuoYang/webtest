package handler

import (
	"context"
	"io"
	"net/http"
	"os"
	"time"
	"github.com/google/uuid"
	"webtest/internal/logger"
	"webtest/internal/service"
	"webtest/internal/utils"
)

func MainHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		processScan(w, r)
		return
	}
	renderPage(w, r)
}

func processScan(w http.ResponseWriter, r *http.Request) {
	requestID := uuid.New().String()
	startTime := time.Now()

	reqLogger := logger.Logger.With(
		"request_id", requestID,
	)
	ctx := context.WithValue(r.Context(), logger.LoggerKey{}, reqLogger)

	reqLogger.Info("scan_started")

	// Load API keys from environment
	vtKey := os.Getenv("VT_API_KEY")
	geminiKey := os.Getenv("GEMINI_API_KEY")

	if vtKey == "" {
		reqLogger.Error("missing_virustotal_api_key")

		utils.WriteJSONError(w, http.StatusInternalServerError,
			"Server configuration error: missing VirusTotal API key")
		return
	}

	if geminiKey == "" {
		reqLogger.Error("missing_gemini_api_key")

		utils.WriteJSONError(w, http.StatusInternalServerError,
			"Server configuration error: missing Gemini API key")
		return
	}

	// Configure upload limits
	const maxUploadSize = 650 << 20  // 650MB absolute limit
	const maxDirectUpload = 32 << 20 // 32MB direct VT upload limit

	// Protect server from oversized uploads
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)

	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		reqLogger.Error("multipart_parse_failed", "error", err)

		utils.WriteJSONError(w, http.StatusBadRequest,
			"File larger than 650MB or invalid form data")
		return
	}

	// Retrieve uploaded file
	file, header, err := r.FormFile("file")
	if err != nil {
		reqLogger.Error("file_missing", "error", err)

		utils.WriteJSONError(w, http.StatusBadRequest, "File missing")
		return
	}
	defer file.Close()

	reqLogger.Info("file_received", "filename",	header.Filename)


	// Store file temporarily (memory-safe for large uploads)
	tmpFile, err := os.CreateTemp("", "upload-*")
	if err != nil {
		reqLogger.Error("temp_file_failed", "error", err)

		utils.WriteJSONError(w, http.StatusInternalServerError,
			"Failed to create temporary file")
		return
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	size, err := io.Copy(tmpFile, file)
	if err != nil {
		reqLogger.Error("file_write_failed", "error", err)

		utils.WriteJSONError(w, http.StatusInternalServerError,
			"Failed to store uploaded file")
		return
	}

	reqLogger.Info("file_stored",
		"size_mb", float64(size)/(1024*1024),
	)


	// Reset file pointer for checking MIME
	if _, err := tmpFile.Seek(0, 0); err != nil {
		reqLogger.Error("file_pointer_seek_failed", "error", err)

		utils.WriteJSONError(w, http.StatusInternalServerError,
			"Failed to reset file pointer")
		return
	}

	mimeType, err := utils.DetectMimeType(tmpFile)
	if err != nil {
		reqLogger.Error("file_type_check_failed", "error", err)

		utils.WriteJSONError(w, http.StatusBadRequest, "Could not detect file type")
		return
	}

	var allowedMimeTypes = map[string]bool{
		"application/pdf":        true,
		"application/zip":        true,
		"application/x-msdownload": true,
		"image/png":              true,
		"image/jpeg":             true,
		"text/plain; charset=utf-8": true,
		"application/javascript":    true,
		"text/javascript":           true,
	}



	if !allowedMimeTypes[mimeType] { 
		reqLogger.Warn("unsupported_file_type", "mime", mimeType)

		utils.WriteJSONError(w, http.StatusUnsupportedMediaType, "Unsupported file type")
		return
	}

	reqLogger.Info("mime_detected",
		"filename", header.Filename,
		"mime", mimeType,
	)

	// Reset file pointer for hashing
	if _, err := tmpFile.Seek(0, 0); err != nil {
		reqLogger.Error("file_pointer_seek_failed", "error", err)

		utils.WriteJSONError(w, http.StatusInternalServerError,
			"Failed to reset file pointer")
		return
	}

	// Compute SHA256 hash for VT lookup
	hash, err := utils.ComputeSHA256(tmpFile)
	if err != nil {
		reqLogger.Error("hash_failed", "error", err)
		utils.WriteJSONError(w, http.StatusInternalServerError, "Hash computation failed")
		return
	}

	reqLogger.Info("hash_computed",
		"sha256", hash,
	)


	// Reset file pointer again before uploading
	if _, err := tmpFile.Seek(0, 0); err != nil {
		reqLogger.Error("file_pointer_seek_failed", "error", err)

		utils.WriteJSONError(w, http.StatusInternalServerError,
			"Failed to reset file pointer")
		return
	}

	reqLogger.Info("virustotal_lookup_started",
		"sha256", hash,
	)

	// Check if file already exists in VirusTotal database
	stats, status, found, err := service.GetFileReport(ctx, vtKey, hash)
	if err != nil {
		reqLogger.Error("virustotal_lookup_failed", "error", err)

		utils.WriteJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// If not found, upload file for analysis
	if !found {
		reqLogger.Info("virustotal_uploading_file",
			"filename", header.Filename,
		)

		var analysisID string

		if size <= maxDirectUpload {
			// Direct upload (≤32MB)
			reqLogger.Info("virustotal_direct_upload_32MB")

			analysisID, err = service.UploadToVirusTotal(ctx, vtKey, header.Filename, tmpFile)
		} else {
			// Large file upload (32MB–650MB)
			reqLogger.Info("virustotal_direct_upload_650MB")

			var uploadURL string
			uploadURL, err = service.GetLargeUploadURL(ctx, vtKey)
			if err != nil {
				reqLogger.Error("virustotal_upload_url_failed", "error", err)

				utils.WriteJSONError(w, http.StatusInternalServerError,
					"Failed to obtain upload URL")
				return
			}
			analysisID, err = service.UploadLargeFile(ctx, vtKey, uploadURL, header.Filename, tmpFile)
		}

		if err != nil {
			reqLogger.Error("virustotal_upload_failed", "error", err)

			utils.WriteJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		
		reqLogger.Info("polling_started",
			"analysis_id", analysisID,
		)

		// Poll VT until analysis completes
		stats, status, err = service.PollAnalysis(ctx, vtKey, analysisID)
		if err != nil {
			reqLogger.Error("virustotal_polling_failed", "error", err)

			utils.WriteJSONError(w, http.StatusInternalServerError,
				"Analysis polling failed")
			return
		}
	} else {
		reqLogger.Info("virustotal_lookup_success",
			"malicious", stats["malicious"],
			"suspicious", stats["suspicious"],
		)
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

	reqLogger.Info("gemini_explanation_generate")

	// Generate AI explanation
	aiText := service.GenerateGeminiExplanation(
		ctx,
		geminiKey,
		header.Filename,
		malicious,
		suspicious,
		harmless,
		undetected,
	)

	reqLogger.Info("scan_completed",
		"duration_ms", time.Since(startTime).Milliseconds(),
		"malicious", malicious,
		"suspicious", suspicious,
		"verdict", verdict,
	)


	// Return structured JSON response
	utils.WriteJSON(w, http.StatusOK, map[string]any{
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
