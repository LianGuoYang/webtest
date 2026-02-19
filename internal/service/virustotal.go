package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"time"
	"webtest/internal/logger"
)

// getFileReport queries VirusTotal’s `/files/{hash}` endpoint to retrieve
// existing analysis statistics for a file based on its SHA256 hash.
// Reference: https://docs.virustotal.com/reference/file-info
func GetFileReport(ctx context.Context, apiKey, hash string) (map[string]int, string, bool, error) {
	logger := logger.GetLogger(ctx)
	logger.Info("vt_lookup_request_started", "sha256", hash)

	url := fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", hash)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, "", false, err
	}

	req.Header.Set("x-apikey", apiKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", false, err
	}
	defer resp.Body.Close()

	logger.Info("vt_lookup_response_received", "status_code", resp.StatusCode)

	switch resp.StatusCode {
	case http.StatusOK:
		// File exists in VirusTotal database → continue parsing response

	case http.StatusNotFound:
		// Hash not found in VirusTotal
		return nil, "", false, nil

	case http.StatusTooManyRequests:
		// Free API quota exceeded (rate limit hit)
		return nil, "", false, fmt.Errorf("rate limit exceeded (429)")

	default:
		// Any other unexpected HTTP error
		return nil, "", false, fmt.Errorf("VT file lookup failed: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", false, err
	}

	var result struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats map[string]int `json:"last_analysis_stats"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, "", false, err
	}

	logger.Info("vt_lookup_success")

	return result.Data.Attributes.LastAnalysisStats,
		"completed",
		true,
		nil
}

// Reference: https://docs.virustotal.com/reference/files-scan
// uploadToVirusTotal sends a file (≤32MB) to VirusTotal’s `/files` endpoint using multipart/form-data.
func UploadToVirusTotal(ctx context.Context, apiKey, filename string, file io.Reader) (string, error) {
	logger := logger.GetLogger(ctx)
	logger.Info("vt_direct_upload_started", "filename", filename)

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return "", err
	}

	if _, err := io.Copy(part, file); err != nil {
		return "", err
	}

	if err := writer.Close(); err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, 
		"POST",
		"https://www.virustotal.com/api/v3/files",
		&buf,
	)
	if err != nil {
		return "", err
	}

	req.Header.Set("x-apikey", apiKey)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	logger.Info("vt_direct_upload_response", "status_code", resp.StatusCode)

	switch resp.StatusCode {
	case http.StatusOK:
		// Upload successful → parse analysis ID

	case http.StatusTooManyRequests:
		return "", fmt.Errorf("rate limit exceeded (429)")

	default:
		return "", fmt.Errorf("VT upload failed: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var out struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}

	logger.Info("vt_direct_upload_success", "analysis_id", out.Data.ID)

	return out.Data.ID, nil
}

// Reference: https://docs.virustotal.com/reference/files-upload-url
// getLargeUploadURL retrieves a one-time upload URL from VirusTotal
// for files larger than 32MB (up to 650MB).
func GetLargeUploadURL(ctx context.Context, apiKey string) (string, error) {
	logger := logger.GetLogger(ctx)
	logger.Info("vt_large_upload_url_request_started")

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"https://www.virustotal.com/api/v3/files/upload_url",
		nil,
	)
	if err != nil {
		return "", err
	}

	req.Header.Set("x-apikey", apiKey)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	logger.Info("vt_large_upload_url_response", "status_code", resp.StatusCode)

	switch resp.StatusCode {
	case http.StatusOK:
    	// Successfully retrieved upload URL

	case http.StatusUnauthorized:
		// Invalid or missing API key
		return "", fmt.Errorf("unauthorized (401)")

	case http.StatusNotFound:
		// Analysis ID not found
		return "", fmt.Errorf("analysis ID not found (404)")

	case http.StatusTooManyRequests:
		// API rate limit exceeded
		return "", fmt.Errorf("rate limit exceeded (429)")

	default:
		// Any unexpected HTTP error
		return "", fmt.Errorf("upload_url failed (%d): %s", resp.StatusCode, string(body))
	}

	var out struct {
		Data string `json:"data"`
	}

	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}

	if out.Data == "" {
		return "", fmt.Errorf("empty upload URL received")
	}

	logger.Info("vt_large_upload_url_success")

	return out.Data, nil
}

func UploadLargeFile(ctx context.Context, apiKey, uploadURL, filename string, file *os.File) (string, error) {
	logger := logger.GetLogger(ctx)
	logger.Info("vt_large_upload_started", "filename", filename)

	pr, pw := io.Pipe()
	writer := multipart.NewWriter(pw)

	go func() {
		defer pw.Close()
		defer writer.Close()

		part, err := writer.CreateFormFile("file", filename)
		if err != nil {
			pw.CloseWithError(err)
			return
		}

		if _, err := io.Copy(part, file); err != nil {
			pw.CloseWithError(err)
			return
		}
	}()

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		uploadURL,
		pr,
	)
	if err != nil {
		return "", err
	}

	req.Header.Set("x-apikey", apiKey)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{
		Timeout: 10 * time.Minute,
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	logger.Info("vt_large_upload_response", "status_code", resp.StatusCode)

	switch resp.StatusCode {
	case http.StatusOK:
		// Receives upload URL

	case http.StatusUnauthorized:
		return "", fmt.Errorf("upload URL expired or unauthorized (401)")

	case http.StatusForbidden:
		return "", fmt.Errorf("upload forbidden or expired (403)")

	case http.StatusTooManyRequests:
		return "", fmt.Errorf("rate limit exceeded (429)")

	default:
		return "", fmt.Errorf("large upload failed: %d", resp.StatusCode)
	}

	var out struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}

	if out.Data.ID == "" {
		return "", fmt.Errorf("no analysis ID returned")
	}

	logger.Info("vt_large_upload_success", "analysis_id", out.Data.ID)

	return out.Data.ID, nil
}

// pollAnalysis repeatedly queries `/analyses/{id}` until the scan
// completes or a timeout is reached.
func PollAnalysis(ctx context.Context, apiKey, id string) (map[string]int, string, error) {
	logger := logger.GetLogger(ctx)
	logger.Info("vt_polling_started", "analysis_id", id)

	url := fmt.Sprintf("https://www.virustotal.com/api/v3/analyses/%s", id)
	client := &http.Client{Timeout: 30 * time.Second}

	for i := 0; i < 30; i++ {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, "", err
		}

		req.Header.Set("x-apikey", apiKey)

		resp, err := client.Do(req)
		if err != nil {
			return nil, "", err
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, "", err
		}

		logger.Info("vt_polling_attempt",
			"attempt", i+1,
			"status_code", resp.StatusCode,
		)

		switch resp.StatusCode {
		case http.StatusOK:
			// Analysis exists → continue parsing response

		case http.StatusUnauthorized:
			// Invalid or missing API key
			return nil, "", fmt.Errorf("unauthorized (401)")

		case http.StatusNotFound:
			// Analysis ID not found
			return nil, "", fmt.Errorf("analysis ID not found (404)")

		case http.StatusTooManyRequests:
			// API rate limit exceeded
			return nil, "", fmt.Errorf("rate limit exceeded (429)")

		default:
			// Any unexpected HTTP error
			return nil, "", fmt.Errorf("analysis polling failed: %d", resp.StatusCode)
		}

		var result struct {
			Data struct {
				Attributes struct {
					Status string         `json:"status"`
					Stats  map[string]int `json:"stats"`
				} `json:"attributes"`
			} `json:"data"`
		}

		if err := json.Unmarshal(body, &result); err != nil {
			return nil, "", err
		}

		if result.Data.Attributes.Status == "completed" {
			logger.Info("vt_polling_completed")

			return result.Data.Attributes.Stats,
				result.Data.Attributes.Status,
				nil
		}

		time.Sleep(2 * time.Second)
	}

	logger.Error("vt_polling_timeout")

	return nil, "", fmt.Errorf("analysis timeout after polling")
}
