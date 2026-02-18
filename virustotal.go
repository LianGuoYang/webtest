package main

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
)

func getFileReport(apiKey, hash string) (map[string]int, string, bool, error) {
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", hash)

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("x-apikey", apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, "", false, nil
	}

	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats map[string]int `json:"last_analysis_stats"`
			} `json:"attributes"`
		} `json:"data"`
	}

	json.Unmarshal(body, &result)

	return result.Data.Attributes.LastAnalysisStats,
		"completed",
		true,
		nil
}

func uploadToVirusTotal(apiKey, filename string, file io.Reader) (string, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	part, _ := writer.CreateFormFile("file", filename)
	io.Copy(part, file)
	writer.Close()

	req, _ := http.NewRequest("POST",
		"https://www.virustotal.com/api/v3/files",
		&buf,
	)

	req.Header.Set("x-apikey", apiKey)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var out struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}

	json.Unmarshal(body, &out)
	return out.Data.ID, nil
}

func getLargeUploadURL(ctx context.Context, apiKey string) (string, error) {
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

	if resp.StatusCode != http.StatusOK {
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

	return out.Data, nil
}

func uploadLargeFile(ctx context.Context, uploadURL, filename string, file *os.File) (string, error) {
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

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("large upload failed (%d): %s", resp.StatusCode, string(body))
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

	return out.Data.ID, nil
}

func pollAnalysis(apiKey, id string) (map[string]int, string, error) {
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/analyses/%s", id)

	for i := 0; i < 15; i++ {

		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("x-apikey", apiKey)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, "", err
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var result struct {
			Data struct {
				Attributes struct {
					Status string         `json:"status"`
					Stats  map[string]int `json:"stats"`
				} `json:"attributes"`
			} `json:"data"`
		}

		json.Unmarshal(body, &result)

		if result.Data.Attributes.Status == "completed" {
			return result.Data.Attributes.Stats,
				result.Data.Attributes.Status,
				nil
		}

		time.Sleep(2 * time.Second)
	}

	return nil, "", fmt.Errorf("timeout")
}
