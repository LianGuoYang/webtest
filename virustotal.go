package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"time"
)

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
