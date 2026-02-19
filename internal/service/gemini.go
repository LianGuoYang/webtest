package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"context"
)

func GenerateGeminiExplanation(ctx context.Context, apiKey, filename string,
		malicious, suspicious, harmless, undetected int,) string {

	if apiKey == "" {
		return "GEMINI_API_KEY is empty."
	}

	prompt := fmt.Sprintf(`
		You are a cybersecurity assistant.

		File: %s

		VirusTotal statistics:
		- Malicious: %d
		- Suspicious: %d
		- Harmless: %d
		- Undetected: %d

		Risk rules:
		- If malicious > 0 → Risk Level: High
		- If malicious = 0 and suspicious > 0 → Risk Level: Medium
		- If malicious = 0 and suspicious = 0 → Risk Level: Low

		Do NOT speculate.
		Be factual.

		Format exactly like this:

		Scan Summary:
		- <one clear sentence>

		Risk Level:
		- <Low / Medium / High>

		Recommended Action:
		- <one practical step>

		Avoid:
		- <one short warning>
		`,
		filename,
		malicious,
		suspicious,
		harmless,
		undetected,
	)

	reqBody := map[string]any{
		"contents": []map[string]any{
			{
				"parts": []map[string]string{
					{"text": prompt},
				},
			},
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "Failed to prepare AI request."
	}

	url := fmt.Sprintf(
		"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=%s",
		apiKey,
	)

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(bodyBytes))
	if err != nil {
		return "AI service unavailable."
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "Failed to read Gemini response."
	}

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue parsing

	case http.StatusTooManyRequests:
		return "AI explanation unavailable: Gemini quota exceeded."

	case http.StatusUnauthorized:
		return "Gemini authentication failed (401)."

	case http.StatusForbidden:
		return "Gemini access forbidden (403)."

	default:
		return fmt.Sprintf("Gemini API error (HTTP %d).", resp.StatusCode)
	}

	var result struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return "Failed to parse Gemini response."
	}

	if len(result.Candidates) == 0 ||
		len(result.Candidates[0].Content.Parts) == 0 {
		return "No explanation generated."
	}

	return result.Candidates[0].Content.Parts[0].Text
}
