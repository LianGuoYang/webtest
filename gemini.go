package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func generateGeminiExplanation(apiKey, filename string,
	malicious, suspicious, harmless, undetected int) string {

	prompt := fmt.Sprintf(`
	You are a cybersecurity assistant.

	Interpret ONLY the VirusTotal detection statistics below.

	Risk rules:
	- If malicious > 0 → Risk Level: High
	- If malicious = 0 and suspicious > 0 → Risk Level: Medium
	- If malicious = 0 and suspicious = 0 → Risk Level: Low

	Do NOT speculate about file behavior.
	Do NOT interpret filename meaning.
	Do NOT exaggerate.
	Be factual and clear.

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

	bodyBytes, _ := json.Marshal(reqBody)

	url := fmt.Sprintf(
	"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=%s",
	apiKey,
	)

	if apiKey == "" {
		return "GEMINI_API_KEY is empty."
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(bodyBytes))
	if err != nil {
		return "AI unavailable."
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "Failed to read Gemini response."
	}

	fmt.Println("Gemini raw response:")
	fmt.Println(string(body))

	if resp.StatusCode == http.StatusTooManyRequests {
		return "AI explanation unavailable: Gemini quota exceeded. Please try again later."
	}

	if resp.StatusCode != http.StatusOK {
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

	if len(result.Candidates) == 0 {
		return "No explanation generated."
	}

	return result.Candidates[0].Content.Parts[0].Text
}

