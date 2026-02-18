package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMainHandler_GET(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	mainHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for GET, got %d", w.Code)
	}
}

func TestProcessScan_FileMissing(t *testing.T) {
	body := &bytes.Buffer{}
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")

	w := httptest.NewRecorder()

	mainHandler(w, req)

	if w.Code == http.StatusOK {
		t.Fatalf("expected error when file missing")
	}
}

func TestProcessScan_FileTooLarge(t *testing.T) {
	largeData := make([]byte, 11<<20) // 11MB
	body := bytes.NewBuffer(largeData)

	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")

	w := httptest.NewRecorder()

	mainHandler(w, req)

	if w.Code == http.StatusOK {
		t.Fatalf("expected error for large file")
	}
}
