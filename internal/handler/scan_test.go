package handler

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProcessScan_FileMissing(t *testing.T) {
	body := &bytes.Buffer{}
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")

	w := httptest.NewRecorder()

	MainHandler(w, req)

	if w.Code == http.StatusOK {
		t.Fatalf("expected error when file missing")
	}
}

func TestProcessScan_FileTooLarge(t *testing.T) {
	largeData := make([]byte, 700<<20) // 11MB
	body := bytes.NewBuffer(largeData)

	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")

	w := httptest.NewRecorder()

	MainHandler(w, req)

	if w.Code == http.StatusOK {
		t.Fatalf("expected error for large file")
	}
}
