package tests

import (
	"bytes"
	"testing"
	"webtest/internal/utils"
)

func TestComputeSHA256(t *testing.T) {
	data := []byte("hello world")
	reader := bytes.NewReader(data)

	hash, err := utils.ComputeSHA256(reader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hash == "" {
		t.Fatalf("expected non-empty hash")
	}

	if len(hash) != 64 {
		t.Fatalf("expected 64-character SHA256 hash, got %d", len(hash))
	}
}
