package main

import (
	"bytes"
	"testing"
)

func TestComputeSHA256(t *testing.T) {
	data := []byte("hello world")

	reader := bytes.NewReader(data)

	hash, fileBytes, err := computeSHA256(reader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hash == "" {
		t.Fatalf("expected non-empty hash")
	}

	if len(hash) != 64 {
		t.Fatalf("expected 64-character SHA256 hash, got %d", len(hash))
	}

	if len(fileBytes) != len(data) {
		t.Fatalf("expected fileBytes length %d, got %d", len(data), len(fileBytes))
	}
}
