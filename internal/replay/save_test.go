package replay

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveResponse(t *testing.T) {
	tmpDir := t.TempDir()
	session := &Session{
		RequestFile: "/dev/null",
		BaseURL:     "http://example.com",
		OutputDir:   tmpDir,
		Save:        true,
	}

	result := &Result{
		Target:     "http://example.com",
		StatusCode: 200,
		Headers:    map[string][]string{"Content-Type": {"text/html"}},
		Body:       "Hello, world!",
		Raw:        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nHello, world!",
	}

	path, err := session.saveResponse(result)
	if err != nil {
		t.Fatalf("saveResponse failed: %v", err)
	}
	if path == "" {
		t.Fatal("expected non-empty path")
	}

	// Verify file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatalf("saved file does not exist: %s", path)
	}

	// Verify content
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read saved file: %v", err)
	}
	if !stringContains(string(data), "HTTP/1.1 200 OK") {
		t.Errorf("expected saved response to contain status line, got: %s", string(data))
	}
	if !stringContains(string(data), "Hello, world!") {
		t.Errorf("expected saved response to contain body, got: %s", string(data))
	}

	// Verify filename format
	if !filepath.IsAbs(path) && !strings.HasPrefix(path, tmpDir) {
		t.Errorf("expected path to be in output dir, got: %s", path)
	}
}

func TestSaveResponseNoSave(t *testing.T) {
	session := &Session{
		Save: false,
	}

	result := &Result{
		StatusCode: 200,
		Body:       "test",
	}

	path, err := session.saveResponse(result)
	if err != nil {
		t.Fatalf("saveResponse should not fail when Save is false: %v", err)
	}
	if path != "" {
		t.Errorf("expected empty path when Save is false, got: %s", path)
	}
}

func TestSaveResponseWithLongURL(t *testing.T) {
	tmpDir := t.TempDir()
	session := &Session{
		RequestFile: "/dev/null",
		BaseURL:     "http://very-long-domain-name.example.com/path/to/resource",
		OutputDir:   tmpDir,
		Save:        true,
	}

	result := &Result{
		Target:     "http://very-long-domain-name.example.com/path/to/resource",
		StatusCode: 200,
		Body:       "ok",
	}

	path, err := session.saveResponse(result)
	if err != nil {
		t.Fatalf("saveResponse failed: %v", err)
	}

	// Verify filename is reasonable (target part is truncated, but full filename can be longer)
	base := filepath.Base(path)
	// The target part should be at most 50 chars, plus _200_timestamp.txt (~20 chars)
	if len(base) > 75 {
		t.Errorf("expected reasonable filename length, got: %s", base)
	}
}

func stringContains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && stringContainsHelper(s, substr))
}

func stringContainsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
