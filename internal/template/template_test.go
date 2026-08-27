package template

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureStderr runs fn while capturing everything written to os.Stderr,
// returning the captured string. os.Stderr is restored afterwards.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w

	fn()

	// Close the write end so the reader sees EOF.
	w.Close()
	os.Stderr = orig

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	return string(buf[:n])
}

// TestLoadDirWarnsOnBadTemplate verifies that a malformed YAML template does
// NOT abort the whole scan (LoadDir returns no error) and that a [WARN]
// message is emitted to stderr so the failure isn't silently lost. Good
// templates in the same directory must still be loaded.
func TestLoadDirWarnsOnBadTemplate(t *testing.T) {
	dir := t.TempDir()

	// Good template
	good := `id: test-good
name: Good Template
description: a valid template
severity: info
http:
  - method: GET
    path:
      - /
    matchers:
      - type: status
        status:
          - 200
`
	if err := os.WriteFile(filepath.Join(dir, "good.yaml"), []byte(good), 0o644); err != nil {
		t.Fatal(err)
	}

	// Broken template: invalid YAML indentation / unterminated structure
	bad := `id: test-bad
name: Bad Template
http:
  - method: GET
    path:
      - /
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "oops: [unterminated
`
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}

	// Non-yaml file should be ignored without warning.
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignore me"), 0o644); err != nil {
		t.Fatal(err)
	}

	var loaded int
	stderr := captureStderr(t, func() {
		tmpls, err := LoadDir(dir)
		if err != nil {
			t.Fatalf("LoadDir should not return error on a bad template: %v", err)
		}
		loaded = len(tmpls)
	})

	// Good template still loaded, bad one skipped (not aborted).
	if loaded != 1 {
		t.Errorf("expected exactly 1 loaded template, got %d", loaded)
	}

	// Warning must be present and mention the bad file.
	if !strings.Contains(stderr, "[WARN]") || !strings.Contains(stderr, "bad.yaml") {
		t.Errorf("expected a [WARN] about bad.yaml on stderr, got: %q", stderr)
	}

	// The good file must NOT be warned about.
	if strings.Contains(stderr, "good.yaml") {
		t.Errorf("good.yaml should not produce a warning, stderr: %q", stderr)
	}

	// Non-yaml files should not trigger warnings.
	if strings.Contains(stderr, "notes.txt") {
		t.Errorf("non-yaml file should be ignored silently, stderr: %q", stderr)
	}
}

// TestLoadDirEmptyDir verifies an empty (or non-existent) directory loads
// zero templates without panicking.
func TestLoadDirEmptyDir(t *testing.T) {
	dir := t.TempDir()
	tmpls, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir on empty dir should not error, got: %v", err)
	}
	if len(tmpls) != 0 {
		t.Errorf("expected 0 templates from empty dir, got %d", len(tmpls))
	}
}

// TestLoadFileErrorIsWrapped verifies a parse error is returned by LoadFile
// (the warning happens at the LoadDir level).
func TestLoadFileErrorIsWrapped(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "broken.yaml")
	if err := os.WriteFile(bad, []byte("http:\n  - method: [unterminated\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(bad); err == nil {
		t.Error("LoadFile should return a wrapped parse error")
	}
}
