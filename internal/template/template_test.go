package template

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadDirWarnsOnBadTemplate verifies that a malformed YAML template does
// NOT abort the whole scan (LoadDir returns no error) and that good templates
// in the same directory are still loaded.
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

	tmpls, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir should not return error on a bad template: %v", err)
	}

	// Good template still loaded, bad one skipped (not aborted).
	if len(tmpls) != 1 {
		t.Errorf("expected exactly 1 loaded template, got %d", len(tmpls))
	}
	if len(tmpls) > 0 && tmpls[0].ID != "test-good" {
		t.Errorf("expected test-good template, got %s", tmpls[0].ID)
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

// TestLoadDirIgnoresNonYaml verifies non-YAML files are silently ignored.
func TestLoadDirIgnoresNonYaml(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignore me"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "readme.md"), []byte("# Readme"), 0o644); err != nil {
		t.Fatal(err)
	}
	tmpls, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir on dir with only non-yaml files should not error, got: %v", err)
	}
	if len(tmpls) != 0 {
		t.Errorf("expected 0 templates, got %d", len(tmpls))
	}
}
