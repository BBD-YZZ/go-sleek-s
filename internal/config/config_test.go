package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.DefaultTimeout != 10 {
		t.Errorf("expected DefaultTimeout=10, got %d", cfg.DefaultTimeout)
	}
	if cfg.Concurrency != 25 {
		t.Errorf("expected Concurrency=25, got %d", cfg.Concurrency)
	}
	if cfg.RateLimit != 150 {
		t.Errorf("expected RateLimit=150, got %d", cfg.RateLimit)
	}
	if cfg.UserAgent == "" {
		t.Error("expected non-empty UserAgent")
	}
	if cfg.TemplateDir != "templates" {
		t.Errorf("expected TemplateDir='templates', got %q", cfg.TemplateDir)
	}
}

func TestLoadMissingFileReturnsDefaults(t *testing.T) {
	cfg, err := Load("/nonexistent/path/config.yaml")
	if err != nil {
		t.Fatalf("Load should not error on missing file, got: %v", err)
	}
	if cfg.DefaultTimeout != 10 {
		t.Errorf("expected default timeout, got %d", cfg.DefaultTimeout)
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	content := `
default-timeout: 30
concurrency: 50
rate-limit: 200
user-agent: "test-agent"
`
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load should succeed: %v", err)
	}
	if cfg.DefaultTimeout != 30 {
		t.Errorf("expected DefaultTimeout=30, got %d", cfg.DefaultTimeout)
	}
	if cfg.Concurrency != 50 {
		t.Errorf("expected Concurrency=50, got %d", cfg.Concurrency)
	}
	if cfg.RateLimit != 200 {
		t.Errorf("expected RateLimit=200, got %d", cfg.RateLimit)
	}
	if cfg.UserAgent != "test-agent" {
		t.Errorf("expected UserAgent='test-agent', got %q", cfg.UserAgent)
	}
}

func TestResolveCeyeTokenPriority(t *testing.T) {
	// Priority: config > flag > env
	if got := ResolveCeyeToken("flag-token", "", ""); got != "flag-token" {
		t.Errorf("config empty, flag should win: got %q", got)
	}
	if got := ResolveCeyeToken("", "env-token", ""); got != "env-token" {
		t.Errorf("config empty, env should win: got %q", got)
	}
	if got := ResolveCeyeToken("", "", "cfg-token"); got != "cfg-token" {
		t.Errorf("config should win: got %q", got)
	}
	if got := ResolveCeyeToken("flag", "env", "cfg"); got != "cfg" {
		t.Errorf("config > flag > env, got %q", got)
	}
}

func TestResolveCeyeDomainPriority(t *testing.T) {
	if got := ResolveCeyeDomain("flag-domain", "", ""); got != "flag-domain" {
		t.Errorf("config empty, flag should win: got %q", got)
	}
	if got := ResolveCeyeDomain("", "env-domain", ""); got != "env-domain" {
		t.Errorf("config empty, env should win: got %q", got)
	}
	if got := ResolveCeyeDomain("flag", "env", "cfg"); got != "cfg" {
		t.Errorf("config > flag > env, got %q", got)
	}
}

func TestToScanOptions(t *testing.T) {
	cfg := &GlobalConfig{
		TemplateDir:  "tpl",
		Concurrency:  10,
		RateLimit:    50,
		DefaultTimeout: 5,
	}
	opts := cfg.ToScanOptions()
	if opts.TemplateDir != "tpl" {
		t.Errorf("expected TemplateDir='tpl', got %q", opts.TemplateDir)
	}
	if opts.Concurrency != 10 {
		t.Errorf("expected Concurrency=10, got %d", opts.Concurrency)
	}
	if opts.RateLimit != 50 {
		t.Errorf("expected RateLimit=50, got %d", opts.RateLimit)
	}
	if opts.Timeout != 5 {
		t.Errorf("expected Timeout=5, got %d", opts.Timeout)
	}
}

func TestExpandTilde(t *testing.T) {
	home, _ := os.UserHomeDir()
	if got := ExpandTilde("~/some/path"); got != filepath.Join(home, "some", "path") {
		t.Errorf("ExpandTilde('~/some/path') = %q, want %q", got, filepath.Join(home, "some", "path"))
	}
	if got := ExpandTilde("/absolute/path"); got != "/absolute/path" {
		t.Errorf("ExpandTilde('/absolute/path') = %q, want '/absolute/path'", got)
	}
}

func TestEnsureDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a", "b", "c", "file.log")
	EnsureDir(path)
	if _, err := os.Stat(filepath.Join(dir, "a", "b", "c")); err != nil {
		t.Errorf("EnsureDir should create nested dirs: %v", err)
	}
}
