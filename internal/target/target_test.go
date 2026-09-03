package target

import (
	"strings"
	"testing"
)

func TestNormalizeTarget(t *testing.T) {
	tests := []struct {
		input, expected string
	}{
		{"http://example.com", "http://example.com:80"},
		{"https://example.com", "https://example.com:443"},
		{"example.com", "http://example.com:80"},
		{"example.com:8080", "http://example.com:8080"},
		{"example.com:443", "https://example.com:443"},
		{"http://example.com/path", "http://example.com:80"},
		{"http://example.com?a=1", "http://example.com:80"},
		{"", ""},
		{"  ", ""},
	}
	for _, tc := range tests {
		result := NormalizeTarget(tc.input)
		if result != tc.expected {
			t.Errorf("NormalizeTarget(%q) = %q, expected %q", tc.input, result, tc.expected)
		}
	}
}

func TestParseTarget(t *testing.T) {
	t.Run("http url", func(t *testing.T) {
		tgt := ParseTarget("http://example.com:8080/api")
		if tgt == nil {
			t.Fatal("expected non-nil target")
		}
		if tgt.URL != "http://example.com:8080" {
			t.Errorf("URL = %q", tgt.URL)
		}
		if tgt.Port != "8080" {
			t.Errorf("Port = %q", tgt.Port)
		}
	})
	t.Run("no scheme", func(t *testing.T) {
		tgt := ParseTarget("example.com")
		if tgt == nil {
			t.Fatal("expected non-nil target")
		}
		if tgt.Scheme != "http" {
			t.Errorf("Scheme = %q", tgt.Scheme)
		}
	})
	t.Run("https", func(t *testing.T) {
		tgt := ParseTarget("https://example.com")
		if tgt == nil {
			t.Fatal("expected non-nil target")
		}
		if tgt.Scheme != "https" {
			t.Errorf("Scheme = %q", tgt.Scheme)
		}
	})
	t.Run("empty", func(t *testing.T) {
		if ParseTarget("") != nil {
			t.Error("expected nil for empty input")
		}
	})
}

func TestNormalizeTargets(t *testing.T) {
	input := []string{
		"http://example.com",
		"http://example.com", // exact duplicate
		"http://other.com",
	}
	result := NormalizeTargets(input)
	if len(result) != 2 {
		t.Fatalf("expected 2 unique targets, got %d: %v", len(result), result)
	}
}

func TestLoadFromLines(t *testing.T) {
	lines := []string{
		"http://example.com",
		"# comment",
		"",
		"http://other.com",
	}
	result := LoadFromLines(lines)
	if len(result) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(result))
	}
	if result[0] != "http://example.com" || result[1] != "http://other.com" {
		t.Errorf("unexpected: %v", result)
	}
}

func TestDedupByHost(t *testing.T) {
	input := []string{
		"http://example.com:80",
		"https://example.com:443",
		"http://other.com",
	}
	result := DedupByHost(input)
	// http://example.com:80 and https://example.com:443 have different ports, so both kept
	if len(result) != 3 {
		t.Fatalf("expected 3 (different ports), got %d: %v", len(result), result)
	}
}

func TestDedupByURL(t *testing.T) {
	input := []string{
		"http://example.com",
		"http://example.com",
		"https://example.com",
	}
	result := DedupByURL(input)
	if len(result) != 2 {
		t.Fatalf("expected 2 after dedup by URL, got %d", len(result))
	}
}

func TestFilterByScheme(t *testing.T) {
	input := []string{
		"http://example.com",
		"https://other.com",
		"http://third.com",
	}
	result := FilterByScheme(input, "https")
	if len(result) != 1 {
		t.Fatalf("expected 1 https target, got %d: %v", len(result), result)
	}
	if !strings.Contains(result[0], "other.com") {
		t.Errorf("unexpected: %v", result)
	}
}

func TestSortByHost(t *testing.T) {
	input := []string{
		"http://zebra.com",
		"http://alpha.com",
		"http://middle.com",
	}
	result := SortByHost(input)
	// Verify alphabetical order
	first := result[0]
	last := result[len(result)-1]
	if !strings.Contains(first, "alpha") {
		t.Errorf("first = %q, expected to contain alpha", first)
	}
	if !strings.Contains(last, "zebra") {
		t.Errorf("last = %q, expected to contain zebra", last)
	}
}

func TestCountByProtocol(t *testing.T) {
	input := []string{
		"http://example.com",
		"https://other.com",
		"https://third.com",
	}
	counts := CountByProtocol(input)
	if counts["http"] != 1 {
		t.Errorf("expected 1 http, got %d", counts["http"])
	}
	if counts["https"] != 2 {
		t.Errorf("expected 2 https, got %d", counts["https"])
	}
}

func TestExtractHosts(t *testing.T) {
	input := []string{
		"http://example.com",
		"https://other.com",
		"http://example.com:8080",
	}
	hosts := ExtractHosts(input)
	if len(hosts) != 2 {
		t.Fatalf("expected 2 unique hosts, got %d", len(hosts))
	}
}

func TestExtractDomains(t *testing.T) {
	hosts := []string{
		"sub1.example.com",
		"sub2.example.com",
		"other.net",
	}
	domains := ExtractDomains(hosts)
	if len(domains) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(domains))
	}
}

func TestIsIPAddress(t *testing.T) {
	if !IsIPAddress("192.168.1.1") {
		t.Error("expected 192.168.1.1 to be IP")
	}
	if IsIPAddress("example.com") {
		t.Error("expected example.com to not be IP")
	}
	if !IsIPAddress("::1") {
		t.Error("expected ::1 to be IP")
	}
}

func TestSummary(t *testing.T) {
	input := []string{
		"http://example.com",
		"https://other.com",
	}
	s := Summary(input)
	if !strings.Contains(s, "2 个目标") {
		t.Errorf("unexpected summary: %s", s)
	}
}

func TestFilterByPort(t *testing.T) {
	input := []string{
		"http://example.com:8080",
		"http://other.com:80",
		"http://third.com:8080",
	}
	result := FilterByPort(input, "8080")
	if len(result) != 2 {
		t.Fatalf("expected 2 targets on port 8080, got %d", len(result))
	}
}

func TestFilterByDomain(t *testing.T) {
	input := []string{
		"http://sub1.example.com",
		"http://sub2.example.com",
		"http://other.com",
	}
	result := FilterByDomain(input, "example.com")
	if len(result) != 2 {
		t.Fatalf("expected 2 targets under example.com, got %d", len(result))
	}
}
