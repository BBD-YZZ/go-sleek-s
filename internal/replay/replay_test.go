package replay

import (
	"strings"
	"testing"
)

func TestParseResponse(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, world!"
	resp := parseResponse(raw)
	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	if resp.Headers["Content-Type"][0] != "text/html" {
		t.Errorf("expected Content-Type text/html, got %v", resp.Headers["Content-Type"])
	}
	if resp.Body != "Hello, world!" {
		t.Errorf("expected body 'Hello, world!', got %q", resp.Body)
	}
}

func TestParseResponseMissingBody(t *testing.T) {
	raw := "HTTP/1.1 204 No Content\r\n\r\n"
	resp := parseResponse(raw)
	if resp.StatusCode != 204 {
		t.Errorf("expected status 204, got %d", resp.StatusCode)
	}
	if resp.Body != "" {
		t.Errorf("expected empty body, got %q", resp.Body)
	}
}

func TestDiffStrings(t *testing.T) {
	old := "line1\nline2\nline3\n"
	new := "line1\nchanged\nline3\n"
	result := diffStrings(old, new)
	if !strings.Contains(result, "- line2") {
		t.Errorf("expected diff to contain '- line2', got: %s", result)
	}
	if !strings.Contains(result, "+ changed") {
		t.Errorf("expected diff to contain '+ changed', got: %s", result)
	}
}

func TestDiffStringsIdentical(t *testing.T) {
	old := "same\nlines\n"
	new := "same\nlines\n"
	result := diffStrings(old, new)
	if result != "" {
		t.Errorf("expected empty diff for identical strings, got: %s", result)
	}
}

func TestDiffMap(t *testing.T) {
	old := map[string][]string{"Content-Type": {"text/html"}}
	new := map[string][]string{"Content-Type": {"application/json"}}
	result := diffMap(old, new)
	if !strings.Contains(result, "- Header: Content-Type") {
		t.Errorf("expected diff to contain removed header, got: %s", result)
	}
	if !strings.Contains(result, "+ Header: Content-Type") {
		t.Errorf("expected diff to contain added header, got: %s", result)
	}
}

func TestDiffMapEmpty(t *testing.T) {
	old := map[string][]string{"X-Test": {"value"}}
	new := map[string][]string{"X-Test": {"value"}}
	result := diffMap(old, new)
	if result != "" {
		t.Errorf("expected empty diff for identical maps, got: %s", result)
	}
}

func TestHTTPStatusText(t *testing.T) {
	if httpStatusText(200) != "OK" {
		t.Errorf("expected 'OK', got %s", httpStatusText(200))
	}
	if httpStatusText(404) != "Not Found" {
		t.Errorf("expected 'Not Found', got %s", httpStatusText(404))
	}
	if httpStatusText(999) != "999" {
		t.Errorf("expected '999', got %s", httpStatusText(999))
	}
}
