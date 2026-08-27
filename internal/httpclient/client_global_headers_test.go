package httpclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestClientInjectGlobalHeaders tests that global headers are injected into
// raw request text before parsing, so they appear in -vv output.
func TestClientInjectGlobalHeaders(t *testing.T) {
	var receivedHeaders map[string]string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := make(map[string]string)
		for k, v := range r.Header {
			h[k] = strings.Join(v, ", ")
		}
		receivedHeaders = h
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	serverHost := server.URL
	if idx := strings.Index(serverHost, "://"); idx >= 0 {
		serverHost = serverHost[idx+3:]
	}
	if idx := strings.Index(serverHost, "/"); idx >= 0 {
		serverHost = serverHost[:idx]
	}

	client := New(ClientConfig{
		Timeout:       5,
		UserAgent:     "gosleek-test-ua",
		AllowExternal: true,
	})
	client.SetGlobalHeaders(map[string]string{
		"X-Custom-Header": "cli-value",
	})

	// Test with raw template that has NO \r\n\r\n separator
	rawReq := "GET /test HTTP/1.1\r\nHost: " + serverHost + "\r\n"
	resp, err := client.SendRaw(context.Background(), server.URL, rawReq)
	if err != nil {
		t.Fatalf("SendRaw failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	// Verify server received the global header
	if receivedHeaders["X-Custom-Header"] != "cli-value" {
		t.Errorf("global header not sent: expected 'cli-value', got %q", receivedHeaders["X-Custom-Header"])
	}

	// Verify server received config user-agent
	if receivedHeaders["User-Agent"] != "gosleek-test-ua" {
		t.Errorf("config user-agent not sent: expected 'gosleek-test-ua', got %q", receivedHeaders["User-Agent"])
	}

	// Verify InjectGlobalHeaders puts CLI headers in the right place
	injected := client.InjectGlobalHeaders(rawReq)
	if !strings.Contains(injected, "X-Custom-Header: cli-value") {
		t.Errorf("global header not in InjectGlobalHeaders text: %q", injected)
	}
	// User-Agent is injected by injectConfigUserAgent in SendParsed, not by InjectGlobalHeaders
	// Verify that SendParsed adds User-Agent by checking the injected raw text
	// (this is done by sending the raw text through ParseRaw + SendParsed)
	parsed, _ := ParseRaw(injected)
	c := New(ClientConfig{UserAgent: "gosleek-test-ua"})
	c.SetGlobalHeaders(map[string]string{"X-Custom-Header": "cli-value"})
	c.injectConfigUserAgent(parsed)
	uaVal, ok := parsed.Headers["User-Agent"]
	if !ok || uaVal != "gosleek-test-ua" {
		t.Errorf("injectConfigUserAgent failed: got %q", uaVal)
	}

	t.Logf("Injected raw text:\n%s", injected)
	t.Logf("Server received headers: %+v", receivedHeaders)
}

// TestClientInjectGlobalHeadersWithBody tests injection when template has \r\n\r\n separator
func TestClientInjectGlobalHeadersWithBody(t *testing.T) {
	var receivedHeaders map[string]string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := make(map[string]string)
		for k, v := range r.Header {
			h[k] = strings.Join(v, ", ")
		}
		receivedHeaders = h
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	serverHost := server.URL
	if idx := strings.Index(serverHost, "://"); idx >= 0 {
		serverHost = serverHost[idx+3:]
	}
	if idx := strings.Index(serverHost, "/"); idx >= 0 {
		serverHost = serverHost[:idx]
	}

	client := New(ClientConfig{
		Timeout:       5,
		UserAgent:     "gosleek-test-ua",
		AllowExternal: true,
	})
	client.SetGlobalHeaders(map[string]string{
		"X-Custom-Header": "cli-value",
	})

	// Test with raw template that HAS \r\n\r\n separator
	rawReq := "GET /test HTTP/1.1\r\nHost: " + serverHost + "\r\n\r\n"
	_, err := client.SendRaw(context.Background(), server.URL, rawReq)
	if err != nil {
		t.Fatalf("SendRaw failed: %v", err)
	}

	// Verify server received the global header
	if receivedHeaders["X-Custom-Header"] != "cli-value" {
		t.Errorf("global header not sent: expected 'cli-value', got %q", receivedHeaders["X-Custom-Header"])
	}

	// Verify injected text has header BEFORE the \r\n\r\n separator
	injected := client.InjectGlobalHeaders(rawReq)
	lastSepIdx := strings.LastIndex(injected, "\r\n\r\n")
	if lastSepIdx < 0 {
		t.Fatalf("no header/body separator found in injected text")
	}
	beforeSep := injected[:lastSepIdx]
	if !strings.Contains(beforeSep, "X-Custom-Header: cli-value") {
		t.Errorf("X-Custom header must be before the blank line separator, got: %q", injected)
	}

	t.Logf("Injected raw text:\n%s", injected)
	t.Logf("Server received headers: %+v", receivedHeaders)
}
