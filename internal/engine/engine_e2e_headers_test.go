package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gosleek/gosleek/internal/config"
	"github.com/gosleek/gosleek/pkg/types"
)

// TestExecuteHTTPWithGlobalHeaders tests that -H headers are actually sent
func TestExecuteHTTPWithGlobalHeaders(t *testing.T) {
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

	cfg := &config.GlobalConfig{
		DefaultTimeout: 5,
		UserAgent:      "gosleek-test-ua",
	}
	scanner := NewScanner(cfg, 2, OOBConfig{}, "", false)
	scanner.SetGlobalHeaders(map[string]string{
		"X-Test-Header":   "cli-value",
		"Authorization":   "Bearer cli-token",
	})

	tmpl := &types.Template{
		ID:          "test-global-headers",
		Name:        "Global Headers Test",
		Description: "Test global header injection",
		Severity:    "info",
		HTTP: []types.HTTPRequest{
			{
				Raw: "GET /test HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
				Matchers: []types.Matcher{
					{
						Type:   "status",
						Status: []int{200},
					},
				},
			},
		},
	}

	scanner.Run(context.Background(), []*types.Template{tmpl}, nil, []string{server.URL})

	if receivedHeaders == nil {
		t.Fatal("no request received")
	}

	// Verify global headers were sent
	for key, expected := range map[string]string{
		"X-Test-Header": "cli-value",
		"Authorization": "Bearer cli-token",
	} {
		actual := receivedHeaders[key]
		if actual != expected {
			t.Errorf("header %s: expected %q, got %q", key, expected, actual)
		}
	}

	// Verify User-Agent from config
	ua := receivedHeaders["User-Agent"]
	if !strings.Contains(ua, "gosleek-test-ua") {
		t.Errorf("User-Agent should contain 'gosleek-test-ua', got %q", ua)
	}

	t.Logf("Received headers: %+v", receivedHeaders)
}
