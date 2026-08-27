package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gosleek/gosleek/internal/config"
	"github.com/gosleek/gosleek/internal/httpclient"
	"github.com/gosleek/gosleek/pkg/types"
)

// TestGlobalHeadersWithoutBodySeparator tests header injection when template has no body separator
func TestGlobalHeadersWithoutBodySeparator(t *testing.T) {
	var receivedHeaders map[string]string
	var requestCount int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		h := make(map[string]string)
		for k, v := range r.Header {
			h[k] = strings.Join(v, ", ")
		}
		receivedHeaders = h
		fmt.Printf("Request #%d received headers: %+v\n", requestCount, h)
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
		"X-Custom-Header": "cli-value",
	})

	// Template WITHOUT \r\n\r\n separator (like xss-reflected-stored.yaml)
	tmpl := &types.Template{
		ID:          "test-no-separator",
		Name:        "No Separator Test",
		Description: "Test without body separator",
		Severity:    "info",
		HTTP: []types.HTTPRequest{
			{
				Raw: "GET /test HTTP/1.1\r\nHost: {{Hostname}}\r\n",
				Matchers: []types.Matcher{
					{Type: "status", Status: []int{200}},
				},
			},
		},
	}

	// Debug: Check what injectGlobalHeaders produces
	rawReq := tmpl.HTTP[0].Raw
	fmt.Printf("Original raw: %q\n", rawReq)
	fmt.Printf("Original has \r\n\r\n: %v\n", strings.Contains(rawReq, "\r\n\r\n"))
	
	injected := scanner.client.InjectGlobalHeaders(rawReq)
	fmt.Printf("Injected raw: %q\n", injected)
	fmt.Printf("Injected has \r\n\r\n: %v\n", strings.Contains(injected, "\r\n\r\n"))
	
	// Parse the injected request
	parsed, err := httpclient.ParseRaw(injected)
	if err != nil {
		t.Fatalf("ParseRaw failed: %v", err)
	}
	fmt.Printf("Parsed headers: %+v\n", parsed.Headers)

	results := scanner.Run(context.Background(), []*types.Template{tmpl}, nil, []string{server.URL})
	fmt.Printf("Results: %d\n", len(results))
	fmt.Printf("Request count: %d\n", requestCount)

	if receivedHeaders == nil {
		t.Fatal("no request received")
	}

	actual := receivedHeaders["X-Custom-Header"]
	if actual != "cli-value" {
		t.Errorf("header not injected! Expected %q, got %q. All headers: %+v", "cli-value", actual, receivedHeaders)
	} else {
		fmt.Printf("SUCCESS: Header was injected correctly\n")
	}
}
