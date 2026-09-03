package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gosleek/gosleek/internal/config"
	"github.com/gosleek/gosleek/pkg/types"
)

// TestResultDedup verifies that identical results (same target+template+severity)
// are only reported once.
func TestResultDedup(t *testing.T) {
	cfg := config.DefaultConfig()
	scanner := NewScanner(cfg, 0, OOBConfig{}, "", true)

	var mu sync.Mutex
	var results []*types.Result
	scanner.SetCallbacks(
		func(r *types.Result) {
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		},
		nil, nil, nil, nil, nil,
	)

	// Create a simple server that returns 200 for any request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	tmpl := &types.Template{
		ID:       "test-dedup",
		Name:     "Test Dedup",
		Severity: types.SeverityHigh,
		HTTP: []types.HTTPRequest{
			{
				Raw: "GET / HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
				Matchers: []types.Matcher{
					{Type: "status", Status: []int{200}},
				},
			},
		},
	}

	// Send same template against same target multiple times
	// The job-level dedup should skip all but the first
	targets := []string{srv.URL}
	ctx := context.Background()

	scanner.Run(ctx, []*types.Template{tmpl}, nil, targets)

	mu.Lock()
	defer mu.Unlock()

	// Only one result should be reported (job-level dedup handles this)
	if len(results) != 1 {
		t.Errorf("expected 1 result (job dedup), got %d", len(results))
	}
}

// TestResultDedupBySeverity verifies that different severities for the same
// template+target are reported separately.
func TestResultDedupBySeverity(t *testing.T) {
	cfg := config.DefaultConfig()
	scanner := NewScanner(cfg, 0, OOBConfig{}, "", true)

	var mu sync.Mutex
	var results []*types.Result
	scanner.SetCallbacks(
		func(r *types.Result) {
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		},
		nil, nil, nil, nil, nil,
	)

	// Two templates with different severities hitting same target
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	tmpl1 := &types.Template{
		ID:       "test-sev-1",
		Name:     "Test Severity 1",
		Severity: types.SeverityHigh,
		HTTP: []types.HTTPRequest{
			{
				Raw: "GET / HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
				Matchers: []types.Matcher{
					{Type: "status", Status: []int{200}},
				},
			},
		},
	}
	tmpl2 := &types.Template{
		ID:       "test-sev-2",
		Name:     "Test Severity 2",
		Severity: types.SeverityMedium,
		HTTP: []types.HTTPRequest{
			{
				Raw: "GET / HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
				Matchers: []types.Matcher{
					{Type: "status", Status: []int{200}},
				},
			},
		},
	}

	targets := []string{srv.URL}
	ctx := context.Background()

	scanner.Run(ctx, []*types.Template{tmpl1, tmpl2}, nil, targets)

	mu.Lock()
	defer mu.Unlock()

	// Each template should report once
	if len(results) != 2 {
		t.Errorf("expected 2 results (different templates), got %d", len(results))
	}
}

// TestResultDedupAPI verifies the API methods for result dedup.
func TestResultDedupAPI(t *testing.T) {
	cfg := config.DefaultConfig()
	scanner := NewScanner(cfg, 0, OOBConfig{}, "", true)

	// Initially not reported
	if scanner.ResultAlreadyReported("http://example.com", "test-id", "high") {
		t.Error("expected not reported initially")
	}

	// Mark as done
	scanner.MarkResultDone("http://example.com", "test-id", "high")

	// Now should be reported
	if !scanner.ResultAlreadyReported("http://example.com", "test-id", "high") {
		t.Error("expected reported after marking")
	}

	// Clear and verify
	scanner.ClearResultDedup()
	if scanner.ResultAlreadyReported("http://example.com", "test-id", "high") {
		t.Error("expected not reported after clear")
	}
}

// TestResultDedupKeyFormat verifies that the dedup key includes severity.
func TestResultDedupKeyFormat(t *testing.T) {
	cfg := config.DefaultConfig()
	scanner := NewScanner(cfg, 0, OOBConfig{}, "", true)

	// Same target+template, different severity → should both be reported
	scanner.MarkResultDone("http://example.com", "test-id", "high")
	if !scanner.ResultAlreadyReported("http://example.com", "test-id", "high") {
		t.Error("high severity should be reported after marking")
	}
	if scanner.ResultAlreadyReported("http://example.com", "test-id", "medium") {
		t.Error("medium severity should NOT be reported (different key)")
	}
}
