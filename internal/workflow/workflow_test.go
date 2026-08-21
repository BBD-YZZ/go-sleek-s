package workflow

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gosleek/gosleek/internal/config"
	"github.com/gosleek/gosleek/internal/httpclient"
	"github.com/gosleek/gosleek/internal/matcher"
	"github.com/gosleek/gosleek/internal/placeholder"
	"github.com/gosleek/gosleek/pkg/types"
)

// createTestWorkflowServer creates a mock HTTP server for workflow testing
func createTestWorkflowServer(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(handler)
}

func createTestWorkflowExecutor(verbose int) (*Executor, *httpclient.Client) {
	cfg := &config.GlobalConfig{
		DefaultTimeout: 5,
	}
	client := httpclient.New(httpclient.ClientConfig{
		Timeout: time.Duration(cfg.DefaultTimeout) * time.Second,
	})
	exec := New(client, cfg.DefaultTimeout, verbose, nil, nil, nil, nil, nil, nil, "")
	return exec, client
}

// TestExecuteHTTPWithRange verifies that Range correctly sends multiple requests
// and that the engine placeholder substitution runs AFTER range replacement.
func TestExecuteHTTPWithRange(t *testing.T) {
	requestCount := 0
	server := createTestWorkflowServer(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
		switch r.URL.Path {
		case "/api/test":
			w.Write([]byte(`{"result":"ok"}`))
		case "/api/token":
			// Simulate token extraction response
			w.Write([]byte(`<input name="csrf_token" value="abc123">`))
		default:
			w.Write([]byte(`ok`))
		}
	})
	defer server.Close()

	exec, _ := createTestWorkflowExecutor(0)

	tmpl := &types.Template{
		ID:   "test-range",
		Name: "Range Test",
		Workflow: []types.WorkflowStep{
			{
				Name: "test-step",
				HTTP: []types.HTTPRequest{
					{
						Raw: "GET /api/test?id={{id}} HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
						Range: &types.RangeConfig{
							Key: "id",
							Values: []string{"1", "2", "3"},
						},
						Matchers: []types.Matcher{
							{Type: "status", Status: []int{200}},
						},
					},
				},
			},
		},
	}

	matched, _, _ := exec.Execute(context.Background(), tmpl.Workflow, server.URL, placeholder.New(placeholder.ParseTarget(server.URL), nil))
	if !matched {
		t.Error("expected match")
	}
	if requestCount != 3 {
		t.Errorf("expected 3 requests, got %d", requestCount)
	}
}

// TestExecuteHTTPWithRangeAndExtractors verifies that extracted values (like
// csrf_token) are available for subsequent requests that use them via {{...}}.
func TestExecuteHTTPWithRangeAndExtractors(t *testing.T) {
	requestCount := 0
	server := createTestWorkflowServer(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		switch r.URL.Path {
		case "/api/token":
			w.Write([]byte(`<input name="csrf_token" value="secret-token-xyz">`))
		case "/api/submit":
			w.Write([]byte(`{"status":"submitted"}`))
		default:
			w.Write([]byte(`ok`))
		}
	})
	defer server.Close()

	exec, _ := createTestWorkflowExecutor(0)

	tmpl := &types.Template{
		ID:   "test-range-extract",
		Name: "Range + Extract Test",
		Workflow: []types.WorkflowStep{
			{
				Name: "get-token",
				HTTP: []types.HTTPRequest{
					{
						Raw: "GET /api/token HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
						Extractors: []types.Extractor{
							{
								Name:  "csrf_token",
								Type:  "regex",
								Regex: []string{`value="([A-Za-z0-9-]+)"`},
							},
						},
						Matchers: []types.Matcher{
							{Type: "status", Status: []int{200}},
						},
					},
				},
			},
			{
				Name:     "submit-form",
				Requires: []string{"get-token"},
				HTTP: []types.HTTPRequest{
					{
						Raw: "POST /api/submit HTTP/1.1\r\nHost: {{Hostname}}\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ncsrf_token={{csrf_token}}&data={{data}}",
						Range: &types.RangeConfig{
							Key: "data",
							Values: []string{"test", "hello", "world"},
						},
						Matchers: []types.Matcher{
							{Type: "status", Status: []int{200}},
						},
					},
				},
			},
		},
	}

	matched, _, ext := exec.Execute(context.Background(), tmpl.Workflow, server.URL, placeholder.New(placeholder.ParseTarget(server.URL), nil))
	if !matched {
		t.Error("expected match")
	}
	if ext["csrf_token"] != "secret-token-xyz" {
		t.Errorf("expected csrf_token=secret-token-xyz, got %q", ext["csrf_token"])
	}
	// 1 request for get-token + 3 requests for submit-form (range values)
	if requestCount != 4 {
		t.Errorf("expected 4 requests, got %d", requestCount)
	}
}

// TestExecuteHTTPWithRunIf verifies that run-if conditions correctly skip requests.
func TestExecuteHTTPWithRunIf(t *testing.T) {
	requestCount := 0
	server := createTestWorkflowServer(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		switch r.URL.Path {
		case "/api/login":
			w.Write([]byte(`<input name="csrf_token" value="token123">`))
		case "/api/submit":
			w.Write([]byte(`{"status":"ok"}`))
		default:
			w.Write([]byte(`ok`))
		}
	})
	defer server.Close()

	exec, _ := createTestWorkflowExecutor(0)

	tmpl := &types.Template{
		ID:   "test-run-if",
		Name: "Run-If Test",
		Workflow: []types.WorkflowStep{
			{
				Name: "get-token",
				HTTP: []types.HTTPRequest{
					{
						Raw: "GET /api/login HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
						Extractors: []types.Extractor{
							{
								Name:  "csrf_token",
								Type:  "regex",
								Regex: []string{`value="([A-Za-z0-9-]+)"`},
							},
						},
						Matchers: []types.Matcher{
							{Type: "status", Status: []int{200}},
						},
					},
				},
			},
			{
				Name:     "submit-with-token",
				Requires: []string{"get-token"},
				HTTP: []types.HTTPRequest{
					{
						Raw: "POST /api/submit HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
						RunIf: "len(csrf_token) > 0",
						Matchers: []types.Matcher{
							{Type: "status", Status: []int{200}},
						},
					},
				},
			},
		},
	}

	matched, _, ext := exec.Execute(context.Background(), tmpl.Workflow, server.URL, placeholder.New(placeholder.ParseTarget(server.URL), nil))
	if !matched {
		t.Error("expected match")
	}
	if ext["csrf_token"] != "token123" {
		t.Errorf("expected csrf_token=token123, got %q", ext["csrf_token"])
	}
	// Both steps should send requests: get-token (1) + submit-with-token (1) = 2
	if requestCount != 2 {
		t.Errorf("expected 2 requests, got %d", requestCount)
	}
}

// TestExecuteHTTPWithRunIfSkip verifies that run-if correctly skips when condition is false.
func TestExecuteHTTPWithRunIfSkip(t *testing.T) {
	requestCount := 0
	server := createTestWorkflowServer(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`ok`))
	})
	defer server.Close()

	exec, _ := createTestWorkflowExecutor(0)

	tmpl := &types.Template{
		ID:   "test-run-if-skip",
		Name: "Run-If Skip Test",
		Workflow: []types.WorkflowStep{
			{
				Name: "step1",
				HTTP: []types.HTTPRequest{
					{
						Raw: "GET /api/test HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
						Matchers: []types.Matcher{
							{Type: "status", Status: []int{200}},
						},
					},
				},
			},
			{
				Name: "step2-skip",
				HTTP: []types.HTTPRequest{
					{
						Raw:   "GET /api/skip HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
						RunIf: "len(nonexistent_var) > 0", // should be false
						Matchers: []types.Matcher{
							{Type: "status", Status: []int{200}},
						},
					},
				},
			},
		},
	}

	exec.Execute(context.Background(), tmpl.Workflow, server.URL, placeholder.New(placeholder.ParseTarget(server.URL), nil))
	// step1 runs, step2 is skipped because nonexistent_var is not set
	if requestCount != 1 {
		t.Errorf("expected 1 request, got %d", requestCount)
	}
}

// TestSubstituteMatcherPlaceholders verifies that {{...}} placeholders inside
// matcher string fields (Words/Regex/Header/Binary/JSONPath/JSONField) are
// replaced by the placeholder engine. This was a silent bug: matcher fields
// were never run through placeholder substitution, only req.Raw was, which
// caused OOB templates to search for the literal string "{{oob_label}}"
// instead of the actual label.
func TestSubstituteMatcherPlaceholders(t *testing.T) {
	ti := &placeholder.TargetInfo{BaseURL: "http://example.com", RootURL: "http://example.com", Hostname: "example.com", Host: "example.com", Port: "80", Scheme: "http"}
	eng := placeholder.New(ti, nil)
	eng.SetExtracted("oob_label", "gs-da94d1ae")
	eng.SetExtracted("oob_token", "deadbeef")

	matchers := []types.Matcher{
		{Type: "json-word", Words: []string{"{{oob_label}}"}, JSONPath: "data", JSONField: "name"},
		{Type: "word", Words: []string{"{{oob_label}}-suffix"}},
		{Type: "regex", Regex: []string{"{{oob_label}}"}},
		{Type: "header", Header: []string{"X-{{oob_label}}: yes"}},
	}

	out := matcher.SubstituterMatcherPlaceholders(matchers, eng)

	if out[0].Words[0] != "gs-da94d1ae" {
		t.Errorf("json-word words not replaced: got %q want %q", out[0].Words[0], "gs-da94d1ae")
	}
	if out[1].Words[0] != "gs-da94d1ae-suffix" {
		t.Errorf("word words not replaced: got %q want %q", out[1].Words[0], "gs-da94d1ae-suffix")
	}
	if out[2].Regex[0] != "gs-da94d1ae" {
		t.Errorf("regex not replaced: got %q want %q", out[2].Regex[0], "gs-da94d1ae")
	}
	if out[3].Header[0] != "X-gs-da94d1ae: yes" {
		t.Errorf("header not replaced: got %q", out[3].Header[0])
	}
	// non-string fields untouched
	if out[0].JSONPath != "data" || out[0].JSONField != "name" {
		t.Errorf("JSONPath/JSONField should be replaced even when literal: got %q/%q", out[0].JSONPath, out[0].JSONField)
	}
}

// TestRangeOrder verifies that Range values are substituted BEFORE placeholder
// engine resolves other {{...}} patterns. This ensures templates can use both
// {{key}} for range iteration AND {{Hostname}} for target resolution.
func TestRangeOrder(t *testing.T) {
	requestCount := 0
	var receivedURLs []string
	server := createTestWorkflowServer(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		receivedURLs = append(receivedURLs, r.RequestURI)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`ok`))
	})
	defer server.Close()

	exec, _ := createTestWorkflowExecutor(0)
	ti := placeholder.ParseTarget(server.URL)
	eng := placeholder.New(ti, nil)

	tmpl := &types.Template{
		ID:   "test-range-order",
		Name: "Range Order Test",
		Workflow: []types.WorkflowStep{
			{
				Name: "range-step",
				HTTP: []types.HTTPRequest{
					{
						Raw: "GET /api/search?q={{query}} HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
						Range: &types.RangeConfig{
							Key:    "query",
							Values: []string{"test1", "test2", "test3"},
						},
						Matchers: []types.Matcher{
							{Type: "status", Status: []int{200}},
						},
					},
				},
			},
		},
	}

	exec.Execute(context.Background(), tmpl.Workflow, server.URL, eng)
	if requestCount != 3 {
		t.Errorf("expected 3 requests, got %d", requestCount)
	}
	expected := []string{"/api/search?q=test1", "/api/search?q=test2", "/api/search?q=test3"}
	for i, exp := range expected {
		if receivedURLs[i] != exp {
			t.Errorf("request %d: got %q, want %q", i, receivedURLs[i], exp)
		}
	}
}

// TestEvalRunIf verifies the run-if evaluation logic.
func TestEvalRunIf(t *testing.T) {
	ti := placeholder.ParseTarget("http://example.com")
	eng := placeholder.New(ti, nil)

	tests := []struct {
		name      string
		extracted map[string]string
		expr      string
		want      bool
	}{
		{"positive_len", map[string]string{"token": "abc123"}, "len(token) > 0", true},
		{"zero_len", map[string]string{"token": ""}, "len(token) == 0", true},
		{"missing_var", map[string]string{}, "len(missing) > 0", false},
		{"unresolved", map[string]string{}, "len({{missing}}) > 0", false},
		{"literal_false", map[string]string{}, "false", false},
		{"literal_0", map[string]string{}, "0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evalRunIf(tt.expr, tt.extracted, eng)
			if got != tt.want {
				t.Errorf("evalRunIf(%q) = %v, want %v", tt.expr, got, tt.want)
			}
		})
	}
}

// TestRangeWithNoPlaceholderMatch verifies that when no placeholder matches
// any range value, the original request is still sent.
func TestRangeWithNoPlaceholderMatch(t *testing.T) {
	requestCount := 0
	server := createTestWorkflowServer(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`ok`))
	})
	defer server.Close()

	exec, _ := createTestWorkflowExecutor(0)
	eng := placeholder.New(placeholder.ParseTarget(server.URL), nil)

	tmpl := &types.Template{
		ID:   "test-range-no-match",
		Name: "Range No Match Test",
		Workflow: []types.WorkflowStep{
			{
				Name: "step",
				HTTP: []types.HTTPRequest{
					{
						Raw: "GET /api/test HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
						Range: &types.RangeConfig{
							Key:    "nonexistent_key",
							Values: []string{"a", "b"},
						},
						Matchers: []types.Matcher{
							{Type: "status", Status: []int{200}},
						},
					},
				},
			},
		},
	}

	exec.Execute(context.Background(), tmpl.Workflow, server.URL, eng)
	// Should still send 1 request (the original, since no placeholder matched)
	if requestCount != 1 {
		t.Errorf("expected 1 request, got %d", requestCount)
	}
}

// TestWorkflowWithExtractorsAcrossSteps verifies that extracted values from
// one step are available in subsequent steps.
func TestWorkflowWithExtractorsAcrossSteps(t *testing.T) {
	requestCount := 0
	var submittedData string
	server := createTestWorkflowServer(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		switch r.URL.Path {
		case "/api/login":
			// Return a form with a token
			w.Write([]byte(`<form><input name="csrf_token" value="secret123"></form>`))
		case "/api/submit":
			// Echo back submitted data
			buf := make([]byte, 1024)
			n, _ := r.Body.Read(buf)
			submittedData = string(buf[:n])
			w.Write([]byte(`{"status":"ok"}`))
		default:
			w.Write([]byte(`ok`))
		}
	})
	defer server.Close()

	exec, _ := createTestWorkflowExecutor(0)
	eng := placeholder.New(placeholder.ParseTarget(server.URL), nil)

	tmpl := &types.Template{
		ID:   "test-extract-across",
		Name: "Extract Across Steps",
		Workflow: []types.WorkflowStep{
			{
				Name: "extract",
				HTTP: []types.HTTPRequest{
					{
						Raw: "GET /api/login HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
						Extractors: []types.Extractor{
							{
								Name:  "csrf_token",
								Type:  "regex",
								Regex: []string{`value="([A-Za-z0-9-]+)"`},
							},
						},
						Matchers: []types.Matcher{
							{Type: "status", Status: []int{200}},
						},
					},
				},
			},
			{
				Name:     "submit",
				Requires: []string{"extract"},
				HTTP: []types.HTTPRequest{
					{
						Raw: "POST /api/submit HTTP/1.1\r\nHost: {{Hostname}}\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ncsrf_token={{csrf_token}}&data=test",
						Matchers: []types.Matcher{
							{Type: "status", Status: []int{200}},
						},
					},
				},
			},
		},
	}

	matched, _, ext := exec.Execute(context.Background(), tmpl.Workflow, server.URL, eng)
	if !matched {
		t.Error("expected match")
	}
	if requestCount != 2 {
		t.Errorf("expected 2 requests, got %d", requestCount)
	}
	if ext["csrf_token"] != "secret123" {
		t.Errorf("expected csrf_token=secret123, got %q", ext["csrf_token"])
	}
	// Verify the submitted data contains the extracted token
	if !strings.Contains(submittedData, "csrf_token=secret123") {
		t.Errorf("submitted data does not contain expected token: %q", submittedData)
	}
}
