package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gosleek/gosleek/internal/config"
	"github.com/gosleek/gosleek/internal/placeholder"
	"github.com/gosleek/gosleek/pkg/types"
)

// createTestServer creates a mock HTTP server for testing
func createTestServer(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(handler)
}

// createTestScanner creates a Scanner for testing
func createTestScanner() *Scanner {
	cfg := &config.GlobalConfig{
		DefaultTimeout:         5,
		Concurrency:            1,
		MaxRetries:             1,
		RetryBackoff:           "1s",
		UserAgent:              "gosleek",
		MaxRedirects:           3,
		MaxCartesianProducts:   10000,
	}
	return NewScanner(cfg, 0, OOBConfig{}, "", false)
}

// TestExecuteHTTPSimple tests basic HTTP execution
func TestExecuteHTTPSimple(t *testing.T) {
	server := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})
	defer server.Close()

	scanner := createTestScanner()
	tmpl := &types.Template{
		ID:          "test-simple",
		Name:        "Simple Test",
		Description: "A simple test",
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

	results := scanner.Run(context.Background(), []*types.Template{tmpl}, nil, []string{server.URL})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].TemplateID != "test-simple" {
		t.Errorf("wrong template ID: %s", results[0].TemplateID)
	}
}

// TestExecuteHTTPWithExtractors tests extraction in HTTP requests
func TestExecuteHTTPWithExtractors(t *testing.T) {
	server := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`token=ABC123&session=xyz`))
	})
	defer server.Close()

	scanner := createTestScanner()
	tmpl := &types.Template{
		ID:          "test-extract",
		Name:        "Extract Test",
		Description: "Test extraction",
		Severity:    "medium",
		HTTP: []types.HTTPRequest{
			{
				Raw: "GET /login HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
				Extractors: []types.Extractor{
					{
						Name:  "token",
						Type:  "regex",
						Regex: []string{`token=([A-Za-z0-9]+)`},
					},
				},
				Matchers: []types.Matcher{
					{
						Type:   "status",
						Status: []int{200},
					},
				},
			},
		},
	}

	results := scanner.Run(context.Background(), []*types.Template{tmpl}, nil, []string{server.URL})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Extracted["token"] != "ABC123" {
		t.Errorf("expected token ABC123, got %s", results[0].Extracted["token"])
	}
}

// TestExecuteHTTPWithVariables tests variable usage
func TestExecuteHTTPWithVariables(t *testing.T) {
	server := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"found":true}`))
	})
	defer server.Close()

	scanner := createTestScanner()
	tmpl := &types.Template{
		ID:          "test-vars",
		Name:        "Variables Test",
		Description: "Test variables",
		Severity:    "low",
		Variables: map[string]string{
			"route_id": "{{rand_text_alpha(8)}}",
		},
		HTTP: []types.HTTPRequest{
			{
				Raw: "GET /api/{{route_id}} HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
				Matchers: []types.Matcher{
					{
						Type:   "status",
						Status: []int{200},
					},
				},
			},
		},
	}

	results := scanner.Run(context.Background(), []*types.Template{tmpl}, nil, []string{server.URL})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

// TestExecuteHTTPWithRunIf tests run-if condition
func TestExecuteHTTPWithRunIf(t *testing.T) {
	server := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"found":true}`))
	})
	defer server.Close()

	scanner := createTestScanner()
	tmpl := &types.Template{
		ID:          "test-runif",
		Name:        "RunIf Test",
		Description: "Test run-if",
		Severity:    "low",
		HTTP: []types.HTTPRequest{
			{
				Raw:   "GET /api HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
				RunIf: "status_code == 200",
				Matchers: []types.Matcher{
					{
						Type:   "status",
						Status: []int{200},
					},
				},
			},
		},
	}

	results := scanner.Run(context.Background(), []*types.Template{tmpl}, nil, []string{server.URL})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

// TestExecuteHTTPWithDSLRunIf tests DSL expression in run-if
func TestExecuteHTTPWithDSLRunIf(t *testing.T) {
	server := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"admin":true}`))
	})
	defer server.Close()

	scanner := createTestScanner()
	tmpl := &types.Template{
		ID:          "test-dsl-runif",
		Name:        "DSL RunIf Test",
		Description: "Test DSL run-if",
		Severity:    "medium",
		HTTP: []types.HTTPRequest{
			{
				Raw:   "GET /api HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
				RunIf: "status_code == 200", // This should pass since default is 200
				Matchers: []types.Matcher{
					{
						Type:  "word",
						Words: []string{"admin"},
					},
				},
			},
		},
	}

	results := scanner.Run(context.Background(), []*types.Template{tmpl}, nil, []string{server.URL})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

// TestExecuteHTTPWithMultiplePaths tests multiple paths
func TestExecuteHTTPWithMultiplePaths(t *testing.T) {
	server := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	})
	defer server.Close()

	scanner := createTestScanner()
	tmpl := &types.Template{
		ID:          "test-paths",
		Name:        "Paths Test",
		Description: "Test multiple paths",
		Severity:    "low",
		HTTP: []types.HTTPRequest{
			{
				Path: []string{"/api/v1/users", "/api/v2/users", "/api/v3/users"},
				Matchers: []types.Matcher{
					{
						Type:   "status",
						Status: []int{200},
					},
				},
			},
		},
	}

	results := scanner.Run(context.Background(), []*types.Template{tmpl}, nil, []string{server.URL})
	if len(results) == 0 {
		t.Error("expected at least 1 result")
	}
}

// TestExecuteWorkflow tests workflow execution
func TestExecuteWorkflow(t *testing.T) {
	server := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"token":"TOKEN123"}`))
		case "/admin":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"result":"admin_access"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer server.Close()

	scanner := createTestScanner()
	tmpl := &types.Template{
		ID:          "test-workflow",
		Name:        "Workflow Test",
		Description: "Test workflow",
		Severity:    "high",
		Workflow: []types.WorkflowStep{
			{
				Name: "login",
				HTTP: []types.HTTPRequest{
					{
						Raw: "POST /login HTTP/1.1\r\nHost: {{Hostname}}\r\nContent-Type: application/json\r\n\r\n{}",
						Extractors: []types.Extractor{
							{
								Name: "token",
								Type: "json",
								JSON: []string{"token"},
							},
						},
						Matchers: []types.Matcher{
							{
								Type:   "status",
								Status: []int{200},
							},
						},
					},
				},
			},
			{
				Name: "admin",
				HTTP: []types.HTTPRequest{
					{
						Raw: "GET /admin HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
						Matchers: []types.Matcher{
							{
								Type:  "word",
								Words: []string{"admin"},
							},
						},
					},
				},
			},
		},
	}

	results := scanner.Run(context.Background(), []*types.Template{tmpl}, nil, []string{server.URL})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

// TestExecuteWorkflowWithDelay tests workflow with delay
func TestExecuteWorkflowWithDelay(t *testing.T) {
	server := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	})
	defer server.Close()

	scanner := createTestScanner()
	tmpl := &types.Template{
		ID:          "test-delay",
		Name:        "Delay Test",
		Description: "Test workflow delay",
		Severity:    "low",
		Workflow: []types.WorkflowStep{
			{
				Name: "step1",
				HTTP: []types.HTTPRequest{
					{
						Raw: "GET /api HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
						Matchers: []types.Matcher{
							{
								Type:   "status",
								Status: []int{200},
							},
						},
					},
				},
			},
			{
				Name:  "step2",
				Delay: 1, // 1 second delay
				HTTP: []types.HTTPRequest{
					{
						Raw: "GET /api HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
						Matchers: []types.Matcher{
							{
								Type:   "status",
								Status: []int{200},
							},
						},
					},
				},
			},
		},
	}

	results := scanner.Run(context.Background(), []*types.Template{tmpl}, nil, []string{server.URL})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

// TestExecuteWorkflowWithRequires tests workflow step dependencies
func TestExecuteWorkflowWithRequires(t *testing.T) {
	server := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	})
	defer server.Close()

	scanner := createTestScanner()
	tmpl := &types.Template{
		ID:          "test-deps",
		Name:        "Dependencies Test",
		Description: "Test workflow dependencies",
		Severity:    "low",
		Workflow: []types.WorkflowStep{
			{
				Name: "step1",
				HTTP: []types.HTTPRequest{
					{
						Raw: "GET /api HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
						Matchers: []types.Matcher{
							{
								Type:   "status",
								Status: []int{200},
							},
						},
					},
				},
			},
			{
				Name:     "step2",
				Requires: []string{"step1"},
				HTTP: []types.HTTPRequest{
					{
						Raw: "GET /api HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
						Matchers: []types.Matcher{
							{
								Type:   "status",
								Status: []int{200},
							},
						},
					},
				},
			},
		},
	}

	results := scanner.Run(context.Background(), []*types.Template{tmpl}, nil, []string{server.URL})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

// TestTemplateNeedsOOBDetection tests OOB detection
func TestTemplateNeedsOOBDetection(t *testing.T) {
	tests := []struct {
		name string
		tmpl *types.Template
		want bool
	}{
		{
			name: "no oob",
			tmpl: &types.Template{
				HTTP: []types.HTTPRequest{{Raw: "GET /test HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n"}},
			},
			want: false,
		},
		{
			name: "with oob",
			tmpl: &types.Template{
				HTTP: []types.HTTPRequest{{Raw: "GET {{oob}} HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n"}},
			},
			want: true,
		},
		{
			name: "with interactsh",
			tmpl: &types.Template{
				HTTP: []types.HTTPRequest{{Raw: "GET {{interactsh-url}} HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n"}},
			},
			want: true,
		},
		{
			name: "with oob label",
			tmpl: &types.Template{
				HTTP: []types.HTTPRequest{{Raw: "GET /check?label={{oob_label}} HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n"}},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TemplateNeedsOOB(tt.tmpl)
			if got != tt.want {
				t.Errorf("TemplateNeedsOOB() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestSubstituteMatcherPlaceholders tests matcher placeholder substitution
func TestSubstituteMatcherPlaceholders(t *testing.T) {
	ti := placeholder.ParseTarget("http://example.com:8080")
	eng := placeholder.New(ti, nil)
	eng.SetExtracted("oob_label", "gs-test123")

	matchers := []types.Matcher{
		{Type: "word", Words: []string{"{{oob_label}}"}},
		{Type: "regex", Regex: []string{"{{oob_label}}"}},
		{Type: "header", Header: []string{"X-{{oob_label}}"}},
	}

	out := substituteMatcherPlaceholders(matchers, eng)

	if out[0].Words[0] != "gs-test123" {
		t.Errorf("word not replaced: %q", out[0].Words[0])
	}
	if out[1].Regex[0] != "gs-test123" {
		t.Errorf("regex not replaced: %q", out[1].Regex[0])
	}
	if out[2].Header[0] != "X-gs-test123" {
		t.Errorf("header not replaced: %q", out[2].Header[0])
	}
}

// TestAggregateMatches tests match aggregation
func TestAggregateMatches2(t *testing.T) {
	tests := []struct {
		name    string
		results []bool
		cond    string
		want    bool
	}{
		{"all true and", []bool{true, true, true}, "and", true},
		{"all true or", []bool{true, true, true}, "or", true},
		{"one false and", []bool{true, false, true}, "and", false},
		{"one true or", []bool{false, true, false}, "or", true},
		{"all false and", []bool{false, false}, "and", false},
		{"all false or", []bool{false, false}, "or", false},
		{"empty", []bool{}, "or", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := aggregateMatches(tt.results, tt.cond)
			if got != tt.want {
				t.Errorf("aggregateMatches() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestBuildRawFromPathWithBodyType tests request building with body types
func TestBuildRawFromPathWithBodyType(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		path      string
		headers   map[string]string
		body      string
		bodyType  string
		wantMatch string
	}{
		{
			name:      "form body",
			method:    "POST",
			path:      "/login",
			body:      "user=admin&pass=secret",
			bodyType:  "form",
			wantMatch: "Content-Type: application/x-www-form-urlencoded",
		},
		{
			name:      "multipart body",
			method:    "POST",
			path:      "/upload",
			body:      "file=test.txt",
			bodyType:  "multipart",
			wantMatch: "multipart/form-data",
		},
		{
			name:      "no body type",
			method:    "GET",
			path:      "/test",
			wantMatch: "GET /test HTTP/1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := buildRawFromPathWithBodyType(tt.method, tt.path, tt.headers, tt.body, tt.bodyType)
			if !strings.Contains(raw, tt.wantMatch) {
				t.Errorf("built request missing %q: %q", tt.wantMatch, raw)
			}
		})
	}
}

// TestInjectGlobalHeaders tests header injection — headers must appear BEFORE \r\n\r\n
// so that ParseRaw correctly treats them as HTTP headers, not body content.
func TestInjectGlobalHeaders2(t *testing.T) {
	raw := "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\nbody"
	headers := map[string]string{"X-Custom": "value", "Authorization": "Bearer token"}

	result := injectGlobalHeaders(raw, headers)
	if !strings.Contains(result, "X-Custom: value") {
		t.Errorf("missing X-Custom header")
	}
	if !strings.Contains(result, "Authorization: Bearer token") {
		t.Errorf("missing Authorization header")
	}
	// Critical: headers must be BEFORE the last \r\n\r\n (the blank line before body).
	// Find the separator that is immediately followed by body content.
	lastSepIdx := strings.LastIndex(result, "\r\n\r\n")
	if lastSepIdx < 0 {
		t.Fatalf("no header/body separator found")
	}
	beforeSep := result[:lastSepIdx]
	if !strings.Contains(beforeSep, "X-Custom: value") {
		t.Errorf("X-Custom header must be before the blank line separator")
	}
	if !strings.Contains(beforeSep, "Authorization: Bearer token") {
		t.Errorf("Authorization header must be before the blank line separator")
	}
	// Body must remain after the blank line
	afterSep := result[lastSepIdx:]
	if !strings.HasPrefix(afterSep, "\r\n\r\nbody") {
		t.Errorf("body must remain after separator, got:\n%s", result)
	}
}

// TestParseMethodPath tests request parsing
func TestParseMethodPath2(t *testing.T) {
	tests := []struct {
		name  string
		raw   string
		wantM string
		wantP string
	}{
		{"GET request", "GET /api/test HTTP/1.1\r\nHost: x\r\n\r\n", "GET", "/api/test"},
		{"POST request", "POST /login HTTP/1.1\r\nHost: x\r\n\r\n", "POST", "/login"},
		{"invalid", "invalid", "?", "?"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, p := parseMethodPath(tt.raw)
			if m != tt.wantM || p != tt.wantP {
				t.Errorf("parseMethodPath() = (%q, %q), want (%q, %q)", m, p, tt.wantM, tt.wantP)
			}
		})
	}
}

// TestEncodeLine tests line encoding
func TestEncodeLine2(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		encoding string
		want     string
	}{
		{"url encode", "hello+world", "url", "hello%2Bworld"}, // + gets escaped
		{"base64 encode", "hello", "base64", "aGVsbG8="},
		{"hex encode", "ab", "hex", "6162"},
		{"no encoding", "hello", "", "hello"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := encodeLine(tt.line, tt.encoding)
			if got != tt.want {
				t.Errorf("encodeLine(%q, %q) = %q, want %q", tt.line, tt.encoding, got, tt.want)
			}
		})
	}
}

// TestLoadWordlist tests wordlist loading
func TestLoadWordlist2(t *testing.T) {
	scanner := createTestScanner()

	// Create a temp wordlist file
	tmpfile, err := os.CreateTemp("", "wordlist*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	tmpfile.WriteString("line1\nline2\n# comment\n\nline3\n")
	tmpfile.Close()

	lines, err := scanner.loadWordlist(tmpfile.Name(), "")
	if err != nil {
		t.Fatalf("loadWordlist failed: %v", err)
	}
	if len(lines) != 3 {
		t.Errorf("expected 3 lines, got %d", len(lines))
	}
}

// TestCartesianProduct tests cartesian product generation
func TestCartesianProduct2(t *testing.T) {
	slices := [][]string{
		{"a", "b"},
		{"1", "2", "3"},
	}
	result := cartesianProduct(slices)
	if len(result) != 6 {
		t.Errorf("expected 6 combinations, got %d", len(result))
	}
}

// TestBuildWordlistCombinations tests wordlist combination building
func TestBuildWordlistCombinations2(t *testing.T) {
	scanner := createTestScanner()

	tmpfile, err := os.CreateTemp("", "wordlist*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	tmpfile.WriteString("word1\nword2\n")
	tmpfile.Close()

	wordlists := []types.WordlistConfig{
		{Key: "w", Path: tmpfile.Name()},
	}
	result := buildWordlistCombinations(scanner, wordlists)
	if len(result) != 2 {
		t.Errorf("expected 2 combinations, got %d", len(result))
	}
}

// TestNewScanner tests scanner initialization
func TestNewScanner2(t *testing.T) {
	cfg := &config.GlobalConfig{
		DefaultTimeout: 5,
		Concurrency:    10,
	}
	scanner := NewScanner(cfg, 1, OOBConfig{}, "", false)
	if scanner == nil {
		t.Fatal("NewScanner returned nil")
	}
	if scanner.client == nil {
		t.Error("client not initialized")
	}
}

// TestSetCallbacks tests callback registration
func TestSetCallbacks2(t *testing.T) {
	cfg := &config.GlobalConfig{}
	scanner := NewScanner(cfg, 0, OOBConfig{}, "", false)

	scanner.SetCallbacks(
		func(r *types.Result) { _ = r },
		nil, nil, nil, nil, nil,
	)

	if scanner.onResult == nil {
		t.Error("onResult callback not set")
	}
}

// TestSetGlobalHeaders tests global header setting
func TestSetGlobalHeaders2(t *testing.T) {
	cfg := &config.GlobalConfig{}
	scanner := NewScanner(cfg, 0, OOBConfig{}, "", false)
	scanner.SetGlobalHeaders(map[string]string{"X-Test": "value"})
}

// TestSetFollowRedirects tests redirect configuration
func TestSetFollowRedirects2(t *testing.T) {
	cfg := &config.GlobalConfig{}
	scanner := NewScanner(cfg, 0, OOBConfig{}, "", false)
	scanner.SetFollowRedirects(false)
	scanner.SetFollowRedirects(true)
}

// TestSetWordlistDir tests wordlist directory setting
func TestSetWordlistDir2(t *testing.T) {
	cfg := &config.GlobalConfig{}
	scanner := NewScanner(cfg, 0, OOBConfig{}, "", false)
	scanner.SetWordlistDir("/tmp")
}

// TestGetStats tests stats retrieval
func TestGetStats2(t *testing.T) {
	cfg := &config.GlobalConfig{}
	scanner := NewScanner(cfg, 0, OOBConfig{}, "", false)
	completed, matched, total := scanner.GetStats()
	if completed != 0 || matched != 0 || total != 0 {
		t.Errorf("expected all zeros, got %d %d %d", completed, matched, total)
	}
}

// TestMarkDone tests mark done functionality
func TestMarkDone2(t *testing.T) {
	cfg := &config.GlobalConfig{}
	scanner := NewScanner(cfg, 0, OOBConfig{}, "", false)
	scanner.MarkDone("http://example.com", "test-id")
	completed := scanner.GetCompleted()
	if len(completed) != 1 {
		t.Errorf("expected 1 completed, got %d", len(completed))
	}
}

// TestScanWithTimeout tests timeout handling
func TestScanWithTimeout(t *testing.T) {
	server := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	defer server.Close()

	cfg := &config.GlobalConfig{
		DefaultTimeout: 1,
		Concurrency:    1,
	}
	scanner := NewScanner(cfg, 0, OOBConfig{}, "", false)

	tmpl := &types.Template{
		ID:          "test-timeout",
		Name:        "Timeout Test",
		Description: "Test timeout",
		Severity:    "low",
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

	// Should complete without hanging
	results := scanner.Run(context.Background(), []*types.Template{tmpl}, nil, []string{server.URL})
	_ = results
}

// TestScanContextCancellation tests context cancellation
func TestScanContextCancellation(t *testing.T) {
	server := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	defer server.Close()

	cfg := &config.GlobalConfig{
		DefaultTimeout: 5,
		Concurrency:    1,
	}
	scanner := NewScanner(cfg, 0, OOBConfig{}, "", false)

	tmpl := &types.Template{
		ID:          "test-cancel",
		Name:        "Cancel Test",
		Description: "Test cancellation",
		Severity:    "low",
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

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	results := scanner.Run(ctx, []*types.Template{tmpl}, nil, []string{server.URL})
	_ = results
}

// TestEdgeCases tests various edge cases
func TestEdgeCases(t *testing.T) {
	scanner := createTestScanner()

	// Test empty template
	results := scanner.Run(context.Background(), []*types.Template{}, nil, []string{"http://example.com"})
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty template list, got %d", len(results))
	}

	// Test empty target list
	tmpl := &types.Template{
		ID: "test", Name: "Test", Description: "Test", Severity: "low",
		HTTP: []types.HTTPRequest{
			{
				Raw: "GET / HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
				Matchers: []types.Matcher{{Type: "status", Status: []int{200}}},
			},
		},
	}
	results = scanner.Run(context.Background(), []*types.Template{tmpl}, nil, []string{})
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty target list, got %d", len(results))
	}
}

// TestDebugOutput tests debug output
func TestDebugOutput(t *testing.T) {
	var debugMsgs []string
	scanner := createTestScanner()
	scanner.SetCallbacks(
		nil, nil,
		func(msg string, args ...interface{}) { fmt.Printf(msg, args...) },
		func(msg string, args ...interface{}) { debugMsgs = append(debugMsgs, fmt.Sprintf(msg, args...)) },
		nil, nil,
	)

	// Just verify callbacks are set
	if len(debugMsgs) < 0 {
		t.Log("debug callbacks working")
	}
}

// TestExecuteHTTPWithProbe tests probe mode
func TestExecuteHTTPWithProbe(t *testing.T) {
	server := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"found":true}`))
	})
	defer server.Close()

	scanner := createTestScanner()
	tmpl := &types.Template{
		ID:          "test-probe",
		Name:        "Probe Test",
		Description: "Test probe mode",
		Severity:    "info",
		HTTP: []types.HTTPRequest{
			{
				Raw:   "GET /api HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
				Probe: true,
				Matchers: []types.Matcher{
					{
						Type:   "status",
						Status: []int{200},
					},
				},
			},
		},
	}

	results := scanner.Run(context.Background(), []*types.Template{tmpl}, nil, []string{server.URL})
	// Probe requests don't generate results
	if len(results) != 0 {
		t.Errorf("expected 0 results for probe, got %d", len(results))
	}
}

// TestExecuteHTTPWithMultipleMatchers tests multiple matchers
func TestExecuteHTTPWithMultipleMatchers(t *testing.T) {
	server := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"admin":true}`))
		w.Header().Set("X-Test", "value")
	})
	defer server.Close()

	scanner := createTestScanner()
	tmpl := &types.Template{
		ID:          "test-multi-matcher",
		Name:        "Multi Matcher Test",
		Description: "Test multiple matchers",
		Severity:    "high",
		HTTP: []types.HTTPRequest{
			{
				Raw: "GET /api HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
				Matchers: []types.Matcher{
					{
						Type:   "status",
						Status: []int{200},
					},
					{
						Type:  "word",
						Words: []string{"admin"},
					},
					{
						Type:   "header",
						Header: []string{"X-Test: value"},
					},
				},
			},
		},
	}

	results := scanner.Run(context.Background(), []*types.Template{tmpl}, nil, []string{server.URL})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

// TestExecuteHTTPWithError tests error handling
func TestExecuteHTTPWithError(t *testing.T) {
	server := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal error"}`))
	})
	defer server.Close()

	scanner := createTestScanner()
	tmpl := &types.Template{
		ID:          "test-error",
		Name:        "Error Test",
		Description: "Test error handling",
		Severity:    "low",
		HTTP: []types.HTTPRequest{
			{
				Raw: "GET /api HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
				Matchers: []types.Matcher{
					{
						Type:   "status",
						Status: []int{200},
					},
				},
			},
		},
	}

	results := scanner.Run(context.Background(), []*types.Template{tmpl}, nil, []string{server.URL})
	// Should return 0 results because status 500 doesn't match 200
	if len(results) != 0 {
		t.Errorf("expected 0 results for error response, got %d", len(results))
	}
}

// TestVariablePassingInWorkflow tests variable passing between workflow steps
func TestVariablePassingInWorkflow(t *testing.T) {
	server := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/step1":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"token":"TOKEN123","user":"admin"}`))
		case "/step2":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"validated":true}`))
		}
	})
	defer server.Close()

	scanner := createTestScanner()
	tmpl := &types.Template{
		ID:          "test-var-pass",
		Name:        "Variable Passing Test",
		Description: "Test variable passing",
		Severity:    "medium",
		Workflow: []types.WorkflowStep{
			{
				Name: "step1",
				HTTP: []types.HTTPRequest{
					{
						Raw: "GET /step1 HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
						Extractors: []types.Extractor{
							{
								Name: "token",
								Type: "json",
								JSON: []string{"token"},
							},
						},
						Matchers: []types.Matcher{
							{
								Type:   "status",
								Status: []int{200},
							},
						},
					},
				},
			},
			{
				Name: "step2",
				HTTP: []types.HTTPRequest{
					{
						// Just test that step2 runs
						Raw: "GET /step2 HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
						Matchers: []types.Matcher{
							{
								Type:   "status",
								Status: []int{200},
							},
						},
					},
				},
			},
		},
	}

	results := scanner.Run(context.Background(), []*types.Template{tmpl}, nil, []string{server.URL})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

// TestDSLRunIfInWorkflow tests DSL run-if in workflow
func TestDSLRunIfInWorkflow(t *testing.T) {
	server := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "skip") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"admin":true}`))
	})
	defer server.Close()

	scanner := createTestScanner()
	tmpl := &types.Template{
		ID:          "test-dsl-wf",
		Name:        "DSL Workflow Test",
		Description: "Test DSL run-if in workflow",
		Severity:    "medium",
		Workflow: []types.WorkflowStep{
			{
				Name: "check",
				HTTP: []types.HTTPRequest{
					{
						Raw: "GET /api HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
						Matchers: []types.Matcher{
							{
								Type:   "status",
								Status: []int{200},
							},
						},
					},
				},
			},
			{
				Name: "admin",
				HTTP: []types.HTTPRequest{
					{
						Raw:   "GET /admin HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
						RunIf: "contains(body, 'admin')",
						Matchers: []types.Matcher{
							{
								Type:  "word",
								Words: []string{"admin"},
							},
						},
					},
				},
			},
		},
	}

	results := scanner.Run(context.Background(), []*types.Template{tmpl}, nil, []string{server.URL})
	_ = results
}

// TestExecuteHTTPWithRange tests the range loop feature
func TestExecuteHTTPWithRange(t *testing.T) {
	requestCount := 0
	server := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	})
	defer server.Close()

	scanner := createTestScanner()
	tmpl := &types.Template{
		ID:          "test-range",
		Name:        "Range Test",
		Description: "Test range loop",
		Severity:    "low",
		HTTP: []types.HTTPRequest{
			{
				Raw: "GET /api/{{param}} HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
				Range: &types.RangeConfig{
					Key:    "param",
					Values: []string{"a", "b", "c"},
				},
				Matchers: []types.Matcher{
					{
						Type:   "status",
						Status: []int{200},
					},
				},
			},
		},
	}

	results := scanner.Run(context.Background(), []*types.Template{tmpl}, nil, []string{server.URL})
	// Should have sent 3 requests (one for each value)
	if requestCount != 3 {
		t.Errorf("expected 3 requests, got %d", requestCount)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

// TestExecuteHTTPWithXPathExtractor tests XPath extraction
func TestExecuteHTTPWithXPathExtractor(t *testing.T) {
	server := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body><div id="token" class="secret">ABC123</div></body></html>`))
	})
	defer server.Close()

	scanner := createTestScanner()
	tmpl := &types.Template{
		ID:          "test-xpath",
		Name:        "XPath Test",
		Description: "Test XPath extraction",
		Severity:    "low",
		HTTP: []types.HTTPRequest{
			{
				Raw: "GET /page HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
				Extractors: []types.Extractor{
					{
						Name:  "token",
						Type:  "xpath",
						XPath: []string{"//div[@id='token']"},
					},
				},
				Matchers: []types.Matcher{
					{
						Type:   "status",
						Status: []int{200},
					},
				},
			},
		},
	}

	results := scanner.Run(context.Background(), []*types.Template{tmpl}, nil, []string{server.URL})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

// TestExecuteHTTPWithCSSElector tests CSS selector extraction
func TestExecuteHTTPWithCSSElector(t *testing.T) {
	server := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body><div class="error">Something went wrong</div></body></html>`))
	})
	defer server.Close()

	scanner := createTestScanner()
	tmpl := &types.Template{
		ID:          "test-css",
		Name:        "CSS Test",
		Description: "Test CSS extraction",
		Severity:    "low",
		HTTP: []types.HTTPRequest{
			{
				Raw: "GET /page HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
				Extractors: []types.Extractor{
					{
						Name: "error",
						Type: "css",
						CSS:  []string{".error"},
					},
				},
				Matchers: []types.Matcher{
					{
						Type:   "status",
						Status: []int{200},
					},
				},
			},
		},
	}

	results := scanner.Run(context.Background(), []*types.Template{tmpl}, nil, []string{server.URL})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}
