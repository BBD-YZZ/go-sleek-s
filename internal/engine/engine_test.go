package engine

import (
	"strings"
	"testing"

	"github.com/gosleek/gosleek/internal/placeholder"
	"github.com/gosleek/gosleek/pkg/types"

	"github.com/gosleek/gosleek/internal/httpclient")

// TestEvaluateRunIf tests the evalRunIf function with various inputs
func TestEvaluateRunIf(t *testing.T) {
	ti := placeholder.ParseTarget("http://example.com:8080")
	eng := placeholder.New(ti, nil)

	tests := []struct {
		name   string
		expr   string
		extracted map[string]string
		want   bool
	}{
		{"empty expression", "", nil, false},
		{"non-empty string", "test", nil, true},
		{"literal false", "false", nil, false},
		{"literal 0", "0", nil, false},
		{"unresolved placeholder", "{{nonexistent}}", nil, false},
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

// TestAggregateMatches tests the aggregateMatches function
func TestAggregateMatches(t *testing.T) {
	tests := []struct {
		name  string
		results []bool
		cond  string
		want  bool
	}{
		{"all true and", []bool{true, true, true}, "and", true},
		{"all true or", []bool{true, true, true}, "or", true},
		{"one false and", []bool{true, false, true}, "and", false},
		{"one true or", []bool{false, true, false}, "or", true},
		{"all false and", []bool{false, false}, "and", false},
		{"all false or", []bool{false, false}, "or", false},
		{"empty results", []bool{}, "or", false},
		{"single true and", []bool{true}, "and", true},
		{"single false or", []bool{false}, "or", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := aggregateMatches(tt.results, tt.cond)
			if got != tt.want {
				t.Errorf("aggregateMatches(%v, %q) = %v, want %v", tt.results, tt.cond, got, tt.want)
			}
		})
	}
}

// TestEvalRunIfDSLExpression tests DSL expression evaluation
func TestEvalRunIfDSLExpression(t *testing.T) {
	ti := placeholder.ParseTarget("http://example.com:8080")
	eng := placeholder.New(ti, nil)
	extracted := map[string]string{
		"token":   "eyJhbGciOiJIUzI1NiJ9.test",
		"user_id": "42",
	}

	tests := []struct {
		name   string
		expr   string
		want   bool
	}{
		// status_code checks - default context is 200
		{"status_code equality", "status_code == 200", true},
		{"status_code not equal", "status_code == 404", false},
		// contains checks - need body context
		{"not contains", "!contains(body, 'error')", true},
		// token checks
		{"extracted token not empty", "token != ''", true},
		{"extracted token value", "token == 'eyJhbGciOiJIUzI1NiJ9.test'", true},
		{"user_id numeric", "user_id == 42", true},
		{"user_id wrong", "user_id == 99", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evalRunIf(tt.expr, extracted, eng)
			if got != tt.want {
				t.Errorf("evalRunIf(%q) = %v, want %v", tt.expr, got, tt.want)
			}
		})
	}
}

// TestBuildRawFromPath tests the buildRawFromPath helper
func TestBuildRawFromPath(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		path    string
		headers map[string]string
		body    string
		wantContains string
	}{
		{
			name:       "simple GET",
			method:     "GET",
			path:       "/api/test",
			wantContains: "GET /api/test HTTP/1.1",
		},
		{
			name:       "POST with body",
			method:     "POST",
			path:       "/api/login",
			body:       "username=admin&password=test",
			wantContains: "POST /api/login HTTP/1.1",
		},
		{
			name:       "with headers",
			method:     "GET",
			path:       "/api/test",
			headers:    map[string]string{"Authorization": "Bearer token", "X-Custom": "value"},
			wantContains: "Authorization: Bearer token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := httpclient.BuildRawFromPath(tt.method, tt.path, tt.headers, tt.body)
			if !strings.Contains(raw, tt.wantContains) {
				t.Errorf("buildRawFromPath did not contain expected: %q (got: %q)", tt.wantContains, raw)
			}
		})
	}
}

// TestTemplateNeedsOOB tests the TemplateNeedsOOB function
func TestTemplateNeedsOOB(t *testing.T) {
	tests := []struct {
		name   string
		tmpl   *types.Template
		want   bool
	}{
		{
			name:   "no OOB",
			tmpl:   &types.Template{HTTP: []types.HTTPRequest{{Raw: "GET /test HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n"}}},
			want:   false,
		},
		{
			name:   "with OOB",
			tmpl:   &types.Template{HTTP: []types.HTTPRequest{{Raw: "GET {{oob}} HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n"}}},
			want:   true,
		},
		{
			name:   "with interactsh",
			tmpl:   &types.Template{HTTP: []types.HTTPRequest{{Raw: "GET {{interactsh-url}} HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n"}}},
			want:   true,
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

// TestParseMethodPath tests the parseMethodPath helper
func TestParseMethodPath(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		wantMethod string
		wantPath   string
	}{
		{
			name:     "GET request",
			raw:      "GET /api/test HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantMethod: "GET",
			wantPath:   "/api/test",
		},
		{
			name:     "POST request",
			raw:      "POST /login HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantMethod: "POST",
			wantPath:   "/login",
		},
		{
			name:     "malformed request",
			raw:      "invalid",
			wantMethod: "?",
			wantPath:   "?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method, path := httpclient.ParseMethodPath(tt.raw)
			if method != tt.wantMethod || path != tt.wantPath {
				t.Errorf("httpclient.ParseMethodPath(%q) = (%q, %q), want (%q, %q)",
					tt.raw, method, path, tt.wantMethod, tt.wantPath)
			}
		})
	}
}
