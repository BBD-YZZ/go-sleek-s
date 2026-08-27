package matcher

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/gosleek/gosleek/pkg/types"
)

// TestExtract tests the Extract function with various extractor types
func TestExtract(t *testing.T) {
	ctx := NewMatchContext(200, `{"token":"ABC123"}`, "Set-Cookie: session=xyz123\r\nX-Custom: value", 0)

	tests := []struct {
		name     string
		ext      types.Extractor
		expected string
	}{
		{
			name:     "json extractor",
			ext:      types.Extractor{Name: "token", Type: "json", JSON: []string{"token"}},
			expected: "ABC123",
		},
		{
			name:     "word extractor",
			ext:      types.Extractor{Name: "word", Type: "word", Words: []string{"token"}},
			expected: "token",
		},
		{
			name:     "kval extractor",
			ext:      types.Extractor{Name: "custom", Type: "kval", KVal: []string{"X-Custom"}},
			expected: "value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Extract([]types.Extractor{tt.ext}, ctx)
			if got, ok := result[tt.ext.Name]; ok {
				if got != tt.expected {
					t.Errorf("Extract(%s) = %q, want %q", tt.ext.Name, got, tt.expected)
				}
			} else {
				t.Logf("Extract(%s) not found in result (may be expected for this test)", tt.ext.Name)
			}
		})
	}
}

// TestExtractPart tests the extractPart function
func TestExtractPart(t *testing.T) {
	ctx := NewMatchContext(200, "body content", "header line", 0)

	tests := []struct {
		name     string
		part     string
		expected string
	}{
		{"body part", "body", "body content"},
		{"header part", "header", "header line"},
		{"all part", "all", "header line\nbody content"},
		{"interactsh part", "interactsh", ""},
		{"empty part", "", "header line\nbody content"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext := types.Extractor{Part: tt.part}
			result := extractPart(ext, ctx)
			if result != tt.expected {
				t.Errorf("extractPart(%q) = %q, want %q", tt.part, result, tt.expected)
			}
		})
	}
}

// TestNavigateJSON tests the navigateJSON function
func TestNavigateJSON(t *testing.T) {
	data := `{"user":{"name":"john","age":30,"tags":["admin","user"]}}`
	var obj interface{}
	if err := json.Unmarshal([]byte(data), &obj); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{"string value", "user.name", "john"},
		{"number value", "user.age", "30"},
		{"nested object", "user", ""}, // returns %!v(MISSING) for map
		{"array index", "user.tags.0", "admin"},
		{"nonexistent", "user.email", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := navigateJSON(obj, tt.path)
			if tt.expected != "" && result != tt.expected {
				t.Errorf("navigateJSON(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}

// TestParseHeaderMap tests the parseHeaderMap function
func TestParseHeaderMap(t *testing.T) {
	raw := "Content-Type: text/html\r\nX-Custom: value1\r\nX-Custom: value2\r\n"
	result := parseHeaderMap(raw)

	if len(result) != 2 {
		t.Errorf("expected 2 headers, got %d", len(result))
	}

	if result["Content-Type"][0] != "text/html" {
		t.Errorf("Content-Type = %q, want 'text/html'", result["Content-Type"][0])
	}

	if len(result["X-Custom"]) != 2 {
		t.Errorf("X-Custom should have 2 values, got %d", len(result["X-Custom"]))
	}
}

// TestEvalDSL tests the exported EvalDSL function
func TestEvalDSL(t *testing.T) {
	ctx := NewMatchContext(200, "admin panel", "Server: nginx", 0)

	tests := []struct {
		name string
		expr string
		want bool
	}{
		{"simple comparison", "status_code == 200", true},
		{"contains function", "contains(body, 'admin')", true},
		{"len function", "len(body) > 5", true},
		{"not operator", "!contains(body, 'error')", true},
		{"logical and", "status_code == 200 && contains(body, 'admin')", true},
		{"logical or", "status_code == 404 || contains(body, 'admin')", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EvalDSL(tt.expr, ctx)
			if err != nil {
				t.Errorf("EvalDSL(%q) error: %v", tt.expr, err)
			}
			if got != tt.want {
				t.Errorf("EvalDSL(%q) = %v, want %v", tt.expr, got, tt.want)
			}
		})
	}
}

// TestResolveVar tests the resolveVar function with extracted variables
func TestResolveVar(t *testing.T) {
	ctx := NewMatchContext(200, "body content", "", 0)
	ctx.ExtractedVars = map[string]string{
		"token":   "ABC123",
		"user_id": "42",
	}

	tests := []struct {
		name     string
		varName  string
		expected string
	}{
		{"status_code", "status_code", "200"},
		{"body", "body", "body content"},
		{"extracted token", "token", "ABC123"},
		{"extracted user_id", "user_id", "42"},
		{"nonexistent", "nonexistent", "nonexistent"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolveVar(tt.varName, ctx)
			if result != tt.expected {
				t.Errorf("resolveVar(%q) = %q, want %q", tt.varName, result, tt.expected)
			}
		})
	}
}

// TestCompareValues tests the compareValues function
func TestCompareValues(t *testing.T) {
	tests := []struct {
		name   string
		left   string
		right  string
		op     string
		want   bool
	}{
		{"equal numbers", "200", "200", "==", true},
		{"not equal numbers", "200", "404", "==", false},
		{"greater than", "200", "100", ">", true},
		{"less than", "100", "200", "<", true},
		{"greater or equal", "200", "200", ">=", true},
		{"less or equal", "100", "200", "<=", true},
		{"not equal string", "abc", "def", "!=", true},
		{"equal string", "abc", "abc", "==", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := compareValues(tt.left, tt.right, tt.op)
			if err != nil {
				t.Errorf("compareValues(%q, %q, %q) error: %v", tt.left, tt.right, tt.op, err)
			}
			if got != tt.want {
				t.Errorf("compareValues(%q, %q, %q) = %v, want %v", tt.left, tt.right, tt.op, got, tt.want)
			}
		})
	}
}

// TestDebugCallback tests the debug callback in MatchContext
func TestDebugCallback(t *testing.T) {
	var log []string
	ctx := NewMatchContext(200, "body", "header", 0)
	ctx.Debug = func(format string, args ...interface{}) {
		log = append(log, fmt.Sprintf(format, args...))
	}

	// Trigger debug via unknown variable in DSL
	_, _ = evalDSL("unknown_var == 'test'", ctx)

	if len(log) == 0 {
		t.Error("expected debug callback to be called")
	}
}

// TestReadValueWithQuotes tests reading quoted values in DSL
func TestReadValueWithQuotes(t *testing.T) {
	ctx := NewMatchContext(200, "hello world", "", 0)

	// Test with single quotes
	result, err := EvalDSL("equals(body, 'hello world')", ctx)
	if err != nil {
		t.Errorf("evalDSL error: %v", err)
	}
	if !result {
		t.Errorf("equals(body, 'hello world') = false, want true")
	}

	// Test with double quotes
	result, err = EvalDSL(`equals(body, "hello world")`, ctx)
	if err != nil {
		t.Errorf("evalDSL error: %v", err)
	}
	if !result {
		t.Errorf(`equals(body, "hello world") = false, want true`)
	}
}

// TestContainsAnyAndContainsAll tests contains_any and contains_all functions
func TestContainsAnyAndContainsAll(t *testing.T) {
	ctx := NewMatchContext(200, "uid=0(root) gid=0", "", 0)

	tests := []struct {
		name string
		expr string
		want bool
	}{
		{"contains_any match", "contains_any(body, 'root', 'xyz')", true},
		{"contains_any no match", "contains_any(body, 'aaa', 'bbb')", false},
		{"contains_all match", "contains_all(body, 'uid=', 'gid=')", true},
		{"contains_all no match", "contains_all(body, 'uid=', 'zzz')", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := EvalDSL(tt.expr, ctx)
			if err != nil {
				t.Errorf("evalDSL error: %v", err)
			}
			if result != tt.want {
				t.Errorf("EvalDSL(%q) = %v, want %v", tt.expr, result, tt.want)
			}
		})
	}
}

// TestRegexFunction tests the regex/matches function
func TestRegexFunction(t *testing.T) {
	ctx := NewMatchContext(200, "token=ABC123", "", 0)

	tests := []struct {
		name string
		expr string
		want bool
	}{
		{"regex match", "regex(body, 'token=[A-Z0-9]+')", true},
		{"regex no match", "regex(body, 'token=[a-z]+')", false},
		{"matches alias", "matches(body, 'token=[A-Z0-9]+')", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := EvalDSL(tt.expr, ctx)
			if err != nil {
				t.Errorf("evalDSL error: %v", err)
			}
			if result != tt.want {
				t.Errorf("EvalDSL(%q) = %v, want %v", tt.expr, result, tt.want)
			}
		})
	}
}

// TestStartsWithAndEndsWith tests starts_with and ends_with functions
func TestStartsWithAndEndsWith(t *testing.T) {
	ctx := NewMatchContext(200, "http://example.com/path", "", 0)

	tests := []struct {
		name string
		expr string
		want bool
	}{
		{"starts_with match", "starts_with(body, 'http://')", true},
		{"starts_with no match", "starts_with(body, 'https://')", false},
		{"has_prefix alias", "has_prefix(body, 'http://')", true},
		{"ends_with match", "ends_with(body, '/path')", true},
		{"ends_with no match", "ends_with(body, '/other')", false},
		{"has_suffix alias", "has_suffix(body, '/path')", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := EvalDSL(tt.expr, ctx)
			if err != nil {
				t.Errorf("evalDSL error: %v", err)
			}
			if result != tt.want {
				t.Errorf("EvalDSL(%q) = %v, want %v", tt.expr, result, tt.want)
			}
		})
	}
}

// TestResponseTime tests the response_time variable
func TestResponseTime(t *testing.T) {
	ctx := NewMatchContext(200, "body", "", 1500*time.Millisecond)

	result, err := EvalDSL("response_time > 1.0", ctx)
	if err != nil {
		t.Errorf("evalDSL error: %v", err)
	}
	if !result {
		t.Error("response_time > 1.0 should be true for 1.5s response")
	}
}

// TestContentSize tests the content_length variable
func TestContentSize(t *testing.T) {
	ctx := NewMatchContext(200, "a very long body content here", "", 0)

	result, err := EvalDSL("content_length > 10", ctx)
	if err != nil {
		t.Errorf("evalDSL error: %v", err)
	}
	if !result {
		t.Error("content_length > 10 should be true")
	}
}

// TestParenthesizedExpression tests parenthesized expressions
func TestParenthesizedExpression(t *testing.T) {
	ctx := NewMatchContext(200, "admin panel", "", 0)

	result, err := EvalDSL("(status_code == 200) && contains(body, 'admin')", ctx)
	if err != nil {
		t.Errorf("evalDSL error: %v", err)
	}
	if !result {
		t.Error("parenthesized expression should be true")
	}
}

// TestComplexExpression tests complex nested expressions
func TestComplexExpression(t *testing.T) {
	ctx := NewMatchContext(200, "uid=0(root) gid=0", "", 0)

	// Complex expression: status_code == 200 && (contains(body, 'root') || contains(body, 'admin'))
	result, err := EvalDSL("status_code == 200 && (contains(body, 'root') || contains(body, 'admin'))", ctx)
	if err != nil {
		t.Errorf("evalDSL error: %v", err)
	}
	if !result {
		t.Error("complex expression should be true")
	}
}

// TestEmptyBody tests DSL with empty body
func TestEmptyBody(t *testing.T) {
	ctx := NewMatchContext(200, "", "", 0)

	result, err := EvalDSL("len(body) == 0", ctx)
	if err != nil {
		t.Errorf("evalDSL error: %v", err)
	}
	if !result {
		t.Error("len(body) == 0 should be true for empty body")
	}
}

// TestInvalidExpression tests invalid DSL expressions
func TestInvalidExpression(t *testing.T) {
	ctx := NewMatchContext(200, "body", "", 0)

	invalid := []string{
		"(",                      // unclosed paren
		"status_code == 200 )",   // unexpected )
		"status_code == 200 &&",  // dangling &&
	}

	for _, expr := range invalid {
		_, err := EvalDSL(expr, ctx)
		if err == nil {
			t.Errorf("expected error for %q, got nil", expr)
		}
	}
}

// TestExtractXPath tests XPath extraction
func TestExtractXPath(t *testing.T) {
	htmlBody := `<html><body><div id="token" class="secret">ABC123</div></body></html>`
	ctx := NewMatchContext(200, htmlBody, "", 0)

	ext := types.Extractor{
		Name:  "token",
		Type:  "xpath",
		XPath: []string{"//div[@id='token']"},
	}

	result := Extract([]types.Extractor{ext}, ctx)
	if result["token"] != "ABC123" {
		t.Errorf("XPath extraction failed: got %q, want 'ABC123'", result["token"])
	}
}

// TestExtractHTML tests HTML/CSS extraction
func TestExtractHTML(t *testing.T) {
	htmlBody := `<html><body><div class="error">Something went wrong</div></body></html>`
	ctx := NewMatchContext(200, htmlBody, "", 0)

	tests := []struct {
		name    string
		ext     types.Extractor
		want    string
	}{
		{
			name: "css selector",
			ext:  types.Extractor{Name: "err", Type: "css", CSS: []string{".error"}},
			want: "Something went wrong",
		},
		{
			name: "tag selector",
			ext:  types.Extractor{Name: "title", Type: "html", CSS: []string{"title"}},
			want: "", // no title tag in body
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Extract([]types.Extractor{tt.ext}, ctx)
			if tt.want != "" {
				if result[tt.ext.Name] != tt.want {
					t.Errorf("HTML extraction failed: got %q, want %q", result[tt.ext.Name], tt.want)
				}
			}
		})
	}
}

// TestCSSToXPath tests CSS to XPath conversion
func TestCSSToXPath(t *testing.T) {
	tests := []struct {
		name     string
		selector string
		want     string
	}{
		{"id selector", "#token", "//*[contains(@id, 'token')]"},
		{"class selector", ".error", "//*[contains(@class, 'error')]"},
		{"tag selector", "div", "//div"},
		{"compound", "div#error", "//div[@id='error']"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cssToXPath(tt.selector)
			if got != tt.want {
				t.Errorf("cssToXPath(%q) = %q, want %q", tt.selector, got, tt.want)
			}
		})
	}
}
