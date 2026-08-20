package workflow

import (
	"testing"

	"github.com/gosleek/gosleek/internal/placeholder"
	"github.com/gosleek/gosleek/pkg/types"
)

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

	out := substituteMatcherPlaceholders(matchers, eng)

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