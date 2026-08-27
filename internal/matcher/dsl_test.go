package matcher

import (
	"testing"
	"time"
)

// TestEvalDSLFunctions exercises the low-level DSL evaluator and its function
// library directly.
func TestEvalDSLFunctions(t *testing.T) {
	ctx := &MatchContext{
		StatusCode:   200,
		Body:         "uid=0(root) gid=0",
		Header:       "Content-Type: text/plain",
		All:          "Content-Type: text/plain\nuid=0(root) gid=0",
		ResponseTime: 500 * time.Millisecond,
		ContentSize:  20,
	}

	cases := []struct {
		name string
		expr string
		want bool
	}{
		// comparison / equality
		{"status_code equals", "status_code == 200", true},
		{"status_code neq", "status_code != 404", true},
		{"content_length gte", "content_length >= 20", true},
		{"content_length lt", "content_length < 20", false},
		// string functions
		{"contains true", "contains(body, 'root')", true},
		{"contains false", "contains(body, 'banana')", false},
		{"equals true", "equals(body, 'uid=0(root) gid=0')", true},
		{"starts_with true", "starts_with(body, 'uid=')", true},
		{"ends_with true", "ends_with(body, 'gid=0')", true},
		{"contains_all true", "contains_all(body, 'uid=', 'gid=0')", true},
		{"contains_all false", "contains_all(body, 'uid=', 'zzz')", false},
		{"contains_any true", "contains_any(body, 'zzz', 'root')", true},
		{"contains_any false", "contains_any(body, 'aaa', 'bbb')", false},
		{"regex true", "regex(body, 'uid=\\d+')", true},
		{"regex false", "regex(body, 'nope\\d+')", false},
		// logic operators
		{"and", "status_code == 200 && contains(body, 'root')", true},
		{"and false", "status_code == 200 && contains(body, 'zzz')", false},
		{"or", "status_code == 500 || contains(body, 'root')", true},
		{"or false", "status_code == 500 || contains(body, 'zzz')", false},
		{"not", "!contains(body, 'zzz')", true},
		{"nested group", "(status_code == 200 && contains(body, 'uid')) || status_code == 500", true},
		// len (body = "uid=0(root) gid=0" → 17 chars)
		{"len gt", "len(body) > 5", true},
		{"len eq", "len(body) == 17", true},
		{"len eq false", "len(body) == 99", false},
		// time
		{"response_time gt", "response_time > 0.1", true},
		// errors / invalid (unknown function returns false, no panic)
		{"unknown func", "frobnicate(body)", false},
		{"unknown var truthy", "foo && bar", true}, // unknown identifiers resolve to themselves (non-empty → true)
		{"empty", "", false},
	}

	for _, c := range cases {
		got, err := evalDSL(c.expr, ctx)
		if got != c.want {
			t.Errorf("[%s] expr=%q got=%v want=%v (err=%v)", c.name, c.expr, got, c.want, err)
		}
	}
}

// TestEvalDSLParsingErrors ensures malformed DSL returns a non-nil error.
// (Note: *incomplete* comparisons such as "status_code ==" are handled
// gracefully by returning false, not an error, per current design.)
func TestEvalDSLParsingErrors(t *testing.T) {
	ctx := &MatchContext{StatusCode: 200}
	bad := []string{
		"(",                       // unclosed paren
		"status_code == 200 )",    // unexpected )
		"status_code == 200 &&",   // dangling &&
		"status_code == 200 garbage", // trailing input (caught by evalDSL guard)
	}
	for _, expr := range bad {
		got, err := evalDSL(expr, ctx)
		if err == nil {
			t.Errorf("expected error for %q, got result=%v", expr, got)
		}
	}
}

// TestEvalDSLsSyntaxErrorNotSilenced verifies that a DSL expression with a
// syntax error does NOT get silently skipped as a "match" by evalDSLs.
// This guards against regressions where parse errors were 'continue'd over
// and the overall result became true (false-positive matches).
func TestEvalDSLsSyntaxErrorNotSilenced(t *testing.T) {
	ctx := &MatchContext{StatusCode: 200, Body: "ok"}
	matched, _ := evalDSLs([]string{"status_code == 200", "status_code == 200 garbage"}, ctx)
	if matched {
		t.Error("a syntactically invalid DSL must NOT be treated as a match")
	}
}
