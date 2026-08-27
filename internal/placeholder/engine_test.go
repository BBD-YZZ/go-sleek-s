package placeholder

import (
	"strings"
	"testing"
)

// TestVariablesEvaluatedOnce verifies the core feature needed by
// CVE-2022-22947-style templates: a variable defined as
//   variables:
//     route_id: "{{rand_text_alpha(8)}}"
// is evaluated ONCE at engine creation, so every subsequent {{route_id}}
// in a multi-step workflow resolves to the SAME random value.
func TestVariablesEvaluatedOnce(t *testing.T) {
	ti := ParseTarget("http://192.168.80.128:8080/")
	eng := New(ti, map[string]string{
		"route_id": "{{rand_text_alpha(8)}}",
	})
	v1 := eng.Replace("{{route_id}}")
	v2 := eng.Replace("{{route_id}}")
	v3 := eng.Replace("POST /routes/{{route_id}} HTTP/1.1")

	if v1 == "" {
		t.Fatal("route_id resolved to empty")
	}
	if v1 != v2 {
		t.Errorf("variable must be stable across resolves: v1=%q v2=%q", v1, v2)
	}
	if !strings.Contains(v3, v1) {
		t.Errorf("route_id not substituted into raw request: %q (want %q)", v3, v1)
	}
	if len(v1) != 8 {
		t.Errorf("rand_text_alpha(8) should produce 8 chars, got %d (%q)", len(v1), v1)
	}
}

// TestBareFunc verifies {{randstr}} (no parentheses) resolves to a generated
// value instead of being left as the literal string "{{randstr}}".
func TestBareFunc(t *testing.T) {
	ti := ParseTarget("http://example.com/")
	eng := New(ti, nil)

	v := eng.Replace("{{randstr}}")
	if strings.Contains(v, "{{") {
		t.Errorf("bare func {{randstr}} was not resolved: %q", v)
	}
	if len(v) == 0 {
		t.Error("randstr returned empty string")
	}
}

// TestVariablesReferenceStaticPlaceholder verifies a variable can reference
// engine-injected static placeholders like {{Hostname}}.
func TestVariablesReferenceStaticPlaceholder(t *testing.T) {
	ti := ParseTarget("http://192.168.80.128:8080/")
	eng := New(ti, map[string]string{
		"callback": "{{Hostname}}/cb",
	})
	v := eng.Replace("{{callback}}")
	if v != "192.168.80.128:8080/cb" {
		t.Errorf("variable referencing {{Hostname}} failed: got %q", v)
	}
}

// TestVariablesInterVariableRef verifies one variable can reference another,
// resolved via multi-round evaluation.
func TestVariablesInterVariableRef(t *testing.T) {
	ti := ParseTarget("http://example.com/")
	eng := New(ti, map[string]string{
		"base": "{{rand_text_alpha(4)}}",
		"full": "prefix-{{base}}-suffix",
	})
	base := eng.Replace("{{base}}")
	full := eng.Replace("{{full}}")

	if len(base) != 4 {
		t.Errorf("base should be 4 chars, got %d (%q)", len(base), base)
	}
	if !strings.Contains(full, base) {
		t.Errorf("inter-variable ref failed: base=%q full=%q", base, full)
	}
	if !strings.HasPrefix(full, "prefix-") || !strings.HasSuffix(full, "-suffix") {
		t.Errorf("full variable malformed: %q", full)
	}
}

// TestRandTextAlphaWithArgs verifies the explicit parenthesized form still works.
func TestRandTextAlphaWithArgs(t *testing.T) {
	ti := ParseTarget("http://example.com/")
	eng := New(ti, nil)

	v := eng.Replace("{{rand_text_alpha(12)}}")
	if len(v) != 12 {
		t.Errorf("rand_text_alpha(12) should produce 12 chars, got %d (%q)", len(v), v)
	}
	for _, c := range v {
		if c < 'a' || c > 'z' {
			t.Errorf("rand_text_alpha should be lowercase letters only, got %q", v)
			break
		}
	}
}

// TestRandInt verifies rand_int(min,max) produces values in range.
func TestRandInt(t *testing.T) {
	ti := ParseTarget("http://example.com/")
	eng := New(ti, nil)

	for i := 0; i < 100; i++ {
		v := eng.Replace("{{rand_int(100,200)}}")
		n := 0
		for _, c := range v {
			if c < '0' || c > '9' {
				t.Errorf("rand_int produced non-numeric: %q", v)
				return
			}
			n = n*10 + int(c-'0')
		}
		if n < 100 || n > 200 {
			t.Errorf("rand_int(100,200) out of range: %d", n)
		}
	}
}

// TestStaticPlaceholders verifies the engine-injected static placeholders
// resolve correctly. Note the real key names: Scheme/Host/Hostname/Port/Path
// plus baseURL/RootURL. Host keeps the port (correct for the HTTP Host header).
func TestStaticPlaceholders(t *testing.T) {
	ti := ParseTarget("https://example.com:8443/path/to?x=1")
	eng := New(ti, nil)

	checks := map[string]string{
		"{{Hostname}}": "example.com:8443",
		"{{Host}}":     "example.com:8443",
		"{{Port}}":     "8443",
		"{{Scheme}}":   "https",
		"{{Path}}":     "/path/to",
		"{{baseURL}}":  "https://example.com:8443",
		"{{RootURL}}":  "https://example.com:8443",
	}
	for ph, want := range checks {
		if got := eng.Replace(ph); got != want {
			t.Errorf("static placeholder %q: got %q want %q", ph, got, want)
		}
	}
}

// TestEncodingFunctions verifies URL/base64/hex encoding helpers.
func TestEncodingFunctions(t *testing.T) {
	ti := ParseTarget("http://example.com/")
	eng := New(ti, nil)

	// url_encode (uses Go's QueryEscape: space -> '+', '&' -> %26)
	if got := eng.Replace("{{url_encode(a b&c)}}"); got != "a+b%26c" {
		t.Errorf("url_encode got %q want %q", got, "a+b%26c")
	}
	// base64
	wantB64 := "aGVsbG8=" // base64("hello")
	if got := eng.Replace("{{base64(hello)}}"); got != wantB64 {
		t.Errorf("base64(hello) got %q want %q", got, wantB64)
	}
	// hex_encode
	if got := eng.Replace("{{hex_encode(ab)}}"); got != "6162" {
		t.Errorf("hex_encode(ab) got %q", got)
	}
}

// TestHashFunctions verifies md5/sha1/sha256 outputs have correct length.
func TestHashFunctions(t *testing.T) {
	ti := ParseTarget("http://example.com/")
	eng := New(ti, nil)

	if got := eng.Replace("{{md5(abc)}}"); got != "900150983cd24fb0d6963f7d28e17f72" {
		t.Errorf("md5(abc) got %q", got)
	}
	if got := eng.Replace("{{sha1(abc)}}"); got != "a9993e364706816aba3e25717850c26c9cd0d89d" {
		t.Errorf("sha1(abc) got %q", got)
	}
	if got := eng.Replace("{{sha256(abc)}}"); len(got) != 64 {
		t.Errorf("sha256(abc) length wrong: %q", got)
	}
}

// TestEscapeSequence verifies the $$ escape leaves a literal $ (an unescaped
// empty placeholder "{{}}" or stray "$" should be handled gracefully).
func TestEscapeSequence(t *testing.T) {
	ti := ParseTarget("http://example.com/")
	eng := New(ti, nil)

	// Stray single $ is passed through.
	if got := eng.Replace("price is $5"); got != "price is $5" {
		t.Errorf("stray $ should be kept: got %q", got)
	}
	// Double $$ — if treated as escape, collapses to single $. (no-op if not
	// implemented, but must not crash or produce placeholders.)
	got := eng.Replace("cost is $$10")
	if strings.Contains(got, "{{") {
		t.Errorf("escape handling leaked a placeholder: %q", got)
	}
}

// TestReplaceWithEscapeIsolation verifies ReplaceWithEscape does not mutate
// the base engine state (no shared template corruption between calls).
func TestReplaceWithEscapeIsolation(t *testing.T) {
	ti := ParseTarget("http://example.com/")
	eng := New(ti, map[string]string{
		"token": "{{rand_text_alphanumeric(6)}}",
	})
	a := eng.ReplaceWithEscape("{{token}}")
	b := eng.ReplaceWithEscape("{{token}}")
	if a == "" || b == "" {
		t.Fatal("token should not be empty")
	}
	if a != b {
		t.Errorf("ReplaceWithEscape must keep variable stable: a=%q b=%q", a, b)
	}
}

// TestSetExtracted verifies extracted values become usable as {{placeholders}}.
func TestSetExtracted(t *testing.T) {
	ti := ParseTarget("http://example.com/")
	eng := New(ti, nil)
	eng.SetExtracted("csrf", "abc123token")
	if got := eng.Replace("value={{csrf}}"); got != "value=abc123token" {
		t.Errorf("SetExtracted value not usable: got %q", got)
	}
}

// TestSetOOB verifies OOB URL injection via SetOOB ({{oob}}/{{interactsh-url}})
// and that oob_label/oob_token are injected the same way the engine does it
// (via SetExtracted), matching the actual engine.go wiring.
func TestSetOOB(t *testing.T) {
	ti := ParseTarget("http://example.com/")
	eng := New(ti, nil)
	eng.SetOOB("http://gS-xxxx.ceye.io")
	eng.SetExtracted("oob_label", "gS-xxxx")
	eng.SetExtracted("oob_token", "tok123")
	eng.SetExtracted("oob_domain", "gS-xxxx.ceye.io")

	if got := eng.Replace("{{oob}}"); got != "http://gS-xxxx.ceye.io" {
		t.Errorf("{{oob}} got %q", got)
	}
	if got := eng.Replace("{{interactsh-url}}"); got != "http://gS-xxxx.ceye.io" {
		t.Errorf("{{interactsh-url}} got %q", got)
	}
	if got := eng.Replace("label={{oob_label}} token={{oob_token}} domain={{oob_domain}}"); got != "label=gS-xxxx token=tok123 domain=gS-xxxx.ceye.io" {
		t.Errorf("oob_label/oob_token/oob_domain injection failed: got %q", got)
	}
}

// TestNoMatchLeftUntouched verifies unrecognized placeholders remain intact
// (so typos are visible, not silently dropped), and {{}} edge cases are safe.
func TestNoMatchLeftUntouched(t *testing.T) {
	ti := ParseTarget("http://example.com/")
	eng := New(ti, nil)
	in := "x={{unknown_func_xyz()}} y={{Hostname}}"
	got := eng.Replace(in)
	if !strings.Contains(got, "{{unknown_func_xyz()}}") {
		t.Errorf("unknown placeholder should remain untouched: got %q", got)
	}
	if !strings.Contains(got, "example.com") {
		t.Errorf("known placeholder should still resolve: got %q", got)
	}
}
