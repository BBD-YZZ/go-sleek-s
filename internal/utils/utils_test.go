package utils

import "testing"

func TestTruncate(t *testing.T) {
	cases := []struct {
		input string
		n     int
		want  string
	}{
		{"hello", 5, "hello"},
		{"hello", 3, "hel..."},
		{"", 0, ""},
		{"hello", 10, "hello"},
		// CJK: "你好" = 6 bytes in UTF-8, truncate to 4 cuts mid-char
		{"你好世界", 4, "你\xe5..."}, // 4 bytes = "你" (3 bytes) + 1 byte of next char
	}
	for _, c := range cases {
		got := Truncate(c.input, c.n)
		if got != c.want {
			t.Errorf("Truncate(%q, %d) = %q, want %q", c.input, c.n, got, c.want)
		}
	}
}

func TestMasked(t *testing.T) {
	cases := []struct {
		input string
		keep  int
		want  string
	}{
		{"short", 10, "short"},
		{"this-is-a-very-long-token", 24, "this-is-a-very-long-toke..."},
		{"", 5, ""},
		{"exactly24chars!!!!", 24, "exactly24chars!!!!"},
	}
	for _, c := range cases {
		got := Masked(c.input, c.keep)
		if got != c.want {
			t.Errorf("Masked(%q, %d) = %q, want %q", c.input, c.keep, got, c.want)
		}
	}
}

func TestMapKeys(t *testing.T) {
	m := map[string]bool{"a": true, "b": false, "c": true}
	keys := MapKeys(m)
	if len(keys) != 3 {
		t.Errorf("MapKeys returned %d keys, want 3", len(keys))
	}
	set := make(map[string]bool)
	for _, k := range keys {
		set[k] = true
	}
	for _, want := range []string{"a", "b", "c"} {
		if !set[want] {
			t.Errorf("MapKeys missing key %q", want)
		}
	}
}

func TestMapKeysInt(t *testing.T) {
	m := map[string]int{"x": 1, "y": 2}
	keys := MapKeys(m)
	if len(keys) != 2 {
		t.Errorf("MapKeys[int] returned %d keys, want 2", len(keys))
	}
}

func TestAtoiSafe(t *testing.T) {
	cases := []struct {
		input string
		want  int
	}{
		{"123", 123},
		{" 456 ", 456},
		{"", 0},
		{"abc", 0},
		{"123abc", 123},
		{"-1", 0},
		{"0", 0},
		{"999999", 999999},
	}
	for _, c := range cases {
		got := AtoiSafe(c.input)
		if got != c.want {
			t.Errorf("AtoiSafe(%q) = %d, want %d", c.input, got, c.want)
		}
	}
}
