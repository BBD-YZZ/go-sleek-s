// Package display provides CJK-aware terminal display helpers shared across
// the gosleek project (console output, table rendering, log truncation).
package display

import "strings"

// DisplayWidth returns the visual column width of s in a terminal,
// accounting for ANSI escape sequences (stripped) and CJK double-width runes.
func DisplayWidth(s string) int {
	var n int
	inEsc := false
	for _, r := range s {
		if r == 0x1b {
			inEsc = true
			continue
		}
		if inEsc {
			if r == 'm' {
				inEsc = false
			}
			continue
		}
		n += RuneDisplayWidth(r)
	}
	return n
}

// RuneDisplayWidth returns the display width of a single rune.
// CJK and fullwidth characters take 2 columns; most others take 1.
func RuneDisplayWidth(r rune) int {
	if r == 0 || r < 0x20 {
		return 0
	}
	switch {
	case r >= 0x1100 && r <= 0x115F: // Hangul Jamo
		return 2
	case r >= 0x2E80 && r <= 0x303E: // CJK Radicals, Kangxi
		return 2
	case r >= 0x3040 && r <= 0x33BF: // Hiragana, Katakana, CJK
		return 2
	case r >= 0x3400 && r <= 0x4DBF: // CJK Ext A
		return 2
	case r >= 0x4E00 && r <= 0x9FFF: // CJK Unified
		return 2
	case r >= 0xA000 && r <= 0xA4CF: // Yi
		return 2
	case r >= 0xAC00 && r <= 0xD7A3: // Hangul Syllables
		return 2
	case r >= 0xF900 && r <= 0xFAFF: // CJK Compatibility
		return 2
	case r >= 0xFE30 && r <= 0xFE4F: // CJK Compatibility Forms
		return 2
	case r >= 0xFF00 && r <= 0xFF60: // Fullwidth Forms
		return 2
	case r >= 0xFFE0 && r <= 0xFFE6: // Fullwidth Signs
		return 2
	case r >= 0x20000 && r <= 0x3FFFD: // CJK Ext B-F
		return 2
	}
	return 1
}

// StripAnsi strips ANSI escape sequences from s.
func StripAnsi(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inEsc := false
	for _, r := range s {
		if r == 0x1b {
			inEsc = true
			continue
		}
		if inEsc {
			if r == 'm' {
				inEsc = false
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// PadRight pads s with spaces to target display width n.
func PadRight(s string, n int) string {
	w := DisplayWidth(s)
	if w >= n {
		return s
	}
	return s + strings.Repeat(" ", n-w)
}

// Truncate shortens s to max display width, appending "…" if truncated.
// Uses CJK-aware display width so Chinese characters count as 2 columns.
func Truncate(s string, max int) string {
	if DisplayWidth(s) <= max {
		return s
	}
	runes := []rune(s)
	w := 0
	for i, r := range runes {
		rw := RuneDisplayWidth(r)
		if w+rw > max-1 {
			return string(runes[:i]) + "…"
		}
		w += rw
	}
	return string(runes) + "…"
}
