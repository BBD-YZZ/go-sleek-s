// Package utils provides shared helper functions used across the gosleek project.
package utils

import "strings"

// Truncate shortens s to at most n bytes, appending an ellipsis marker if
// truncated. Unlike the C truncation that would split a multi-byte rune,
// this operates on bytes (safe for UTF-8) and is suitable for log display.
func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// Masked shows the first keep bytes of s, masking the rest with "...".
func Masked(s string, keep int) string {
	if len(s) <= keep {
		return s
	}
	return s[:keep] + "..."
}

// MapKeys extracts keys from a map[string]V into a []string slice.
// The type parameter V is inferred by the caller.
func MapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// AtoiSafe parses the leading decimal digits from s into an int.
// Non-digit characters stop the parse (like the legacy implementation).
func AtoiSafe(s string) int {
	s = strings.TrimSpace(s)
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}
