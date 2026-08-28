package matcher

import (
	"regexp"
	"strings"

	"github.com/gosleek/gosleek/internal/placeholder"
)

// unresolvedPlaceholderRe matches a complete {{...}} placeholder.
var unresolvedPlaceholderRe = regexp.MustCompile(`\{\{[^}]+\}\}`)

// EvalRunIf evaluates a run-if condition for a request block.
//
// It checks both the extracted map (from previous requests in the same step)
// and the engine's extracted values (from previous steps) for variable
// resolution. This implementation is shared between the engine and workflow
// packages so that both paths use identical semantics.
func EvalRunIf(expr string, extracted map[string]string, eng *placeholder.Engine) bool {
	val := eng.Replace(expr)
	if val == "" {
		return false
	}
	// Check for unresolved placeholders using a regex that matches
	// complete {{...}} patterns. This avoids false positives when the
	// user's expression legitimately contains literal "{{" or "}}".
	if unresolvedPlaceholderRe.MatchString(val) {
		return false
	}
	// Literal "false" or "0" → false
	lower := strings.ToLower(strings.TrimSpace(val))
	if lower == "false" || lower == "0" {
		return false
	}
	// If the expression looks like a DSL expression (contains ==, !=, etc.),
	// evaluate it using the DSL engine.
	// Note: for run-if, unknown extracted variables should resolve to ""
	// (not their name string) so that len(missing) == 0 evaluates correctly.
	if strings.Contains(val, "==") || strings.Contains(val, "!=") ||
		strings.Contains(val, ">") || strings.Contains(val, "<") ||
		strings.Contains(val, "contains") || strings.Contains(val, "regex") ||
		strings.Contains(val, "!") {
		// Build a match context with extracted variables from BOTH
		// the local extracted map AND the engine's extracted values,
		// so that variables extracted in previous workflow steps are available.
		mergedVars := make(map[string]string, len(extracted))
		for k, v := range extracted {
			mergedVars[k] = v
		}
		// Copy engine's extracted values (they take precedence)
		engineExtracted := eng.GetExtractedMap()
		for k, v := range engineExtracted {
			mergedVars[k] = v
		}
		ctx := &MatchContext{
			StatusCode:     200,
			Body:           "",
			Header:         "",
			ExtractedVars:  mergedVars,
			UnknownVarMode: "empty",
		}
		if result, err := EvalDSL(val, ctx); err == nil {
			return result
		}
		// If DSL evaluation fails, fall through to default behavior
	}
	return true
}
