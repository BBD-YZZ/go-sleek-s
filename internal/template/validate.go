package template

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/gosleek/gosleek/internal/placeholder"
	"github.com/gosleek/gosleek/pkg/types"
)

// ValidationError holds a single validation issue.
type ValidationError struct {
	Template string
	Field    string
	Message  string
	Level    string // "error" or "warning"
}

// Validate checks a template for required fields and common mistakes.
// Returns a list of errors (empty = valid).
func Validate(tmpl *types.Template) []ValidationError {
	var errs []ValidationError

	add := func(level, field, msg string) {
		errs = append(errs, ValidationError{
			Template: tmpl.ID,
			Field:    field,
			Message:  msg,
			Level:    level,
		})
	}

	// Required fields
	if strings.TrimSpace(tmpl.ID) == "" {
		add("error", "id", "id is required and must be non-empty")
	}
	if strings.TrimSpace(tmpl.Name) == "" {
		add("error", "name", "name is required")
	}
	if strings.TrimSpace(tmpl.Description) == "" {
		add("error", "description", "description is required")
	}

	// Severity validation
	validSev := map[string]bool{
		"info": true, "low": true, "medium": true, "high": true, "critical": true,
	}
	if !validSev[strings.ToLower(tmpl.Severity)] {
		add("error", "severity", fmt.Sprintf("severity must be one of: info, low, medium, high, critical (got: %q)", tmpl.Severity))
	}

	// Must have at least one of: http, workflow
	if len(tmpl.HTTP) == 0 && len(tmpl.Workflow) == 0 {
		add("error", "http/workflow", "template must define either http requests or a workflow")
	}

	// Must have at least one matcher (template-level, per-request, or in workflow steps)
	hasMatcher := false
	for _, req := range tmpl.HTTP {
		if len(req.Matchers) > 0 {
			hasMatcher = true
			break
		}
	}
	if !hasMatcher {
		for _, step := range tmpl.Workflow {
			for _, req := range step.HTTP {
				if len(req.Matchers) > 0 {
					hasMatcher = true
					break
				}
			}
			if hasMatcher {
				break
			}
		}
	}
	if !hasMatcher && len(tmpl.Matchers) == 0 {
		add("error", "matchers", "template must define at least one matcher (template-level, per-request, or in workflow steps)")
	}

	// Collect all extractor names defined in this template
	extractorNames := make(map[string]bool)
	for _, req := range tmpl.HTTP {
		for _, ext := range req.Extractors {
			if ext.Name != "" {
				extractorNames[ext.Name] = true
			}
		}
	}
	for _, ext := range tmpl.Extractors {
		if ext.Name != "" {
			extractorNames[ext.Name] = true
		}
	}

	// Wordlist validation
	wordlistPaths := make(map[string]bool)
	for _, req := range tmpl.HTTP {
		for _, wl := range req.Wordlist {
			wordlistPaths[wl.Path] = true
		}
	}

	// Validate HTTP request blocks
	for i, req := range tmpl.HTTP {
		prefix := fmt.Sprintf("http[%d]", i)
		if req.Raw == "" && len(req.Path) == 0 && req.Method == "" {
			add("error", prefix+".raw", "http block must have a raw request, path, or method")
		}
		// Validate matchers
		for j, m := range req.Matchers {
			mprefix := fmt.Sprintf("%s.matchers[%d]", prefix, j)
			validateMatcher(m, mprefix, &errs, add)
		}
		// Validate matchers-condition
		if req.MatchersCondition != "" {
			if req.MatchersCondition != "and" && req.MatchersCondition != "or" {
				add("error", prefix+".matchers-condition", "must be 'and' or 'or'")
			}
		}
		// Validate run-if references
		if req.RunIf != "" {
			checkRunIf(req.RunIf, prefix+".run-if", extractorNames, &errs, add)
		}
		// Validate wordlist paths
		for wi, wl := range req.Wordlist {
			if wl.Key == "" {
				add("error", prefix+".wordlist["+fmt.Sprintf("%d", wi)+"].key", "wordlist entry requires a non-empty key")
				continue
			}
			if wl.Path == "" {
				add("error", prefix+".wordlist["+fmt.Sprintf("%d", wi)+"].path", "wordlist entry requires a non-empty path")
				continue
			}
			if !wordlistPaths[wl.Path] {
				if _, err := os.Stat(wl.Path); err != nil {
					add("warning", prefix+".wordlist["+fmt.Sprintf("%d", wi)+"].path", fmt.Sprintf("wordlist file not found: %s (may be relative to wordlist-dir)", wl.Path))
				}
			}
		}
	}

	// Validate workflow steps
	stepNames := make(map[string]bool)
	for i, step := range tmpl.Workflow {
		prefix := fmt.Sprintf("workflow[%d]", i)
		if step.Name == "" {
			add("error", prefix+".name", "workflow step must have a name")
		} else {
			if stepNames[step.Name] {
				add("error", prefix+".name", fmt.Sprintf("duplicate workflow step name: %q", step.Name))
			}
			stepNames[step.Name] = true
		}
		if step.Template == "" && len(step.HTTP) == 0 {
			add("error", prefix, "workflow step must reference a template or define http requests")
		}
		// Validate matchers in workflow steps
		for j, req := range step.HTTP {
			wfPrefix := fmt.Sprintf("%s.http[%d]", prefix, j)
			for k, m := range req.Matchers {
				mPrefix := fmt.Sprintf("%s.matchers[%d]", wfPrefix, k)
				validateMatcher(m, mPrefix, &errs, add)
			}
			// Check run-if in workflow steps
			if req.RunIf != "" {
				checkRunIf(req.RunIf, wfPrefix+".run-if", extractorNames, &errs, add)
			}
			// Validate wordlist paths in workflow steps
			for wi, wl := range req.Wordlist {
				if wl.Key == "" {
					add("error", wfPrefix+".wordlist["+fmt.Sprintf("%d", wi)+"].key", "wordlist entry requires a non-empty key")
					continue
				}
				if wl.Path == "" {
					add("error", wfPrefix+".wordlist["+fmt.Sprintf("%d", wi)+"].path", "wordlist entry requires a non-empty path")
					continue
				}
				if !wordlistPaths[wl.Path] {
					if _, err := os.Stat(wl.Path); err != nil {
						add("warning", wfPrefix+".wordlist["+fmt.Sprintf("%d", wi)+"].path", fmt.Sprintf("wordlist file not found: %s (may be relative to wordlist-dir)", wl.Path))
					}
				}
			}
		}
	}
	// Validate requires references point to defined steps
	for i, step := range tmpl.Workflow {
		for _, dep := range step.Requires {
			if !stepNames[dep] {
				prefix := fmt.Sprintf("workflow[%d].requires", i)
				add("error", prefix, fmt.Sprintf("requires references unknown step: %q", dep))
			}
		}
	}

	// Validate template-level matchers
	for j, m := range tmpl.Matchers {
		mprefix := fmt.Sprintf("matchers[%d]", j)
		validateMatcher(m, mprefix, &errs, add)
	}

	// OOB validation
	if tmpl.OOB != nil {
		if tmpl.OOB.Provider != "ceye" {
			add("error", "oob.provider", "only 'ceye' provider is supported")
		}
	}

	// Check for unused extractors (warnings)
	usedExtractors := collectReferencedExtractors(tmpl)
	for name := range extractorNames {
		if !usedExtractors[name] {
			add("warning", fmt.Sprintf("extractor[%s]", name), "extractor not referenced by any matcher or run-if")
		}
	}

	return errs
}

// checkRunIf validates that all {{var}} placeholders in run-if reference defined extractors.
func checkRunIf(expr, prefix string, extractorNames map[string]bool, errs *[]ValidationError, add func(string, string, string)) {
	re := regexp.MustCompile(`\{\{([^}]+)\}\}`)
	matches := re.FindAllStringSubmatch(expr, -1)
	for _, m := range matches {
		varName := strings.TrimSpace(m[1])
		// Strip function calls like "base64(var)"
		if idx := strings.Index(varName, "("); idx > 0 {
			varName = varName[:idx]
		}
		if varName == "" {
			continue
		}
		if !extractorNames[varName] {
			add("warning", prefix, fmt.Sprintf("references undefined extractor '%s' (not found in any extractor name)", varName))
		}
	}
}

// collectReferencedExtractors returns the set of extractor names referenced
// by matchers, run-if, or raw requests in the template.
func collectReferencedExtractors(tmpl *types.Template) map[string]bool {
	referenced := make(map[string]bool)
	re := regexp.MustCompile(`\{\{([^}]+)\}\}`)
	allText := ""
	for _, req := range tmpl.HTTP {
		allText += req.RunIf + "\n"
		allText += req.Raw + "\n"
		for _, m := range req.Matchers {
			allText += strings.Join(m.Words, " ") + " "
			allText += strings.Join(m.Regex, " ") + " "
		}
	}
	matches := re.FindAllStringSubmatch(allText, -1)
	for _, m := range matches {
		varName := strings.TrimSpace(m[1])
		if idx := strings.Index(varName, "("); idx > 0 {
			varName = varName[:idx]
		}
		if varName != "" && !placeholder.IsBareFunction(varName) {
			referenced[varName] = true
		}
	}
	return referenced
}

func validateMatcher(m types.Matcher, prefix string, errs *[]ValidationError, add func(string, string, string)) {
	validTypes := map[string]bool{
		"status": true, "word": true, "regex": true, "header": true,
		"size": true, "time": true, "binary": true, "dsl": true,
		"json-word": true, "json-2darray": true,
	}
	if !validTypes[strings.ToLower(m.Type)] {
		add("error", prefix+".type", fmt.Sprintf("invalid matcher type: %q", m.Type))
		return
	}

	switch strings.ToLower(m.Type) {
	case "status":
		if len(m.Status) == 0 {
			add("error", prefix+".status", "status matcher requires at least one status code")
		}
	case "word", "regex", "header", "json-word", "json-2darray":
		field := m.Type
		if len(m.Words) == 0 && len(m.Regex) == 0 && len(m.Header) == 0 {
			add("error", prefix+"."+field, fmt.Sprintf("%s matcher requires at least one %s entry", field, field))
		}
	case "size":
		if len(m.Size) == 0 {
			add("error", prefix+".size", "size matcher requires at least one size entry")
		}
	case "time":
		if m.Time == "" {
			add("error", prefix+".time", "time matcher requires a time value (e.g. '>=5')")
		}
	case "binary":
		if len(m.Binary) == 0 {
			add("error", prefix+".binary", "binary matcher requires at least one binary entry")
		}
	case "dsl":
		if len(m.DSL) == 0 {
			add("error", prefix+".dsl", "dsl matcher requires at least one expression")
		}
	}

	// condition validation
	if m.Condition != "" && m.Condition != "and" && m.Condition != "or" {
		add("error", prefix+".condition", "condition must be 'and' or 'or'")
	}

	// part validation
	validParts := map[string]bool{
		"": true, "body": true, "header": true, "all": true, "interactsh": true,
	}
	if !validParts[strings.ToLower(m.Part)] {
		add("error", prefix+".part", fmt.Sprintf("invalid part: %q", m.Part))
	}
}

// FormatErrors renders validation errors for display.
func FormatErrors(errs []ValidationError) string {
	if len(errs) == 0 {
		return "valid"
	}
	var sb strings.Builder
	for _, e := range errs {
		level := strings.ToUpper(e.Level)
		if e.Level == "" {
			level = "ERROR"
		}
		sb.WriteString(fmt.Sprintf("  [%s] [%s] %s: %s\n", level, e.Template, e.Field, e.Message))
	}
	return sb.String()
}
