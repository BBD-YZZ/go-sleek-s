package matcher

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gosleek/gosleek/pkg/types"
)

// Extract runs extractors on a response and returns extracted data.
func Extract(extractors []types.Extractor, ctx *MatchContext) map[string]string {
	result := make(map[string]string)
	for _, ext := range extractors {
		val, err := extractSingle(ext, ctx)
		if err != nil || val == "" {
			continue
		}
		if ext.Name != "" {
			result[ext.Name] = val
		}
	}
	return result
}

func extractSingle(ext types.Extractor, ctx *MatchContext) (string, error) {
	switch strings.ToLower(ext.Type) {
	case "cookie":
		return extractCookie(ext, ctx)
	case "regex":
		return extractRegex(ext, ctx)
	case "word":
		return extractWord(ext, ctx)
	case "kval":
		return extractKVal(ext, ctx)
	case "json":
		return extractJSON(ext, ctx)
	default:
		return extractRegex(ext, ctx)
	}
}

// extractCookie extracts cookie values from Set-Cookie response headers.
// The cookie name is specified in ext.Name.
func extractCookie(ext types.Extractor, ctx *MatchContext) (string, error) {
	cookieName := strings.ToLower(ext.Name)
	if cookieName == "" {
		return "", fmt.Errorf("cookie extractor requires name")
	}
	for _, line := range strings.Split(ctx.CookieHeaders, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToLower(line), "set-cookie:") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		cookieStr := strings.TrimSpace(parts[1])
		// Take only the key=value part before the first semicolon
		cookieStr = strings.SplitN(cookieStr, ";", 2)[0]
		kv := strings.SplitN(cookieStr, "=", 2)
		if len(kv) != 2 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(kv[0]), cookieName) {
			return strings.TrimSpace(kv[1]), nil
		}
	}
	return "", nil
}

func extractRegex(ext types.Extractor, ctx *MatchContext) (string, error) {
	data := extractPart(ext, ctx)
	if len(ext.Regex) == 0 {
		return "", fmt.Errorf("no regex pattern")
	}
	group := ext.Group
	if group == 0 {
		group = 1
	}
	for _, pattern := range ext.Regex {
		re, err := cachedCompile(pattern)
		if err != nil {
			continue
		}
		matches := re.FindStringSubmatch(data)
		if len(matches) > group {
			return matches[group], nil
		}
		if len(matches) > 0 {
			return matches[0], nil
		}
	}
	return "", nil
}

func extractWord(ext types.Extractor, ctx *MatchContext) (string, error) {
	data := extractPart(ext, ctx)
	for _, w := range ext.Words {
		if strings.Contains(data, w) {
			return w, nil
		}
	}
	return "", nil
}

func extractKVal(ext types.Extractor, ctx *MatchContext) (string, error) {
	headerMap := parseHeaderMap(ctx.CookieHeaders + "\n" + ctx.Header)
	for _, key := range ext.KVal {
		lowerKey := strings.ToLower(key)
		for k, vs := range headerMap {
			if strings.Contains(strings.ToLower(k), lowerKey) {
				if len(vs) > 0 {
					return vs[0], nil
				}
			}
		}
	}
	return "", nil
}

func extractJSON(ext types.Extractor, ctx *MatchContext) (string, error) {
	data := extractPart(ext, ctx)
	for _, jsonPath := range ext.JSON {
		var obj interface{}
		if err := json.Unmarshal([]byte(data), &obj); err != nil {
			continue
		}
		val := navigateJSON(obj, jsonPath)
		if val != "" {
			return val, nil
		}
	}
	return "", nil
}

func extractPart(ext types.Extractor, ctx *MatchContext) string {
	part := strings.ToLower(ext.Part)
	if part == "" {
		part = "all"
	}
	switch part {
	case "body":
		return ctx.Body
	case "header":
		return ctx.Header
	case "all":
		return ctx.All
	case "interactsh":
		return ctx.InteractshData
	default:
		return ctx.All
	}
}

func navigateJSON(obj interface{}, path string) string {
	parts := strings.Split(path, ".")
	current := obj
	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			if val, ok := v[part]; ok {
				current = val
			} else {
				return ""
			}
		case []interface{}:
			idx := atoiSafe(part)
			if idx >= 0 && idx < len(v) {
				current = v[idx]
			} else {
				return ""
			}
		default:
			return fmt.Sprintf("%v", current)
		}
	}
	switch v := current.(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%v", v)
	case bool:
		return fmt.Sprintf("%v", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// parseHeaderMap parses a raw header string into a map.
func parseHeaderMap(raw string) map[string][]string {
	result := make(map[string][]string)
	for _, line := range strings.Split(raw, "\n") {
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		result[key] = append(result[key], val)
	}
	return result
}
