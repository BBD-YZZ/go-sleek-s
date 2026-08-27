package matcher

import (
	"encoding/json"
	"fmt"
	"regexp"
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
	case "xpath":
		return extractXPath(ext, ctx)
	case "css":
		return extractCSS(ext, ctx)
	case "html":
		return extractHTML(ext, ctx)
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

// extractXPath extracts data using XPath expressions from HTML body.
func extractXPath(ext types.Extractor, ctx *MatchContext) (string, error) {
	if len(ext.XPath) == 0 {
		return "", fmt.Errorf("no xpath pattern")
	}
	data := extractPart(ext, ctx)
	for _, expr := range ext.XPath {
		result, err := applyXPath(data, expr)
		if err == nil && result != "" {
			return result, nil
		}
	}
	return "", nil
}

// extractCSS extracts data using CSS selectors from HTML body.
func extractCSS(ext types.Extractor, ctx *MatchContext) (string, error) {
	if len(ext.CSS) == 0 {
		return "", fmt.Errorf("no css selector")
	}
	data := extractPart(ext, ctx)
	for _, selector := range ext.CSS {
		result := applyCSSSelector(data, selector)
		if result != "" {
			return result, nil
		}
	}
	return "", nil
}

// extractHTML extracts text content from HTML tags using CSS-like selectors.
func extractHTML(ext types.Extractor, ctx *MatchContext) (string, error) {
	data := extractPart(ext, ctx)
	for _, tag := range ext.CSS {
		re, err := cachedCompile(fmt.Sprintf(`<%s[^>]*>([^<]*)</%s>`, tag, tag))
		if err != nil {
			continue
		}
		matches := re.FindStringSubmatch(data)
		if len(matches) > 1 {
			return matches[1], nil
		}
	}
	return "", nil
}

// applyXPath applies a simple XPath expression to HTML content.
// Supports basic expressions like //tag, //tag[@attr='value'], //tag/text()
func applyXPath(html, expr string) (string, error) {
	// Handle //tag[@attr='value']/text() patterns
	if strings.HasSuffix(expr, "/text()") {
		expr = expr[:len(expr)-7]
	}
	// Extract tag and attribute conditions
	tag := expr
	attrExpr := ""
	if idx := strings.Index(expr, "["); idx >= 0 {
		tag = expr[:idx]
		attrExpr = expr[idx:]
	}
	// Remove leading //
	tag = strings.TrimPrefix(tag, "//")
	tag = strings.TrimPrefix(tag, "/")

	// Find matching tag content
	var reStr string
	if attrExpr != "" {
		// Parse attribute condition like [@id='token']
		attrName := strings.TrimPrefix(attrExpr, "[@")
		parts := strings.SplitN(attrName, "=", 2)
		if len(parts) < 2 {
			return "", fmt.Errorf("invalid xpath attr: %s", attrExpr)
		}
		attrName = parts[0]
		attrValue := strings.TrimSuffix(parts[1], "]")
		attrValue = strings.Trim(attrValue, "'\"")
		reStr = fmt.Sprintf(`<%s[^>]*\b%s="%s"[^>]*>([^<]*)</%s>`, tag, attrName, attrValue, tag)
	} else {
		reStr = fmt.Sprintf(`<%s[^>]*>([^<]*)</%s>`, tag, tag)
	}

	re, err := cachedCompile(reStr)
	if err != nil {
		return "", err
	}
	matches := re.FindStringSubmatch(html)
	if len(matches) > 1 {
		return matches[1], nil
	}
	return "", nil
}

// cssToXPath converts a CSS selector to a simple XPath expression.
func cssToXPath(selector string) string {
	// Basic CSS to XPath conversion
	selector = strings.TrimSpace(selector)
	if strings.HasPrefix(selector, "#") {
		id := strings.TrimPrefix(selector, "#")
		return fmt.Sprintf("//*[contains(@id, '%s')]", id)
	}
	if strings.HasPrefix(selector, ".") {
		class := strings.TrimPrefix(selector, ".")
		return fmt.Sprintf("//*[contains(@class, '%s')]", class)
	}
	// Compound selectors like "div#error"
	if idx := strings.Index(selector, "#"); idx > 0 {
		tag := selector[:idx]
		id := selector[idx+1:]
		return fmt.Sprintf("//%s[@id='%s']", tag, id)
	}
	if idx := strings.Index(selector, "."); idx > 0 {
		tag := selector[:idx]
		class := selector[idx+1:]
		return fmt.Sprintf("//%s[contains(@class, '%s')]", tag, class)
	}
	// Tag selector
	return fmt.Sprintf("//%s", selector)
}

// applyCSSSelector applies a CSS selector to HTML content.
func applyCSSSelector(html, selector string) string {
	// Handle simple class selectors like .error
	if strings.HasPrefix(selector, ".") {
		class := selector[1:]
		// Match any tag with class="... error ..." containing the text
		re, err := cachedCompile(fmt.Sprintf(`class="[^"]*%s[^"]*"[^>]*>([^<]*)</[^>]+>`, regexp.QuoteMeta(class)))
		if err == nil {
			matches := re.FindStringSubmatch(html)
			if len(matches) > 1 {
				return matches[1]
			}
		}
		// Try alternate format
		re, err = cachedCompile(fmt.Sprintf(`class="%s"[^>]*>([^<]*)</[^>]+>`, regexp.QuoteMeta(class)))
		if err == nil {
			matches := re.FindStringSubmatch(html)
			if len(matches) > 1 {
				return matches[1]
			}
		}
		return ""
	}
	// Handle compound selectors
	xpath := cssToXPath(selector)
	result, err := applyXPath(html, xpath)
	if err != nil || result == "" {
		return ""
	}
	return result
}
