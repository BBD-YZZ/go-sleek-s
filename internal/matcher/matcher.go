package matcher

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gosleek/gosleek/internal/utils"
	"github.com/gosleek/gosleek/pkg/types"
)

// MatchContext provides response data to matchers.
type MatchContext struct {
	StatusCode   int
	Body         string
	Header       string // all headers as string
	CookieHeaders string // raw Set-Cookie headers for cookie extractor
	All          string // header + body
	ResponseTime time.Duration
	ContentSize  int
	// OOB data
	InteractshData string
	// [批次B-3 修复点] Debug 回调: 替代直接写 stderr, 由上层 (engine/console)
	// 注入, 使 matcher 的调试输出走统一的日志通道。nil 时静默。
	Debug func(format string, args ...interface{})
	// ExtractedVars holds variables extracted from previous requests in the
	// same template, so that DSL expressions and matchers in later steps can
	// reference them as first-class variables (e.g. `token == "{{token}}"`).
	ExtractedVars map[string]string
}

// NewMatchContext builds a context from response parts.
func NewMatchContext(statusCode int, body, header string, elapsed time.Duration) *MatchContext {
	return NewMatchContextWithCookies(statusCode, body, header, "", elapsed)
}

// NewMatchContextWithCookies builds a context including raw Set-Cookie headers.
func NewMatchContextWithCookies(statusCode int, body, header, cookieHeaders string, elapsed time.Duration) *MatchContext {
	all := header + "\n" + body
	return &MatchContext{
		StatusCode:    statusCode,
		Body:          body,
		Header:        header,
		CookieHeaders: cookieHeaders,
		All:           all,
		ResponseTime:  elapsed,
		ContentSize:   len(body),
		ExtractedVars: make(map[string]string),
	}
}

// debugf writes a debug message via the context's Debug callback if set.
// [批次B-3 修复点] 统一调试输出入口, 替代散落的 fmt.Fprintf(os.Stderr, ...)
func (ctx *MatchContext) debugf(format string, args ...interface{}) {
	if ctx.Debug != nil {
		ctx.Debug(format, args...)
	}
}

// Evaluate runs all matchers and returns whether the response matches.
// matchersCondition = "and" (all must match) or "or" (any must match).
func Evaluate(matchers []types.Matcher, condition string, ctx *MatchContext) (bool, string) {
	if len(matchers) == 0 {
		return false, "" // no matchers = no match (prevents false positives)
	}
	if condition == "" {
		condition = "or"
	}

	var evidence []string
	anyMatch := false
	allMatch := true

	for _, m := range matchers {
		matched, ev := evalSingle(m, ctx)
		if matched {
			anyMatch = true
			if ev != "" {
				evidence = append(evidence, ev)
			}
		} else {
			allMatch = false
		}
	}

	var result bool
	if condition == "and" {
		result = allMatch
	} else {
		result = anyMatch
	}

	evStr := ""
	if len(evidence) > 0 {
		evStr = strings.Join(evidence, "; ")
	}
	return result, evStr
}

func evalSingle(m types.Matcher, ctx *MatchContext) (bool, string) {
	var matched bool
	var evidence string

	switch strings.ToLower(m.Type) {
	case "status":
		matched = matchStatus(m, ctx)
		evidence = fmt.Sprintf("status: %d", ctx.StatusCode)
	case "word":
		matched, evidence = matchWord(m, ctx)
	case "regex":
		matched, evidence = matchRegex(m, ctx)
	case "header":
		hdrMatched, hdrEv := matchHeader(m, ctx)
		matched = hdrMatched
		evidence = hdrEv
	case "size":
		matched = matchSize(m, ctx)
		evidence = fmt.Sprintf("size: %d", ctx.ContentSize)
	case "time":
		matched = matchTime(m, ctx)
		evidence = fmt.Sprintf("time: %v", ctx.ResponseTime)
	case "binary":
		matched = matchBinary(m, ctx)
	case "dsl":
		matched, evidence = evalDSLs(m.DSL, ctx)
	case "json-word":
		matched, evidence = matchJSONWord(m, ctx)
	case "json-2darray":
		matched, evidence = matchJSON2DArray(m, ctx)
	default:
		matched = false
	}

	// Apply negative
	if m.Negative {
		matched = !matched
		evidence = "NOT(" + evidence + ")"
	}

	return matched, evidence
}

func getPart(m types.Matcher, ctx *MatchContext) string {
	part := strings.ToLower(m.Part)
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

func matchStatus(m types.Matcher, ctx *MatchContext) bool {
	for _, code := range m.Status {
		if code == ctx.StatusCode {
			return true
		}
	}
	return false
}

func matchWord(m types.Matcher, ctx *MatchContext) (bool, string) {
	data := getPart(m, ctx)
	if len(m.Words) == 0 {
		return false, ""
	}

	cond := strings.ToLower(m.Condition)
	if cond == "" {
		cond = "or"
	}

	// Case-insensitive: lowercase both data and words for comparison only
	var cmpData string
	var cmpWords []string
	if m.CaseInsensitive {
		cmpData = strings.ToLower(data)
		for _, w := range m.Words {
			cmpWords = append(cmpWords, strings.ToLower(w))
		}
	} else {
		cmpData = data
		cmpWords = m.Words
	}

	all := true
	any := false
	var evidence []string
	for _, w := range cmpWords {
		if strings.Contains(cmpData, w) {
			any = true
			evidence = append(evidence, w)
		} else {
			all = false
		}
	}

	var result bool
	if cond == "and" {
		result = all
	} else {
		result = any
	}

	ev := ""
	if len(evidence) > 0 {
		ev = "words: " + strings.Join(evidence, ", ")
	}
	return result, ev
}

func matchRegex(m types.Matcher, ctx *MatchContext) (bool, string) {
	data := getPart(m, ctx)
	if len(m.Regex) == 0 {
		return false, ""
	}

	cond := strings.ToLower(m.Condition)
	if cond == "" {
		cond = "or"
	}

	// Prepend (?i) flag when case-insensitive is requested
	patterns := m.Regex
	if m.CaseInsensitive {
		prefixed := make([]string, len(m.Regex))
		for i, p := range m.Regex {
			prefixed[i] = "(?i)" + p
		}
		patterns = prefixed
	}

	all := true
	any := false
	var evidence []string
	for _, pattern := range patterns {
		re, err := cachedCompile(pattern)
		if err != nil {
			all = false
			continue
		}
		if re.MatchString(data) {
			any = true
			matched := re.FindString(data)
			if matched != "" {
				evidence = append(evidence, matched)
			}
		} else {
			all = false
		}
	}

	var result bool
	if cond == "and" {
		result = all
	} else {
		result = any
	}

	ev := ""
	if len(evidence) > 0 {
		ev = "regex: " + strings.Join(evidence, ", ")
	}
	return result, ev
}

func matchHeader(m types.Matcher, ctx *MatchContext) (bool, string) {
	// header type: treat words as header patterns
	data := ctx.Header
	items := m.Header
	if len(items) == 0 {
		items = m.Words
	}
	if len(items) == 0 {
		return false, ""
	}

	cond := strings.ToLower(m.Condition)
	if cond == "" {
		cond = "or"
	}

	// Case-insensitive comparison: lowercase both sides
	var cmpData string
	var cmpItems []string
	if m.CaseInsensitive {
		cmpData = strings.ToLower(data)
		for _, it := range items {
			cmpItems = append(cmpItems, strings.ToLower(it))
		}
	} else {
		cmpData = data
		cmpItems = items
	}

	all := true
	any := false
	var evidence []string
	for _, h := range cmpItems {
		if strings.Contains(cmpData, h) {
			any = true
			evidence = append(evidence, h)
		} else {
			all = false
		}
	}

	var result bool
	if cond == "and" {
		result = all
	} else {
		result = any
	}

	ev := ""
	if len(evidence) > 0 {
		ev = "header: " + strings.Join(evidence, ", ")
	}
	return result, ev
}

func matchSize(m types.Matcher, ctx *MatchContext) bool {
	size := ctx.ContentSize
	for _, s := range m.Size {
		if matchSizeExpr(size, s) {
			return true
		}
	}
	return false
}

func matchSizeExpr(actual int, expr string) bool {
	expr = strings.TrimSpace(expr)
	// Operators: >100, <5000, ==200, >=100, <=5000
	if strings.HasPrefix(expr, ">=") {
		n := atoiSafe(expr[2:])
		return actual >= n
	}
	if strings.HasPrefix(expr, "<=") {
		n := atoiSafe(expr[2:])
		return actual <= n
	}
	if strings.HasPrefix(expr, ">") {
		n := atoiSafe(expr[1:])
		return actual > n
	}
	if strings.HasPrefix(expr, "<") {
		n := atoiSafe(expr[1:])
		return actual < n
	}
	if strings.HasPrefix(expr, "==") {
		n := atoiSafe(expr[2:])
		return actual == n
	}
	if strings.HasPrefix(expr, "!=") {
		n := atoiSafe(expr[2:])
		return actual != n
	}
	n := atoiSafe(expr)
	return actual == n
}

func matchTime(m types.Matcher, ctx *MatchContext) bool {
	expr := strings.TrimSpace(m.Time)
	if expr == "" {
		return false
	}
	seconds := ctx.ResponseTime.Seconds()

	// Parse operator
	if strings.HasPrefix(expr, ">=") {
		n := parseFloatSafe(expr[2:])
		return seconds >= n
	}
	if strings.HasPrefix(expr, "<=") {
		n := parseFloatSafe(expr[2:])
		return seconds <= n
	}
	if strings.HasPrefix(expr, ">") {
		n := parseFloatSafe(expr[1:])
		return seconds > n
	}
	if strings.HasPrefix(expr, "<") {
		n := parseFloatSafe(expr[1:])
		return seconds < n
	}
	if strings.HasPrefix(expr, "==") {
		n := parseFloatSafe(expr[2:])
		return seconds == n
	}
	n := parseFloatSafe(expr)
	return seconds >= n
}

func matchBinary(m types.Matcher, ctx *MatchContext) bool {
	data := getPart(m, ctx)
	for _, b := range m.Binary {
		// [批次A-5 修复点] binary matcher 的 pattern 是十六进制字符串 (如 "0d0a"),
		// 必须先 hex-decode 成原始字节, 再在响应体中搜索对应的字节序列。
		// 旧实现直接用 strings.Contains 在文本中搜索十六进制字符串本身,
		// 永远不会匹配到真正的二进制内容。
		b = strings.TrimSpace(b)
		// Normalize: strip optional "0x" prefix and spaces between byte groups
		b = strings.ReplaceAll(b, " ", "")
		if strings.HasPrefix(b, "0x") || strings.HasPrefix(b, "0X") {
			b = b[2:]
		}
		if b == "" {
			continue
		}
		needleBytes, err := hexDecodeString(b)
		if err != nil {
			continue // invalid hex — skip this pattern
		}
		if strings.Contains(data, string(needleBytes)) {
			return true
		}
	}
	return false
}

// hexDecodeString decodes a hex string into bytes, tolerant of odd-length
// input by left-padding with a zero nibble (common in shorthand patterns).
func hexDecodeString(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		s = "0" + s
	}
	return hex.DecodeString(s)
}

// matchJSONWord parses the response body as JSON, navigates to a JSON array
// (default path "data"), and runs case-insensitive substring matching on each
// element's field (default "name").
//
// Use case: ceye.io API returns
//
//	{"meta":{"code":200,"message":"OK"},"data":[{"name":"http://...ceye.io/",...}, ...]}
//
// The name field for type=dns is case-mixed (e.g. "gS-xxxx.LBWssd.ceye.iO"),
// while our oob_label is always lowercase. Case-insensitive JSON-array match
// handles both reliably.
//
// Configurable via matcher:
//   json-path:    path to the array (default "data")
//   json-field:   field name in each array element (default "name")
//   words:        substring list to match
//   case-insensitive: enable lowercase comparison (default: true for json-word)
//   condition:    "and" / "or" across words
//   debug:        print per-element matching trace to stderr
func matchJSONWord(m types.Matcher, ctx *MatchContext) (bool, string) {
	if len(m.Words) == 0 {
		return false, ""
	}

	// Parse body as generic JSON object
	var root map[string]interface{}
	if err := json.Unmarshal([]byte(ctx.Body), &root); err != nil {
		// [批次B-3 修复点] 改走 Debug 回调, 不再直接写 stderr
		ctx.debugf("[json-word] json.Unmarshal failed: %v\n  body=%q", err, truncate(ctx.Body, 200))
		return false, ""
	}

	path := m.JSONPath
	if path == "" {
		path = "data"
	}
	field := m.JSONField
	if field == "" {
		field = "name"
	}

	// Navigate to the JSON array
	rawArr, ok := root[path]
	if !ok {
		ctx.debugf("[json-word] key %q not found in JSON root, keys=%v", path, mapKeys(root))
		return false, ""
	}
	arr, ok := rawArr.([]interface{})
	if !ok {
		ctx.debugf("[json-word] %q is not an array (got %T)", path, rawArr)
		return false, ""
	}

	// OOB scenario default: ALWAYS case-insensitive comparison unless user explicitly disables.
	ci := m.CaseInsensitive
	if !ci {
		// json-word is designed for OOB record lookups, force CI even if user forgot.
		ci = true
	}

	// Collect all field values from array elements (raw + lowercase copy)
	var rawVals []string
	var cmpVals []string
	for _, item := range arr {
		obj, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		v, ok := obj[field].(string)
		if !ok {
			continue
		}
		rawVals = append(rawVals, v)
		cmpVals = append(cmpVals, strings.ToLower(v))
	}

	if len(cmpVals) == 0 {
		ctx.debugf("[json-word] empty cmpVals: arr_len=%d, raw_body=%q", len(arr), truncate(ctx.Body, 400))
		return false, ""
	}

	// Prepare lowercase word list
	cmpWords := make([]string, len(m.Words))
	for i, w := range m.Words {
		cmpWords[i] = strings.ToLower(w)
	}

	cond := strings.ToLower(m.Condition)
	if cond == "" {
		cond = "or"
	}

	// Match logic: for each word, look for a substring match across any array value
	all := true
	any := false
	seen := make(map[string]bool)
	var evidence []string
	for _, w := range cmpWords {
		matchedWord := false
		for vi, val := range cmpVals {
			if strings.Contains(val, w) {
				matchedWord = true
				any = true
				if !seen[rawVals[vi]] {
					seen[rawVals[vi]] = true
					evidence = append(evidence, rawVals[vi])
				}
			}
		}
		if !matchedWord {
			all = false
		}
	}

	var result bool
	if cond == "and" {
		result = all
	} else {
		result = any
	}

	// [批次B-3 修复点] OOB 可见性日志改走 Debug 回调
	ctx.debugf("[json-word] arr_len=%d, field=%q, words=%v(lower=%v), matched=%v, evidence=%v",
		len(arr), field, m.Words, cmpWords, result, evidence)

	ev := ""
	if len(evidence) > 0 {
		ev = "json-word: " + strings.Join(evidence, ", ")
	}
	return result, ev
}

// matchJSON2DArray matches against dnslog.cn-style responses:
//   Case A (root array): [["domain","ip","time"],...]
//     yaml: type: json-2darray, json-path: "", json-2darray-column: 0, words: ["{{oob_label}}"]
//   Case B (nested): {"code":200,"data":[["domain","ip","time"],...]}
//     yaml: type: json-2darray, json-path: data, json-2darray-column: 0, words: ["{{oob_label}}"]
//
// Parses the JSON array, checks each row's column N for a substring match
// against the provided words (case-insensitive, same as json-word).
func matchJSON2DArray(m types.Matcher, ctx *MatchContext) (bool, string) {
	if len(m.Words) == 0 {
		return false, ""
	}

	path := m.JSONPath
	colIdx := m.JSON2DColumn
	if colIdx < 0 {
		colIdx = 0
	}

	// Try root-level array first: [["domain","ip","time"],...]
	var rawArr []interface{}
	if err := json.Unmarshal([]byte(ctx.Body), &rawArr); err == nil {
		// root is an array — use it directly
		return match2DArrayRows(rawArr, colIdx, m.Words, m.Condition, ctx, "")
	}

	// Try object with nested array: {"data":[...]}
	var root map[string]interface{}
	if err := json.Unmarshal([]byte(ctx.Body), &root); err != nil {
		ctx.debugf("[json-2darray] json.Unmarshal failed: %v\n  body=%q", err, truncate(ctx.Body, 200))
		return false, ""
	}

	if path == "" {
		path = "data"
	}
	rawArr2, ok := root[path]
	if !ok {
		ctx.debugf("[json-2darray] key %q not found in JSON root, keys=%v", path, mapKeys(root))
		return false, ""
	}
	arr, ok := rawArr2.([]interface{})
	if !ok {
		ctx.debugf("[json-2darray] %q is not an array (got %T)", path, rawArr2)
		return false, ""
	}
	return match2DArrayRows(arr, colIdx, m.Words, m.Condition, ctx, path)
}

// match2DArrayRows extracts string values from a 2D array and matches against words.
func match2DArrayRows(arr []interface{}, colIdx int, words []string, cond string, ctx *MatchContext, path string) (bool, string) {
	var matches []string
	for _, item := range arr {
		row, ok := item.([]interface{})
		if !ok || colIdx >= len(row) {
			continue
		}
		val, ok := row[colIdx].(string)
		if !ok {
			continue
		}
		matches = append(matches, val)
	}

	if len(matches) == 0 {
		ctx.debugf("[json-2darray] empty matches: arr_len=%d, col=%d, path=%q, raw_body=%q",
			len(arr), colIdx, path, truncate(ctx.Body, 400))
		return false, ""
	}

	// Case-insensitive comparison (same as json-word)
	cmpMatches := make([]string, len(matches))
	for i, v := range matches {
		cmpMatches[i] = strings.ToLower(v)
	}
	cmpWords := make([]string, len(words))
	for i, w := range words {
		cmpWords[i] = strings.ToLower(w)
	}

	cond = strings.ToLower(cond)
	if cond == "" {
		cond = "or"
	}

	all := true
	any := false
	seen := make(map[string]bool)
	var evidence []string
	for _, w := range cmpWords {
		matchedWord := false
		for vi, val := range cmpMatches {
			if strings.Contains(val, w) {
				matchedWord = true
				any = true
				if !seen[matches[vi]] {
					seen[matches[vi]] = true
					evidence = append(evidence, matches[vi])
				}
			}
		}
		if !matchedWord {
			all = false
		}
	}

	var result bool
	if cond == "and" {
		result = all
	} else {
		result = any
	}

	ctx.debugf("[json-2darray] arr_len=%d, col=%d, path=%q, words=%v(lower=%v), matched=%v, evidence=%v",
		len(arr), colIdx, path, words, cmpWords, result, evidence)

	ev := ""
	if len(evidence) > 0 {
		ev = "json-2darray: " + strings.Join(evidence, ", ")
	}
	return result, ev
}

// truncate returns the first n bytes of s with an ellipsis marker if truncated.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated " + strconv.Itoa(len(s)-n) + " bytes)"
}

// mapKeysJSON extracts keys from a JSON map for debug output.
func mapKeys(m map[string]interface{}) []string {
	return utils.MapKeys(m)
}

func atoiSafe(s string) int {
	return utils.AtoiSafe(s)
}

func parseFloatSafe(s string) float64 {
	s = strings.TrimSpace(s)
	n, _ := strconv.ParseFloat(s, 64)
	return n
}
