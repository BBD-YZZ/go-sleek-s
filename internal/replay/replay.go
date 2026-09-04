package replay

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gosleek/gosleek/internal/httpclient"
	"github.com/gosleek/gosleek/internal/logutil"
)

// Session represents a single replay operation: one request sent, one response
// received, optionally compared with a previous response.
type Session struct {
	// Input
	RequestFile string // path to raw request file
	BaseURL     string // target URL (overwrites Host header if given)
	Proxy       string // HTTP/SOCKS5 proxy
	Insecure    bool   // skip TLS verification

	// Output
	OutputDir  string // directory to save response files
	Save       bool   // whether to save response to disk
	Compare    bool   // compare with a previous response file
	OldPath    string // path to previous response for comparison

	// Verbosity
	Verbose int // 0=normal, 1=-v, 2=-vv

	// Results
	RequestRaw    string            // original raw request (before global headers)
	ResponseRaw   string            // raw response
	StatusCode    int               // response status code
	ResponseTime  time.Duration     // response time
	Headers       map[string][]string // response headers
	Body          string            // response body
	Error         error             // send error, if any
}

// Result aggregates replay results for display and comparison.
type Result struct {
	Target       string
	StatusCode   int
	ResponseTime time.Duration
	Headers      map[string][]string
	Body         string
	Raw          string
	SavedPath    string
	Error        error
	Compare      CompareResult // diff against previous response
}

// CompareResult holds the diff between two responses.
type CompareResult struct {
	HasDiff       bool
	StatusChanged bool
	BodyChanged   bool
	BodyDiff      string
	HeaderDiff    string
}

// Run executes a replay session and returns the result.
func (s *Session) Run(ctx context.Context) (*Result, error) {
	// Read request file
	rawReq, err := s.readRequest()
	if err != nil {
		return nil, fmt.Errorf("读取请求文件失败: %w", err)
	}
	logutil.Log("info", "回放", "读取请求文件: %s (%d bytes)", s.RequestFile, len(rawReq))
	s.RequestRaw = rawReq

	// Inject global headers (User-Agent from config)
	client := s.buildClient()
	rawReq = client.InjectGlobalHeaders(rawReq)

	// Parse and send
	parsed, err := httpclient.ParseRaw(rawReq)
	if err != nil {
		return nil, fmt.Errorf("解析请求失败: %w", err)
	}

	resp, err := client.SendParsed(ctx, s.BaseURL, parsed)
	if err != nil {
		return nil, fmt.Errorf("发送请求失败: %w", err)
	}
	logutil.Log("info", "回放", "请求完成: target=%s status=%d time=%s body=%d bytes", s.BaseURL, resp.StatusCode, resp.Time, len(resp.Body))

	// Build result
	result := &Result{
		Target:       s.BaseURL,
		StatusCode:   resp.StatusCode,
		ResponseTime: resp.Time,
		Headers:      resp.Headers,
		Body:         resp.Body,
		Raw:          resp.Raw,
		Error:        nil,
	}

	s.ResponseRaw = resp.Raw
	s.StatusCode = resp.StatusCode
	s.ResponseTime = resp.Time
	s.Headers = resp.Headers
	s.Body = resp.Body

	// Save response if requested
	if s.Save {
		path, err := s.saveResponse(result)
		if err == nil {
			result.SavedPath = path
		}
	}

	// Compare if requested
	if s.Compare {
		compare, err := s.compareResponse(result)
		if err == nil {
			result.Compare = compare
		}
	}

	return result, nil
}

// readRequest reads the raw HTTP request from the specified file.
func (s *Session) readRequest() (string, error) {
	data, err := os.ReadFile(s.RequestFile)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// buildClient creates an httpclient.Client configured for replay.
func (s *Session) buildClient() *httpclient.Client {
	cfg := httpclient.ClientConfig{
		Timeout:        30 * time.Second,
		MaxRetries:     0,
		MaxRedirects:   3,
		FollowRedirect: true,
		Proxy:          s.Proxy,
		Insecure:       s.Insecure,
		MaxBodySize:    10 * 1024 * 1024, // 10MB
		UserAgent:      "gosleek-replay/1.0",
	}
	return httpclient.New(cfg)
}

// saveResponse writes the response to a file in the output directory.
func (s *Session) saveResponse(r *Result) (string, error) {
	if !s.Save {
		return "", nil
	}
	timestamp := time.Now().Format("20060102-150405")
	dir := s.OutputDir
	if dir == "" {
		dir = "./responses"
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}

	// Generate filename from target
	safeTarget := strings.ReplaceAll(s.BaseURL, "://", "_")
	safeTarget = strings.ReplaceAll(safeTarget, "/", "_")
	safeTarget = strings.ReplaceAll(safeTarget, ":", "_")
	if len(safeTarget) > 50 {
		// Use first 40 chars + last 10 chars to reduce collision
		safeTarget = safeTarget[:40] + "_" + safeTarget[len(safeTarget)-10:]
	}

	// Status-code based filename
	filename := fmt.Sprintf("%s_%d_%s.txt", safeTarget, r.StatusCode, timestamp)
	path := filepath.Join(dir, filename)

	var content strings.Builder
	content.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\r\n", r.StatusCode,
		httpStatusText(r.StatusCode)))
	for k, vs := range r.Headers {
		for _, v := range vs {
			content.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
		}
	}
	content.WriteString("\r\n")
	content.WriteString(r.Body)

	return path, os.WriteFile(path, []byte(content.String()), 0644)
}

// compareResponse compares the current response with a previously saved one.
func (s *Session) compareResponse(current *Result) (CompareResult, error) {
	// Read previous response
	prevData, err := os.ReadFile(s.OldPath)
	if err != nil {
		return CompareResult{}, fmt.Errorf("读取历史响应失败: %w", err)
	}

	prev := parseResponse(string(prevData))
	cur := parseResponse(current.Raw)

	var result CompareResult

	// Status code comparison
	if prev.StatusCode != cur.StatusCode {
		result.StatusChanged = true
	}

	// Body comparison using diff
	if result.StatusChanged || s.Verbose >= 1 {
		bodyDiff := diffStrings(prev.Body, cur.Body)
		if bodyDiff != "" {
			result.BodyChanged = true
			result.BodyDiff = bodyDiff
		}
	}

	// Header comparison
	headerDiff := diffMap(prev.Headers, cur.Headers)
	if headerDiff != "" {
		result.HeaderDiff = headerDiff
	}

	result.HasDiff = result.StatusChanged || result.BodyChanged || result.HeaderDiff != ""
	return result, nil
}

// parseResponse parses a raw HTTP response string.
func parseResponse(raw string) (resp struct {
	StatusCode int
	Headers    map[string][]string
	Body       string
}) {
	resp.Headers = make(map[string][]string)
	lines := strings.Split(raw, "\r\n")
	if len(lines) == 0 {
		return
	}

	// Parse status line
	parts := strings.Fields(lines[0])
	if len(parts) >= 2 {
		fmt.Sscanf(parts[1], "%d", &resp.StatusCode)
	}

	// Parse headers
	i := 1
	for i < len(lines) && lines[i] != "" {
		idx := strings.Index(lines[i], ":")
		if idx > 0 {
			key := lines[i][:idx]
			val := strings.TrimSpace(lines[i][idx+1:])
			resp.Headers[key] = append(resp.Headers[key], val)
		}
		i++
	}

	// Body is everything after the blank line
	if i < len(lines) {
		resp.Body = strings.Join(lines[i+1:], "\r\n")
	}

	return
}

// diffStrings produces a simple line-level diff between two strings.
func diffStrings(old, newStr string) string {
	oldLines := strings.Split(old, "\n")
	newLines := strings.Split(newStr, "\n")

	var result strings.Builder
	maxLen := len(oldLines)
	if len(newLines) > maxLen {
		maxLen = len(newLines)
	}

	for i := 0; i < maxLen; i++ {
		var oldLine, newLine string
		if i < len(oldLines) {
			oldLine = oldLines[i]
		}
		if i < len(newLines) {
			newLine = newLines[i]
		}

		if oldLine == newLine {
			if result.Len() > 0 && result.Len() < 2000 {
				result.WriteString(oldLine + "\n")
			}
		} else {
			if result.Len() < 2000 {
				if i < len(oldLines) {
					result.WriteString(fmt.Sprintf("- %s\n", oldLine))
				}
				if i < len(newLines) {
					result.WriteString(fmt.Sprintf("+ %s\n", newLine))
				}
			}
		}
	}

	return result.String()
}

// diffMap produces a simple diff between two header maps.
// Headers that commonly change between requests (Response-Time, etc.) are ignored.
func diffMap(old, newMap map[string][]string) string {
	// Headers to ignore when comparing (commonly change between requests)
	ignoreHeaders := map[string]bool{
		"Response-Time": true,
		"X-Response-Time": true,
		"Date": true,
		"Server": true,
	}

	var result strings.Builder
	allKeys := make(map[string]bool)
	for k := range old {
		allKeys[k] = true
	}
	for k := range newMap {
		allKeys[k] = true
	}

	for k := range allKeys {
		// Skip ignored headers
		if ignoreHeaders[k] {
			continue
		}
		oldVals, oldOk := old[k]
		newVals, newOk := newMap[k]
		if !oldOk {
			for _, v := range newVals {
				result.WriteString(fmt.Sprintf("+ Header: %s: %s\n", k, v))
			}
		} else if !newOk {
			for _, v := range oldVals {
				result.WriteString(fmt.Sprintf("- Header: %s: %s\n", k, v))
			}
		} else if fmt.Sprintf("%v", oldVals) != fmt.Sprintf("%v", newVals) {
			result.WriteString(fmt.Sprintf("- Header: %s: %v\n", k, oldVals))
			result.WriteString(fmt.Sprintf("+ Header: %s: %v\n", k, newVals))
		}
	}

	return result.String()
}

// normalizeBody strips common variable fields from response body for comparison.
// This helps reduce false positives in diff output.
func normalizeBody(body string) string {
	// Replace Response-Time header if present
	normalized := strings.ReplaceAll(body, "\r\nResponse-Time: ", "\r\nX-Response-Time: <stripped>\r\n")
	// Replace UUID-like patterns
	normalized = strings.ReplaceAll(normalized, "\r\nX-Cf-Ray: ", "\r\nX-Cf-Ray: <stripped>\r\n")
	return normalized
}

// httpStatusText returns the HTTP status text for a given code.
func httpStatusText(code int) string {
	switch code {
	case 200:
		return "OK"
	case 201:
		return "Created"
	case 204:
		return "No Content"
	case 301:
		return "Moved Permanently"
	case 302:
		return "Found"
	case 304:
		return "Not Modified"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 500:
		return "Internal Server Error"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	default:
		return fmt.Sprintf("%d", code)
	}
}
