package httpclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gosleek/gosleek/internal/placeholder"
	"github.com/gosleek/gosleek/internal/ratelimit"
)

// RawRequest holds a parsed raw HTTP request.
type RawRequest struct {
	Method  string
	Path    string // URL path including query
	Headers map[string]string
	Body    string
}

// Response is a captured HTTP response with timing.
type Response struct {
	StatusCode int
	Headers    map[string][]string
	Body       string
	Raw        string // full raw response for replay
	Time       time.Duration // elapsed time
}

// Client wraps http.Client with retry, rate-limit, and connection pooling.
type Client struct {
	httpClient     *http.Client
	limiter        *ratelimit.Limiter
	maxRetries     int
	backoff        time.Duration
	userAgent      string
	followRedirect bool // default: follow up to MaxRedirects; false = never follow
	maxBodySize    int64 // 0 = unlimited
	allowExternal  bool // allow Host header to redirect to different hosts
	globalHeaders  map[string]string // global CLI headers injected into raw request text
}

// ClientConfig configures the HTTP client.
type ClientConfig struct {
	Timeout          time.Duration
	MaxRetries       int
	Backoff          time.Duration
	RateLimit        int
	Proxy            string
	UserAgent        string
	MaxRedirects     int
	Insecure         bool
	FollowRedirect   bool // default per-request behavior; true = respect MaxRedirects
	MaxBodySize      int64 // max response body size in bytes (0 = unlimited)
	AllowExternal    bool // allow Host header to redirect to different hosts
}

// New creates a new HTTP client.
func New(cfg ClientConfig) *Client {
	// Dial timeout is separate from request timeout.
	// A short request timeout (e.g. 10s for a local target) should NOT
	// cause DNS resolution or TCP connect to fail when reaching external
	// hosts like api.ceye.io — those can legitimately take 5-10s.
	dialTimeout := cfg.Timeout
	if dialTimeout < 30*time.Second {
		dialTimeout = 30 * time.Second
	}

	transport := &http.Transport{
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.Insecure, // controlled by -verify-ssl flag
		},
		DialContext: (&net.Dialer{
			Timeout:   dialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	// Proxy support: HTTP and SOCKS5
	if cfg.Proxy != "" {
		setupProxy(transport, cfg.Proxy, cfg.Timeout)
	}

	checkRedirect := func(req *http.Request, via []*http.Request) error {
		if len(via) >= cfg.MaxRedirects {
			return http.ErrUseLastResponse
		}
		return nil
	}
	if cfg.MaxRedirects == 0 {
		checkRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	limiter := ratelimit.New(cfg.RateLimit)

	client := &http.Client{
		Transport:     transport,
		CheckRedirect: checkRedirect,
	}

	return &Client{
		httpClient:     client,
		limiter:        limiter,
		maxRetries:     cfg.MaxRetries,
		backoff:        cfg.Backoff,
		userAgent:      cfg.UserAgent,
		followRedirect: cfg.FollowRedirect,
		maxBodySize:    cfg.MaxBodySize,
		allowExternal:  cfg.AllowExternal,
	}
}

// setupProxy configures HTTP or SOCKS5 proxy on the transport.
//
// Supported formats:
//   http://[user:pass@]host:port
//   https://[user:pass@]host:port
//   socks5://[user:pass@]host:port
//   socks5h://[user:pass@]host:port   (hostname resolved by proxy)
//
// For passwords containing special characters like '@', either:
//   - URL-encode them: socks5://admin%40123:p%40ssw0rd@127.0.0.1:1080
//   - Or rely on Go's url.Parse which finds the LAST '@' as the userinfo/host separator
func setupProxy(transport *http.Transport, proxyStr string, timeout time.Duration) {
	proxyURL, err := url.Parse(proxyStr)
	if err != nil {
		return
	}

	scheme := strings.ToLower(proxyURL.Scheme)
	switch scheme {
	case "socks5", "socks5h":
		// Extract auth credentials from URL
		var username, password string
		if proxyURL.User != nil {
			username = proxyURL.User.Username()
			password, _ = proxyURL.User.Password()
		}

		dialer := &socks5Dialer{
			proxyAddr: proxyURL.Host,
			username:  username,
			password:  password,
			timeout:   timeout,
		}
		transport.DialContext = dialer.DialContext
		// Clear any HTTP proxy setting
		transport.Proxy = nil

	default:
		// HTTP / HTTPS proxy — http.ProxyURL handles auth via URL
		transport.Proxy = http.ProxyURL(proxyURL)
	}
}

// SetGlobalHeaders injects global CLI headers into the raw request text
// before sending. This ensures headers appear in -vv output and are sent
// for both plugin (SendRaw) and workflow (SendParsed) paths.
func (c *Client) SetGlobalHeaders(headers map[string]string) {
	if c.globalHeaders == nil {
		c.globalHeaders = make(map[string]string)
	}
	for k, v := range headers {
		c.globalHeaders[k] = v
	}
}

// HTTPClient returns the underlying *http.Client for direct use.
func (c *Client) HTTPClient() *http.Client {
	return c.httpClient
}
func ParseRaw(raw string) (*RawRequest, error) {
	// Normalize line endings
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	raw = strings.ReplaceAll(raw, "\n", "\r\n")

	reader := bufio.NewReader(strings.NewReader(raw))

	// First line: METHOD PATH HTTP/1.1
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read request line: %w", err)
	}
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid request line: %s", line)
	}

	req := &RawRequest{
		Method:  parts[0],
		Path:    parts[1],
		Headers: make(map[string]string),
	}

	// Read headers
	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break // end of headers
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		req.Headers[key] = val
	}

	// Read body (remaining)
	body, _ := io.ReadAll(reader)
	req.Body = strings.TrimRight(string(body), "\r\n")

	return req, nil
}

// SendRaw sends a raw HTTP request to the given base URL.
// Global headers (from -H/--header) are injected into the raw request text
// before parsing, so they appear in -vv output and are actually sent.
func (c *Client) SendRaw(ctx context.Context, baseURL string, raw string) (*Response, error) {
	raw = c.InjectGlobalHeaders(raw)
	parsed, err := ParseRaw(raw)
	if err != nil {
		return nil, err
	}
	return c.SendParsed(ctx, baseURL, parsed)
}

// SendParsed sends a parsed raw request to the given base URL.
func (c *Client) SendParsed(ctx context.Context, baseURL string, req *RawRequest) (*Response, error) {
	// Inject config user-agent into raw request text so it appears in -vv output.
	c.injectConfigUserAgent(req)
	// Determine host for rate limiting
	host := baseURL
	if u, err := url.Parse(baseURL); err == nil {
		host = u.Host
	}
	// [批次A-2 修复点] 限流器现在真正消费令牌, 此处 Wait 会阻塞直到有令牌可用
	c.limiter.Wait(host)

	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(c.backoff * time.Duration(1<<(attempt-1)))
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}

		resp, err := c.doRequest(ctx, baseURL, req)
		if err != nil {
			lastErr = err
			// Don't retry if the context is already expired
			if ctx.Err() != nil {
				break
			}
			continue
		}
		// Per-request redirect override: if context says do not follow,
		// and the response is a redirect, drop through so caller sees it.
		if isRedirect(resp.StatusCode) {
			if v, ok := ctx.Value(ContextKeyFollowRedirects{}).(bool); ok && !v {
				return resp, nil
			}
		}
		return resp, nil
	}
	return nil, fmt.Errorf("after %d retries: %w", c.maxRetries, lastErr)
}

func isRedirect(code int) bool {
	return code == http.StatusMovedPermanently ||
		code == http.StatusFound ||
		code == http.StatusSeeOther ||
		code == http.StatusTemporaryRedirect ||
		code == http.StatusPermanentRedirect
}

func (c *Client) doRequest(ctx context.Context, baseURL string, rawReq *RawRequest) (*Response, error) {
	// Build full URL
	//
	// Three cases:
	//  1. Path is a full URL (starts with http:// or https://) → use directly
	//  2. Path is relative AND the raw request has a Host header that differs
	//     from the target host (e.g., "Host: api.ceye.io") → construct URL
	//     using the Host header. Default to https for external hosts.
	//  3. Otherwise → concatenate baseURL + path (normal case)
	fullURL := ""

	pathLower := strings.ToLower(rawReq.Path)
	if strings.HasPrefix(pathLower, "http://") || strings.HasPrefix(pathLower, "https://") {
		// Case 1: full URL in path
		fullURL = rawReq.Path
	} else {
		// Strip trailing slash from baseURL to avoid double slashes
		// e.g., "http://host:8080/" + "/" = "http://host:8080//" (bad)
		cleanBase := strings.TrimRight(baseURL, "/")

		// Check if the raw request specifies a different Host
		rawHost := getHeaderCI(rawReq.Headers, "Host")
		if rawHost != "" {
			targetURL, err := url.Parse(baseURL)
			if err == nil && !isSameTarget(rawHost, targetURL.Host) {
				// Case 2: Host header points to a different server
				// (e.g., ceye API verification step)
				// SSRF protection: only allow external host redirect if explicitly enabled
				if !c.allowExternal {
					return nil, fmt.Errorf("SSRF防护: Host header指向外部主机 %s，已拒绝（使用 --allow-external-hosts 启用）", rawHost)
				}
				scheme := "http"
				if strings.HasPrefix(pathLower, "/") {
					fullURL = scheme + "://" + rawHost + rawReq.Path
				} else {
					fullURL = scheme + "://" + rawHost + "/" + rawReq.Path
				}
			} else {
				// Case 3: same host — use baseURL + path
				if strings.HasPrefix(rawReq.Path, "/") {
					fullURL = cleanBase + rawReq.Path
				} else {
					fullURL = cleanBase + "/" + rawReq.Path
				}
			}
		} else {
			if strings.HasPrefix(rawReq.Path, "/") {
				fullURL = cleanBase + rawReq.Path
			} else {
				fullURL = cleanBase + "/" + rawReq.Path
			}
		}
	}

	// Create request
	var bodyReader io.Reader
	if rawReq.Body != "" {
		bodyReader = strings.NewReader(rawReq.Body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, rawReq.Method, fullURL, bodyReader)
	if err != nil {
		return nil, err
	}

	// Auto-compute Content-Length for body requests to improve
	// compatibility with servers that require a correct body length
	// (e.g. when sending POST/PUT raw requests). Only set it when the
	// caller did not already provide an explicit Content-Length, since a
	// manually-specified value should win (e.g. chunked-equivalent cases).
	if rawReq.Body != "" && getHeaderCI(rawReq.Headers, "Content-Length") == "" {
		httpReq.ContentLength = int64(len(rawReq.Body))
		httpReq.Header.Set("Content-Length", fmt.Sprintf("%d", len(rawReq.Body)))
	}

	// Set headers from raw request (skip Host — it's determined by the URL)
	for k, v := range rawReq.Headers {
		if strings.EqualFold(k, "Host") {
			continue
		}
		// For headers with dots in the name (e.g.,
		// spring.cloud.function.routing-expression), preserve the original
		// case — Go's Header.Set canonicalizes keys, which can break
		// case-sensitive servers.
		if strings.Contains(k, ".") {
			httpReq.Header[k] = []string{v}
		} else {
			httpReq.Header.Set(k, v)
		}
	}
	// Set default User-Agent if not provided
	if httpReq.Header.Get("User-Agent") == "" && c.userAgent != "" {
		httpReq.Header.Set("User-Agent", c.userAgent)
	}

	// Send
	start := time.Now()
	// Use cookie jar from context if present
	client := c.httpClient
	if jar := getCookieJar(ctx); jar != nil {
		client = &http.Client{
			Transport: c.httpClient.Transport,
			Jar:       jar,
		}
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// Check if body was truncated
	if c.maxBodySize > 0 && int64(len(bodyBytes)) >= c.maxBodySize {
		bodyBytes = bodyBytes[:c.maxBodySize]
		// Drain remaining body to avoid connection reuse issues
		io.Copy(io.Discard, resp.Body)
	}
	elapsed := time.Since(start)

	// Decompress body based on Content-Encoding header
	contentType := resp.Header.Get("Content-Type")
	contentEncoding := resp.Header.Get("Content-Encoding")
	bodyBytes, contentType = decompressBody(bodyBytes, contentType, contentEncoding)

	// Fix character encoding (GBK, etc.)
	bodyBytes = fixEncoding(bodyBytes, contentType)

	// Build response headers map
	headers := make(map[string][]string)
	for k, v := range resp.Header {
		headers[k] = v
	}

	// Build raw response for replay
	raw := buildRawResponse(resp, bodyBytes, elapsed)

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       string(bodyBytes),
		Raw:        raw,
		Time:       elapsed,
	}, nil
}

func buildRawResponse(resp *http.Response, body []byte, elapsed time.Duration) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("HTTP/%d.%d %d %s\r\n", resp.ProtoMajor, resp.ProtoMinor,
		resp.StatusCode, http.StatusText(resp.StatusCode)))
	for k, vs := range resp.Header {
		for _, v := range vs {
			sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
		}
	}
	sb.WriteString(fmt.Sprintf("Response-Time: %s\r\n", elapsed))
	sb.WriteString("\r\n")
	sb.Write(body)
	return sb.String()
}

// getHeaderCI does a case-insensitive lookup in a map.
func getHeaderCI(headers map[string]string, key string) string {
	for k, v := range headers {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

// isSameTarget reports whether the raw Host header value and the target URL
// host refer to the same server. This prevents the "different host" code path
// from firing when the only difference is a missing port or default port.
//
// Examples:
//
//	isSameTarget("192.168.80.128:8080", "192.168.80.128:8080") → true
//	isSameTarget("example.com",         "example.com")         → true
//	isSameTarget("api.ceye.io",         "192.168.80.128:8080") → false
//	isSameTarget("example.com",         "example.com:8080")    → false  (port mismatch)
//	isSameTarget("example.com:80",      "example.com")         → true   (default port)
func isSameTarget(rawHost, targetHost string) bool {
	// Fast path: exact match (case-insensitive)
	if strings.EqualFold(rawHost, targetHost) {
		return true
	}

	// Split into hostname + port
	rawHostname, rawPort := splitHostPort(rawHost)
	targetHostname, targetPort := splitHostPort(targetHost)

	// Hostnames must match (case-insensitive)
	if !strings.EqualFold(rawHostname, targetHostname) {
		return false
	}

	// If both have ports, they must match
	if rawPort != "" && targetPort != "" {
		return rawPort == targetPort
	}

	// If only one has a port, check if it's a default port (80/443)
	// "example.com" vs "example.com:80" → same (80 is default for http)
	// "example.com" vs "example.com:8080" → different (non-default port)
	if rawPort == "" && targetPort != "" {
		return targetPort == "80" || targetPort == "443"
	}
	if rawPort != "" && targetPort == "" {
		return rawPort == "80" || rawPort == "443"
	}

	// Both empty — shouldn't reach here (caught by fast path), but handle it
	return true
}

// splitHostPort splits a host:port string into hostname and port.
// Unlike net.SplitHostPort, it doesn't error on missing port — just returns
// empty string for the port.
func splitHostPort(host string) (hostname, port string) {
	// Handle IPv6 addresses like [::1]:8080
	if strings.HasPrefix(host, "[") {
		idx := strings.LastIndex(host, "]")
		if idx >= 0 {
			hostname = host[:idx+1]
			if idx+1 < len(host) && host[idx+1] == ':' {
				port = host[idx+2:]
			}
			return
		}
	}
	// Regular host:port or just host
	idx := strings.LastIndex(host, ":")
	if idx < 0 {
		return host, ""
	}
	return host[:idx], host[idx+1:]
}

// GetHeader returns the first value of a header (case-insensitive).
func (r *Response) GetHeader(key string) string {
	for k, vs := range r.Headers {
		if strings.EqualFold(k, key) {
			if len(vs) > 0 {
				return vs[0]
			}
		}
	}
	return ""
}

// ResolveURL returns the full URL that would be used for a request.
// This is useful for logging when the actual URL differs from baseURL
// (e.g., ceye API steps where Host header overrides the target).
func ResolveURL(baseURL string, rawReq *RawRequest) string {
	pathLower := strings.ToLower(rawReq.Path)
	if strings.HasPrefix(pathLower, "http://") || strings.HasPrefix(pathLower, "https://") {
		return rawReq.Path
	}
	cleanBase := strings.TrimRight(baseURL, "/")
	rawHost := getHeaderCI(rawReq.Headers, "Host")
	if rawHost != "" {
		targetURL, err := url.Parse(baseURL)
		if err == nil && !isSameTarget(rawHost, targetURL.Host) {
			scheme := "http"
			if strings.HasPrefix(pathLower, "/") {
				return scheme + "://" + rawHost + rawReq.Path
			}
			return scheme + "://" + rawHost + "/" + rawReq.Path
		}
	}
	if strings.HasPrefix(rawReq.Path, "/") {
		return cleanBase + rawReq.Path
	}
	return cleanBase + "/" + rawReq.Path
}

// AllHeaders returns all headers as a single string for matching.
func (r *Response) AllHeaders() string {
	var sb strings.Builder
	for k, vs := range r.Headers {
		for _, v := range vs {
			sb.WriteString(fmt.Sprintf("%s: %s\n", k, v))
		}
	}
	return sb.String()
}

// RawRequestString converts a RawRequest back to a raw string.
func (r *RawRequest) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", r.Method, r.Path))
	for k, v := range r.Headers {
		sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	sb.WriteString("\r\n")
	sb.WriteString(r.Body)
	return sb.String()
}

// ParseRawBytes parses raw HTTP request from bytes.
func ParseRawBytes(raw []byte) (*RawRequest, error) {
	return ParseRaw(string(raw))
}

// InjectGlobalHeaders injects global CLI headers into the raw request text.
// Called in SendRaw and also exported so engine.go can call it.
func (c *Client) InjectGlobalHeaders(raw string) string {
	if len(c.globalHeaders) == 0 {
		return raw
	}
	sep := "\r\n\r\n"
	idx := strings.Index(raw, sep)
	if idx < 0 {
		idx = strings.Index(raw, "\n\n")
	}
	if idx >= 0 {
		var sb strings.Builder
		sb.WriteString(raw[:idx])
		sb.WriteString("\r\n")
		for k, v := range c.globalHeaders {
			sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
		}
		sb.WriteString(raw[idx:])
		return sb.String()
	}
	// No separator — trim trailing \r\n then append
	raw = strings.TrimRight(raw, "\r\n")
	var sb strings.Builder
	sb.WriteString(raw)
	sb.WriteString("\r\n")
	for k, v := range c.globalHeaders {
		sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	return sb.String()
}

// injectConfigUserAgent injects the config user-agent into the raw request text
// so it appears in -vv output. Only injects if no User-Agent header is present.
func (c *Client) injectConfigUserAgent(req *RawRequest) {
	if req == nil || c.userAgent == "" {
		return
	}
	// Check if any User-Agent header already exists (case-insensitive)
	for k := range req.Headers {
		if strings.EqualFold(k, "User-Agent") {
			return
		}
	}
	req.Headers["User-Agent"] = c.userAgent
}

// ReadAllRaw is a helper to read raw request from a bytes.Reader.
func ReadAllRaw(r *bytes.Reader) (string, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ParseMethodPath extracts the HTTP method and path from a raw HTTP request string.
func ParseMethodPath(raw string) (method, path string) {
	firstLine := strings.SplitN(raw, "\r\n", 2)[0]
	parts := strings.SplitN(firstLine, " ", 3)
	if len(parts) >= 2 {
		return parts[0], parts[1]
	}
	return "?", "?"
}

// BuildRawFromPath constructs a raw HTTP request string from method, path, headers and body.
func BuildRawFromPath(method, path string, headers map[string]string, body string) string {
	return BuildRawFromPathWithBodyType(method, path, headers, body, "")
}

// BuildRawFromPathWithBodyType constructs a raw HTTP request string from method, path,
// headers and body with body type support (form / multipart).
func BuildRawFromPathWithBodyType(method, path string, headers map[string]string, body, bodyType string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", method, path))
	sb.WriteString("Host: {{Hostname}}\r\n")

	if bodyType != "" && body != "" {
		switch strings.ToLower(bodyType) {
		case "form", "form-urlencoded":
			for k, v := range headers {
				sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
			}
			sb.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
			sb.WriteString("Connection: close\r\n")
			sb.WriteString("\r\n")
			sb.WriteString(body)
			return sb.String()
		case "multipart", "multipart-form-data":
			boundary := "----gosleekFormBoundary" + placeholder.RandTextHex(8)
			contentType := "multipart/form-data; boundary=" + boundary
			for k, v := range headers {
				sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
			}
			sb.WriteString("Content-Type: " + contentType + "\r\n")
			sb.WriteString("Connection: close\r\n")
			sb.WriteString("\r\n")
			sb.WriteString(BuildMultipartBody(body, boundary))
			return sb.String()
		}
	}

	for k, v := range headers {
		sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	sb.WriteString("Connection: close\r\n")
	sb.WriteString("\r\n")
	if body != "" {
		sb.WriteString(body)
	}
	return sb.String()
}

// BuildMultipartBody generates a multipart form body from key=value pairs.
func BuildMultipartBody(body, boundary string) string {
	var sb strings.Builder
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, "=")
		if idx < 0 {
			continue
		}
		key := line[:idx]
		value := line[idx+1:]
		sb.WriteString("--" + boundary + "\r\n")
		sb.WriteString(fmt.Sprintf("Content-Disposition: form-data; name=\"%s\"\r\n\r\n", key))
		sb.WriteString(value + "\r\n")
	}
	sb.WriteString("--" + boundary + "--\r\n")
	return sb.String()
}
