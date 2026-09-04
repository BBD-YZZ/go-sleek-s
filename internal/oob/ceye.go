package oob

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/gosleek/gosleek/internal/httpclient"
	"github.com/gosleek/gosleek/internal/logutil"
	"github.com/gosleek/gosleek/internal/placeholder"
)

// ceyeProvider implements Provider for ceye.io.
//
// API format (correct):
//   GET /v1/records?token=TOKEN&type=DNS|HTTP HTTP/1.1
//   Host: api.ceye.io
//   User-Agent: gosleek/1.0
//   Accept: */*
//
// Response: {"data":[{"name":"label.subdomain","time":"...","type":"dns|http",...}]}
//
// Matching strategy: fetch ALL records (no filter), then client-side match
// by checking if any record name contains the label (case-insensitive).
type ceyeProvider struct {
	label       string // gs-xxxxxxxx
	callbackURL string // gs-xxxxxxxx.ceye.io
	token       string // API token
	apiURL      string // custom API URL base (default: https://api.ceye.io)
	pollInterval string
	pollTimeout string
	client      *httpclient.Client // shared client from engine
	verbose     int
	onPacket    func(tag string, summary string, raw string)
	onRaw       func(tag, format string, args ...interface{})
}

func newCeyeProvider(token string) *ceyeProvider {
	return &ceyeProvider{
		token: token,
		apiURL: "http://api.ceye.io",  // ceye API 使用 HTTP，不是 HTTPS
	}
}

func (c *ceyeProvider) Name() string      { return "ceye" }
func (c *ceyeProvider) Label() string     { return c.label }
func (c *ceyeProvider) CallbackURL() string { return c.callbackURL }
func (c *ceyeProvider) Token() string     { return c.token }

// Probe is a no-op for ceye — the label/callbackURL are set externally via Setup.
func (c *ceyeProvider) Probe(ctx context.Context) error { return nil }

// VerifyDNS polls the ceye API for DNS records, then filters by label client-side.
func (c *ceyeProvider) VerifyDNS(ctx context.Context) (bool, error) {
	return c.verifyRecords(ctx, "dns")
}

// VerifyHTTP polls the ceye API for HTTP records, then filters by label client-side.
func (c *ceyeProvider) VerifyHTTP(ctx context.Context) (bool, error) {
	return c.verifyRecords(ctx, "http")
}

func (c *ceyeProvider) verifyRecords(ctx context.Context, recordType string) (bool, error) {
	if c.label == "" {
		return false, fmt.Errorf("ceye: no label, call Setup() first")
	}
	if c.token == "" {
		return false, fmt.Errorf("ceye: no token configured")
	}

	// apiBase is the scheme+host only (no path) — path comes from raw request
	// 默认使用 HTTP，因为 ceye API 不支持 HTTPS
	apiBase := "http://api.ceye.io"
	if c.apiURL != "" {
		if u, err := parseURLNoPath(c.apiURL); err == nil {
			apiBase = u
		}
	}

	// C4 fix: derive the Host header from apiBase instead of hardcoding
	// "api.ceye.io". When the user configures a self-hosted ceye mirror via
	// api-url, the Host header must match the URL host; otherwise doRequest's
	// "Host header points to external host" branch fires SSRF protection
	// (allow-external=false) and every ceye API call fails.
	apiHost := "api.ceye.io"
	if u, err := url.Parse(apiBase); err == nil && u.Host != "" {
		apiHost = u.Host
	}

	// Correct API format: token as query parameter, NO filter parameter.
	// Get ALL records for this type, then filter client-side.
	rawReq := fmt.Sprintf(
		"GET /v1/records?token=%s&type=%s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: gosleek/1.0\r\n"+
			"Accept: */*\r\n"+
			"Connection: close\r\n\r\n",
		url.QueryEscape(c.token),
		recordType,
		apiHost,
	)

	if c.verbose >= 2 && c.onPacket != nil {
		c.onPacket("外带", fmt.Sprintf("ceye %s query  label=%s type=%s", recordType, c.label, recordType), rawReq)
	}
	logutil.Log("info", "外带", "ceye %s 查询: label=%s apiBase=%s", recordType, c.label, apiBase)

	// Build the ceye API poll timeout (default 10s from config.yaml).
	// Add extra buffer for retries: MaxRetries=2 means up to 3 total calls
	// with exponential backoff (2s + 4s = 6s overhead).
	pollTimeout := 10 * time.Second
	if c.pollTimeout != "" {
		if d, err := time.ParseDuration(c.pollTimeout); err == nil && d > 0 {
			pollTimeout = d
		}
	}
	// Ensure enough time for retries: SendParsed retries consume context time.
	// Formula: pollTimeout × (MaxRetries+1) + sum(backoff delays)
	// With MaxRetries=2, Backoff=2s: 10s×3 + 2s + 4s = 36s
	// But we must also respect the parent context (pluginCtx) deadline.
	// Set ceye timeout to min(totalTimeout, remaining pluginCtx time).
	retryBuffer := 12 * time.Second
	attemptTimeout := pollTimeout + retryBuffer/2
	totalTimeout := attemptTimeout*3 + retryBuffer

	// Check if parent context is already expired
	if ctx.Err() != nil {
		return false, ctx.Err()
	}

	// Calculate remaining time in parent context
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		// No deadline in parent context, use our calculated timeout
		ceyeTimeout := totalTimeout
		// Log the computed timeout for debugging (visible at -v or higher).
		if c.verbose >= 1 && c.onRaw != nil {
			c.onRaw("外带", "ceye %s poll timeout: %v (no parent deadline, using calculated)", recordType, ceyeTimeout)
		}
		ceyeCtx, ceyeCancel := context.WithTimeout(context.Background(), ceyeTimeout)
		defer ceyeCancel()

		// Always use the shared client if available — same client as YAML workflow
		var resp *httpclient.Response
		var err error
		if c.client != nil {
			parsed, perr := httpclient.ParseRaw(rawReq)
			if perr != nil {
				return false, fmt.Errorf("ceye request parse failed: %w", perr)
			}
			resp, err = c.client.SendParsed(ceyeCtx, apiBase, parsed)
		} else {
			// Fallback: create a new client with generous timeout.
			// Use apiBase (scheme+host) so the base URL matches the Host header
			// derived above — avoids SSRF-protection false positives for mirrors.
			resp, err = httpclient.New(httpclient.ClientConfig{
				Timeout:        totalTimeout + 30*time.Second, // extra for dial + TLS
				AllowExternal:  true,                         // ceye API is always external
			}).SendRaw(ceyeCtx, apiBase, rawReq)
		}

		if err != nil {
			if c.verbose >= 2 && c.onRaw != nil {
				c.onRaw("外带", "ceye %s query failed: %v", recordType, err)
			}
			return false, fmt.Errorf("ceye API request failed: %w", err)
		}

		// Log response
		if c.verbose >= 2 && c.onPacket != nil {
			summary := fmt.Sprintf("ceye %s response  status=%d  %d bytes", recordType, resp.StatusCode, len(resp.Body))
			c.onPacket("外带", summary, resp.Raw)
		}

		// Parse JSON and check for matches
		return c.checkRecords(ctx, recordType, resp.Body)
	}

	// Calculate remaining time in parent context
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return false, fmt.Errorf("parent context already expired")
	}

	// Use the minimum of our calculated timeout and remaining time
	ceyeTimeout := totalTimeout
	if remaining < ceyeTimeout {
		ceyeTimeout = remaining
	}

	// Log the computed timeout for debugging (visible at -v or higher).
	if c.verbose >= 1 && c.onRaw != nil {
		c.onRaw("外带", "ceye %s poll timeout: %v (calculated=%v, remaining=%v)", recordType, ceyeTimeout, totalTimeout, remaining)
	}

	// Create context from parent (pluginCtx) to respect plugin deadline.
	// This ensures ceye calls are cancelled when the plugin times out.
	ceyeCtx, ceyeCancel := context.WithTimeout(ctx, ceyeTimeout)
	defer ceyeCancel()

	// Always use the shared client if available — same client as YAML workflow
	var resp *httpclient.Response
	var err error
	if c.client != nil {
		parsed, perr := httpclient.ParseRaw(rawReq)
		if perr != nil {
			return false, fmt.Errorf("ceye request parse failed: %w", perr)
		}
		resp, err = c.client.SendParsed(ceyeCtx, apiBase, parsed)
	} else {
		// Fallback: create a new client with generous timeout.
		// Use apiBase (scheme+host) so the base URL matches the Host header
		// derived above — avoids SSRF-protection false positives for mirrors.
		resp, err = httpclient.New(httpclient.ClientConfig{
			Timeout:        totalTimeout + 30*time.Second, // extra for dial + TLS
			AllowExternal:  true,                         // ceye API is always external
		}).SendRaw(ceyeCtx, apiBase, rawReq)
	}

	if err != nil {
		if c.verbose >= 2 && c.onRaw != nil {
			c.onRaw("外带", "ceye %s query failed: %v", recordType, err)
		}
		return false, fmt.Errorf("ceye API request failed: %w", err)
	}

	// Log response
	if c.verbose >= 2 && c.onPacket != nil {
		summary := fmt.Sprintf("ceye %s response  status=%d  %d bytes", recordType, resp.StatusCode, len(resp.Body))
		c.onPacket("外带", summary, resp.Raw)
	}

	// Parse JSON and check for matches
	logutil.Log("info", "外带", "ceye %s 检查记录: label=%s", recordType, c.label)
	return c.checkRecords(ctx, recordType, resp.Body)
}

// checkRecords parses ceye API response and checks for label match.
func (c *ceyeProvider) checkRecords(ctx context.Context, recordType, body string) (bool, error) {
	// Parse JSON: {"data":[{"name":"label.subdomain","type":"dns",...}]}
	// Client-side filter: check if any record name contains our label
	type ceyeRecord struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	var result struct {
		Data []ceyeRecord `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		// If parsing fails, fall back to a simple string search
		return len(body) > 0 && strings.Contains(body, `"name":`) && strings.Contains(strings.ToLower(body), strings.ToLower(c.label)), nil
	}

	// Match: record name contains label (case-insensitive)
	// e.g. record name "gs-a5d2e859.lbwssd.ceye.io" contains label "gs-a5d2e859"
	logutil.Log("info", "外带", "ceye %s 匹配: 共 %d 条记录", recordType, len(result.Data))
	for _, r := range result.Data {
		logutil.Log("debug", "外带", "  记录: name=%s type=%s", r.Name, r.Type)
		s := strings.TrimRight(strings.ToLower(r.Name), ".")
		if strings.Contains(s, strings.ToLower(c.label)) {
			logutil.Log("info", "外带", "ceye %s 命中: %s", recordType, r.Name)
			return true, nil
		}
	}
	logutil.Log("debug", "外带", "ceye %s 无匹配", recordType)
	return false, nil
}

// Setup configures the ceye provider with label and domain.
func (c *ceyeProvider) Setup(label, domain string) {
	// Auto-generate label if not provided (for ceye we need a unique identifier)
	if label == "" {
		label = "gs-" + placeholder.RandTextHex(8)
	}
	c.label = label
	if domain != "" {
		c.callbackURL = label + "." + domain
	}
	logutil.Log("info", "外带", "ceye 配置: label=%s callbackURL=%s", c.label, c.callbackURL)
}

// SetClient sets the shared HTTP client.
func (c *ceyeProvider) SetClient(client *httpclient.Client) {
	c.client = client
}

// SetVerbose enables request/response logging.
func (c *ceyeProvider) SetVerbose(verbose int, onPacket func(string, string, string), onRaw func(string, string, ...interface{})) {
	c.verbose = verbose
	c.onPacket = onPacket
	c.onRaw = onRaw
}

// SetAPIConfig sets ceye-specific API configuration.
func (c *ceyeProvider) SetAPIConfig(apiURL, pollInterval, pollTimeout string) {
	if apiURL != "" {
		c.apiURL = apiURL
	}
	if pollInterval != "" {
		c.pollInterval = pollInterval
	}
	if pollTimeout != "" {
		c.pollTimeout = pollTimeout
	}
}

// parseURLNoPath strips the path from a URL, returning only scheme+host.
// e.g. "https://api.ceye.io/v1/records" → "https://api.ceye.io"
func parseURLNoPath(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	u.Path = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}
