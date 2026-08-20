package oob

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/gosleek/gosleek/internal/httpclient"
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
		apiURL: "https://api.ceye.io",
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
	apiBase := "https://api.ceye.io"
	if c.apiURL != "" {
		if u, err := parseURLNoPath(c.apiURL); err == nil {
			apiBase = u
		}
	}

	// Correct API format: token as query parameter, NO filter parameter.
	// Get ALL records for this type, then filter client-side.
	rawReq := fmt.Sprintf(
		"GET /v1/records?token=%s&type=%s HTTP/1.1\r\n"+
			"Host: api.ceye.io\r\n"+
			"User-Agent: gosleek/1.0\r\n"+
			"Accept: */*\r\n"+
			"Connection: close\r\n\r\n",
		url.QueryEscape(c.token),
		recordType,
	)

	if c.verbose >= 2 && c.onPacket != nil {
		c.onPacket("外带", fmt.Sprintf("ceye %s query  label=%s type=%s", recordType, c.label, recordType), rawReq)
	}

	// Use configured pollTimeout (default 10s), not hardcoded
	timeout := 10 * time.Second
	if c.pollTimeout != "" {
		if d, err := time.ParseDuration(c.pollTimeout); err == nil && d > 0 {
			timeout = d
		}
	}
	// Also respect the context deadline (don't exceed it)
	if d, ok := ctx.Deadline(); ok {
		if time.Until(d) < timeout {
			timeout = time.Until(d)
		}
	}

	ctxWithTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Always use the shared client if available — same client as YAML workflow
	var resp *httpclient.Response
	var err error
	if c.client != nil {
		parsed, perr := httpclient.ParseRaw(rawReq)
		if perr != nil {
			return false, fmt.Errorf("ceye request parse failed: %w", perr)
		}
		resp, err = c.client.SendParsed(ctxWithTimeout, apiBase, parsed)
	} else {
		// Fallback: create a new client with generous timeout
		resp, err = httpclient.New(httpclient.ClientConfig{
			Timeout: timeout + 30*time.Second, // extra for dial + TLS
		}).SendRaw(ctxWithTimeout, "http://api.ceye.io", rawReq)
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

	// Parse JSON: {"data":[{"name":"label.subdomain","type":"dns",...}]}
	// Client-side filter: check if any record name contains our label
	type ceyeRecord struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	var result struct {
		Data []ceyeRecord `json:"data"`
	}
	if err := json.Unmarshal([]byte(resp.Body), &result); err != nil {
		// If parsing fails, fall back to a simple string search
		return len(resp.Body) > 0 && strings.Contains(resp.Body, `"name":`) && strings.Contains(strings.ToLower(resp.Body), strings.ToLower(c.label)), nil
	}

	// Match: record name contains label (case-insensitive)
	// e.g. record name "gs-a5d2e859.lbwssd.ceye.io" contains label "gs-a5d2e859"
	for _, r := range result.Data {
		s := strings.TrimRight(strings.ToLower(r.Name), ".")
		if strings.Contains(s, strings.ToLower(c.label)) {
			return true, nil
		}
	}
	return false, nil
}

// Setup configures the ceye provider with label and domain.
func (c *ceyeProvider) Setup(label, domain string) {
	c.label = label
	c.callbackURL = label + "." + domain
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
