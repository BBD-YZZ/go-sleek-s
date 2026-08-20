package oob

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gosleek/gosleek/internal/httpclient"
)

// ceyeProvider implements Provider for ceye.io.
type ceyeProvider struct {
	label       string // gs-xxxxxxxx
	callbackURL string // gs-xxxxxxxx.ceye.io
	token       string // API token
}

func newCeyeProvider(token string) *ceyeProvider {
	return &ceyeProvider{token: token}
}

func (c *ceyeProvider) Name() string { return "ceye" }
func (c *ceyeProvider) Label() string { return c.label }
func (c *ceyeProvider) CallbackURL() string { return c.callbackURL }
func (c *ceyeProvider) Token() string { return c.token }

// Probe is a no-op for ceye — the label/callbackURL are set externally via SetupCeye.
func (c *ceyeProvider) Probe(ctx context.Context) error { return nil }

// VerifyDNS polls the ceye API for DNS records matching the label.
func (c *ceyeProvider) VerifyDNS(ctx context.Context) (bool, error) {
	return c.verifyRecords(ctx, "dns")
}

// VerifyHTTP polls the ceye API for HTTP records matching the label.
func (c *ceyeProvider) VerifyHTTP(ctx context.Context) (bool, error) {
	return c.verifyRecords(ctx, "http")
}

func (c *ceyeProvider) verifyRecords(ctx context.Context, recordType string) (bool, error) {
	rawReq := fmt.Sprintf(
		"GET /v1/records?type=%s&filter=%s HTTP/1.1\r\n"+
			"Host: api.ceye.io\r\n"+
			"Authorization: %s\r\n"+
			"Connection: close\r\n\r\n",
		recordType, c.label, c.token,
	)

	resp, err := httpclient.New(httpclient.ClientConfig{Timeout: 10 * time.Second}).SendRaw(ctx, "http://api.ceye.io", rawReq)
	if err != nil {
		return false, fmt.Errorf("ceye API request failed: %w", err)
	}
	// ceye API 返回 JSON: {"data":[{"name":"gs-xxxx.subdomain","time":"..."}]}
	// 如果返回了记录，说明回调被触发了
	return len(resp.Body) > 0 && strings.Contains(resp.Body, `"name":`), nil
}

// Setup configures the ceye provider with label and domain.
func (c *ceyeProvider) Setup(label, domain string) {
	c.label = label
	c.callbackURL = label + "." + domain
}

// ceyeRecord represents a ceye API record entry.
type ceyeRecord struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// ParseCeyeRecords parses ceye API JSON response.
func ParseCeyeRecords(body string) ([]ceyeRecord, error) {
	var result struct {
		Data []ceyeRecord `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return nil, err
	}
	return result.Data, nil
}
