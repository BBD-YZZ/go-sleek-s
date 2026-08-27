package oob

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gosleek/gosleek/internal/httpclient"
)

// callbackRedResponse is the JSON response from callback.red GET /get
type callbackRedResponse struct {
	Key       string `json:"key"`
	Subdomain string `json:"subdomain"`
}

// callbackRedQueryResponse is the JSON response from callback.red POST /key=xxx
type callbackRedQueryResponse struct {
	Code int             `json:"code"`
	Data json.RawMessage `json:"data"`
}

// callbackRedRecord represents a single record in callback.red data array.
type callbackRedRecord struct {
	Subdomain string `json:"subdomain"`
	Type      string `json:"type"`
}

// callbackRedProvider implements Provider for callback.red.
//
// Two-step flow:
//   1. GET /get → returns {"key":"uuid","subdomain":"xxx.callback.red",...}
//   2. POST / with "key=uuid" → returns {"code":200,"data":[{"subdomain":"xxx.callback.red","type":"dns",...}]}
//      or {"code":403,"data":["Domain Expired"]}
//
// Examples:
//   - probe subdomain: "tsgm.callback.red" → label="tsgm", callbackURL="tsgm.callback.red"
//   - verify response: data[0].subdomain = "tsgm.callback.red" (with optional trailing dot)
//   - match: json-word json-path=data json-field=subdomain words=["{{oob_label}}"] condition=or
type callbackRedProvider struct {
	key       string
	subdomain string
	label     string
	client    *httpclient.Client
	verbose   int
	onPacket  func(tag string, summary string, raw string)
	onRaw     func(tag, format string, args ...interface{})
}

// Setup is a no-op for callback.red — it auto-probes.
func (c *callbackRedProvider) Setup(label, domain string) {}

// SetClient sets the shared HTTP client.
func (c *callbackRedProvider) SetClient(client *httpclient.Client) {
	c.client = client
}

// SetVerbose enables request/response logging.
func (c *callbackRedProvider) SetVerbose(verbose int, onPacket func(string, string, string), onRaw func(string, string, ...interface{})) {
	c.verbose = verbose
	c.onPacket = onPacket
	c.onRaw = onRaw
}

// SetAPIConfig is a no-op for callbackred.
func (c *callbackRedProvider) SetAPIConfig(apiURL, pollInterval, pollTimeout string) {}

func newCallbackRedProvider() *callbackRedProvider {
	return &callbackRedProvider{
		client: httpclient.New(httpclient.ClientConfig{Timeout: 15 * time.Second}),
	}
}

func (c *callbackRedProvider) Name() string        { return "callbackred" }
func (c *callbackRedProvider) Label() string       { return c.label }
func (c *callbackRedProvider) CallbackURL() string { return c.subdomain }
func (c *callbackRedProvider) Token() string       { return c.key }

// Probe fetches a fresh subdomain and key from callback.red.
func (c *callbackRedProvider) Probe(ctx context.Context) error {
	url := "http://callback.red/get"

	rawReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: callback.red\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: zh-CN,zh;q=0.9\r\nConnection: close\r\n\r\n", url)
	if c.verbose >= 2 && c.onPacket != nil {
		c.onPacket("外带", "callback.red probe (获取 key)", rawReq)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")

	var resp *http.Response
	var httpErr error
	if c.client != nil {
		resp, httpErr = c.client.HTTPClient().Do(req)
	} else {
		resp, httpErr = http.DefaultClient.Do(req)
	}
	if httpErr != nil {
		if c.verbose >= 2 && c.onRaw != nil {
			c.onRaw("外带", "callback.red probe failed: %v", httpErr)
		}
		return httpErr
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	var result callbackRedResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("callback.red: failed to parse response: %w", err)
	}
	if result.Key == "" || result.Subdomain == "" {
		return fmt.Errorf("callback.red: empty key or subdomain in response")
	}
	c.key = result.Key
	c.subdomain = result.Subdomain

	// Extract bare label: "tsgm.callback.red" → "tsgm"
	if idx := strings.Index(result.Subdomain, "."); idx > 0 {
		c.label = result.Subdomain[:idx]
	} else {
		c.label = result.Subdomain
	}
	return nil
}

// VerifyDNS checks callback.red for DNS records.
func (c *callbackRedProvider) VerifyDNS(ctx context.Context) (bool, error) {
	return c.verifyRecords(ctx)
}

// VerifyHTTP checks callback.red for HTTP records.
func (c *callbackRedProvider) VerifyHTTP(ctx context.Context) (bool, error) {
	return c.verifyRecords(ctx)
}

func (c *callbackRedProvider) verifyRecords(ctx context.Context) (bool, error) {
	if c.key == "" {
		return false, fmt.Errorf("callback.red: no key, call Probe() first")
	}

	rawReq := "POST / HTTP/1.1\r\n" +
		"Host: callback.red\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Connection: close\r\n\r\n" +
		"key=" + c.key
	if c.verbose >= 2 && c.onPacket != nil {
		c.onPacket("外带", fmt.Sprintf("callback.red query  key=%s", c.key[:min(len(c.key), 8)]), rawReq)
	}

	var resp *httpclient.Response
	var err error
	if c.client != nil {
		parsed, perr := httpclient.ParseRaw(rawReq)
		if perr != nil {
			return false, fmt.Errorf("callback.red request parse failed: %w", perr)
		}
		resp, err = c.client.SendParsed(ctx, "http://callback.red", parsed)
	} else {
		resp, err = httpclient.New(httpclient.ClientConfig{Timeout: 15 * time.Second}).SendRaw(ctx, "http://callback.red", rawReq)
	}
	if err != nil {
		if c.verbose >= 2 && c.onRaw != nil {
			c.onRaw("外带", "callback.red query failed: %v", err)
		}
		return false, err
	}

	if c.verbose >= 2 && c.onPacket != nil {
		summary := fmt.Sprintf("callback.red response  status=%d  %d bytes", resp.StatusCode, len(resp.Body))
		c.onPacket("外带", summary, resp.Raw)
	}

	// Parse JSON: {"code":200,"data":[{"subdomain":"...","type":"..."}]}
	var result callbackRedQueryResponse
	if err := json.Unmarshal([]byte(resp.Body), &result); err != nil {
		return false, fmt.Errorf("callback.red: failed to parse response: %w", err)
	}
	if result.Code == 403 {
		return false, nil
	}
	if result.Code != 200 {
		return false, fmt.Errorf("callback.red: unexpected code %d", result.Code)
	}

	// Parse data array
	var records []callbackRedRecord
	if err := json.Unmarshal(result.Data, &records); err != nil {
		return false, fmt.Errorf("callback.red: failed to parse data: %w", err)
	}

	// Match: subdomain contains label (case-insensitive, trailing dot tolerance)
	for _, r := range records {
		s := strings.TrimRight(strings.ToLower(r.Subdomain), ".")
		if strings.Contains(s, strings.ToLower(c.label)) {
			return true, nil
		}
	}
	return false, nil
}
