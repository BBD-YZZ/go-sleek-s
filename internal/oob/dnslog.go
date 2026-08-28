package oob

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gosleek/gosleek/internal/httpclient"
)

// dnslogProvider implements Provider for 47.244.138.18 (DNSLog.cn style).
//
// Two-step flow:
//   1. GET /getdomain.php → returns subdomain identifier (plain text) + Set-Cookie: PHPSESSID
//   2. GET /getrecords.php?domain=xxx → returns [["domain","ip","time"],...] JSON array
//
// Examples:
//   - probe returns: "hdmwny.dnslog.cn" → label="hdmwny", callbackURL="hdmwny.dnslog.cn"
//   - records response: [["hdmwny.dnslog.cn","218.x.x.x","2024-03-18 22:20:13"],...]
//   - match: json-word json-path=data json-field=0 words=["{{oob_label}}"] condition=or
//     (json-word 默认 case-insensitive，"hdmwny" 匹配 "hdmwny.dnslog.cn" 的首字母段)
type dnslogProvider struct {
	label      string // bare identifier, e.g. "hdmwny"
	domain     string // full domain, e.g. "hdmwny.dnslog.cn"
	cookie     string // PHPSESSID value
	client     *httpclient.Client
	verbose    int
	onPacket   func(tag string, summary string, raw string)
	onRaw      func(tag, format string, args ...interface{})
}

func newDNSLogProvider() *dnslogProvider {
	return &dnslogProvider{
		client: httpclient.New(httpclient.ClientConfig{Timeout: 15 * time.Second}),
	}
}

func (d *dnslogProvider) Name() string          { return "dnslog" }
func (d *dnslogProvider) Label() string         { return d.label }
func (d *dnslogProvider) CallbackURL() string   { return d.domain }
func (d *dnslogProvider) Token() string         { return d.cookie }

// Setup is a no-op for dnslog — it auto-probes.
func (d *dnslogProvider) Setup(label, domain string) {}

// SetClient sets the shared HTTP client.
func (d *dnslogProvider) SetClient(client *httpclient.Client) {
	d.client = client
}

// SetVerbose enables request/response logging.
func (d *dnslogProvider) SetVerbose(verbose int, onPacket func(string, string, string), onRaw func(string, string, ...interface{})) {
	d.verbose = verbose
	d.onPacket = onPacket
	d.onRaw = onRaw
}

// SetAPIConfig is a no-op for dnslog.
func (d *dnslogProvider) SetAPIConfig(apiURL, pollInterval, pollTimeout string) {}

// Probe fetches a fresh subdomain and PHPSESSID from dnslog.
func (d *dnslogProvider) Probe(ctx context.Context) error {
	targetURL := "http://47.244.138.18/getdomain.php"

	parsed, _ := url.Parse(targetURL)
	rawReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: 47.244.138.18\r\nConnection: close\r\n\r\n", parsed.RequestURI())
	if d.verbose >= 2 && d.onPacket != nil {
		d.onPacket("外带", "dnslog probe (获取子域名)", rawReq)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return err
	}

	var resp *http.Response
	var httpErr error
	if d.client != nil {
		resp, httpErr = d.client.HTTPClient().Do(req)
	} else {
		resp, httpErr = http.DefaultClient.Do(req)
	}
	if httpErr != nil {
		if d.verbose >= 2 && d.onRaw != nil {
			d.onRaw("外带", "dnslog probe failed: %v", httpErr)
		}
		return httpErr
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	rawDomain := strings.TrimSpace(string(body))
	if rawDomain == "" {
		return fmt.Errorf("dnslog: empty domain response")
	}
	d.domain = rawDomain

	// Extract the bare label: "hdmwny.dnslog.cn" → "hdmwny"
	if idx := strings.Index(rawDomain, "."); idx > 0 {
		d.label = rawDomain[:idx]
	} else {
		d.label = rawDomain
	}

	// Extract PHPSESSID from Set-Cookie header
	for _, c := range resp.Cookies() {
		if c.Name == "PHPSESSID" {
			d.cookie = c.Value
			break
		}
	}
	if d.cookie == "" {
		return fmt.Errorf("dnslog: no PHPSESSID cookie")
	}
	return nil
}

// VerifyDNS checks if any DNS callback was received.
func (d *dnslogProvider) VerifyDNS(ctx context.Context) (bool, error) {
	if d.domain == "" || d.cookie == "" {
		return false, fmt.Errorf("dnslog: not probed, call Probe() first")
	}
	return d.getRecords(ctx)
}

// VerifyHTTP checks if any HTTP callback was received.
// DNSLog only tracks DNS, but we use the same endpoint for consistency.
func (d *dnslogProvider) VerifyHTTP(ctx context.Context) (bool, error) {
	return d.VerifyDNS(ctx)
}

func (d *dnslogProvider) getRecords(ctx context.Context) (bool, error) {
	targetURL := fmt.Sprintf("http://47.244.138.18/getrecords.php?domain=%s", d.domain)

	parsed, _ := url.Parse(targetURL)
	rawReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: 47.244.138.18\r\nCookie: PHPSESSID=%s\r\nConnection: close\r\n\r\n", parsed.RequestURI(), d.cookie)
	if d.verbose >= 2 && d.onPacket != nil {
		d.onPacket("外带", fmt.Sprintf("dnslog query  domain=%s", d.domain), rawReq)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return false, err
	}
	req.AddCookie(&http.Cookie{Name: "PHPSESSID", Value: d.cookie})

	var resp *http.Response
	var httpErr error
	if d.client != nil {
		resp, httpErr = d.client.HTTPClient().Do(req)
	} else {
		resp, httpErr = http.DefaultClient.Do(req)
	}
	if httpErr != nil {
		if d.verbose >= 2 && d.onRaw != nil {
			d.onRaw("外带", "dnslog query failed: %v", httpErr)
		}
		return false, httpErr
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))

	if d.verbose >= 2 && d.onPacket != nil {
		summary := fmt.Sprintf("dnslog response  status=%d  %d bytes", resp.StatusCode, len(body))
		// 从原始 *http.Response 重建完整响应字符串, 包含所有响应头
		respRaw := fmt.Sprintf("HTTP/%d.%d %d %s\r\n", resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode, resp.Status)
		for k, vs := range resp.Header {
			for _, v := range vs {
				respRaw += fmt.Sprintf("%s: %s\r\n", k, v)
			}
		}
		respRaw += "\r\n" + string(body)
		d.onPacket("响应", summary, respRaw)
	}

	respStr := strings.TrimSpace(string(body))
	if respStr == "[]" || respStr == "" {
		return false, nil
	}

	// Parse as 2D string array: [["domain","ip","time"],...]
	var raw [][]string
	if err := json.Unmarshal(body, &raw); err != nil {
		return false, err
	}

	// Match: row[0] must contain our label as a complete DNS subdomain segment
	// (e.g. label="hdmwny" matches "hdmwny.dnslog.cn" but NOT "ahdmwny.dnslog.cn").
	// Strict segment matching prevents single-char labels from accidentally
	// matching unrelated DNS records.
	for _, row := range raw {
		if len(row) >= 1 {
			// Exact full-domain match
			if row[0] == d.domain {
				return true, nil
			}
			// Segment-exact match: label must appear as a complete dot-delimited segment
			segments := strings.Split(strings.ToLower(row[0]), ".")
			for _, seg := range segments {
				if seg == strings.ToLower(d.label) {
					return true, nil
				}
			}
		}
	}
	return false, nil
}
