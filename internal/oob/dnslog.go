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

// dnslogProvider implements Provider for 47.244.138.18 (DNSLog.cn style).
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
}

func newDNSLogProvider() *dnslogProvider {
	return &dnslogProvider{
		client: httpclient.New(httpclient.ClientConfig{Timeout: 15 * time.Second}),
	}
}

func (d *dnslogProvider) Name() string       { return "dnslog" }
func (d *dnslogProvider) Label() string      { return d.label }
func (d *dnslogProvider) CallbackURL() string { return d.domain }
func (d *dnslogProvider) Token() string      { return d.cookie }

// Setup is a no-op for dnslog — it auto-probes.
func (d *dnslogProvider) Setup(label, domain string) {}

// Probe fetches a fresh subdomain and PHPSESSID from dnslog.
// The response is a bare domain string like "hdmwny.dnslog.cn".
// We split it to get the label (identifier prefix) and the full domain.
func (d *dnslogProvider) Probe(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://47.244.138.18/getdomain.php", nil)
	if err != nil {
		return err
	}

	resp, err := d.client.HTTPClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	rawDomain := strings.TrimSpace(string(body))
	if rawDomain == "" {
		return fmt.Errorf("dnslog: empty domain response")
	}
	d.domain = rawDomain

	// Extract the bare label: "hdmwny.dnslog.cn" → "hdmwny"
	// Use first dot as separator; if no dot, use the whole string
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
// dnslog returns [["domain","ip","time"],...]; we check row[0] contains label.
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
	url := fmt.Sprintf("http://47.244.138.18/getrecords.php?domain=%s", d.domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, err
	}
	req.AddCookie(&http.Cookie{Name: "PHPSESSID", Value: d.cookie})

	resp, err := d.client.HTTPClient().Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	respStr := strings.TrimSpace(string(body))

	// Empty or "[]" means no records
	if respStr == "[]" || respStr == "" {
		return false, nil
	}

	// Parse as 2D string array: [["domain","ip","time"],...]
	var raw [][]string
	if err := json.Unmarshal(body, &raw); err != nil {
		return false, err
	}

	// Exact match on row[0] (the domain field)
	// e.g. "hdmwny.dnslog.cn" contains "hdmwny"
	for _, row := range raw {
		if len(row) >= 1 {
			if strings.EqualFold(row[0], d.domain) ||
				(strings.Contains(strings.ToLower(row[0]), strings.ToLower(d.label))) {
				return true, nil
			}
		}
	}
	return false, nil
}
