package fingerprint

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/gosleek/gosleek/internal/httpclient"
	"github.com/gosleek/gosleek/internal/placeholder"
	"github.com/gosleek/gosleek/pkg/types"
)

// defaultTTL is how long a successful fingerprint remains valid before
// being evicted.
const defaultTTL = 5 * time.Minute

// failTTL is how long a failed probe is cached to avoid repeated探测.
const failTTL = 30 * time.Second

// cacheEntry wraps a fingerprint with its creation time.
type cacheEntry struct {
	fp        *TargetFingerprint
	createdAt time.Time
}

// TargetFingerprint holds detected technology indicators for a target.
type TargetFingerprint struct {
	Target  string
	Titles  []string
	Headers map[string]string
	Server  string
	// Technologies detected
	TechStack map[string]bool
}

// Detector identifies target technology stack for pre-filtering templates.
type Detector struct {
	client *httpclient.Client
	cache  sync.Map // target → *cacheEntry
}

// New creates a fingerprint detector.
func New(client *httpclient.Client) *Detector {
	return &Detector{client: client}
}

// Detect probes a target to determine its technology stack.
// On transient network failure the result is NOT cached (A8 fix), so
// subsequent calls will retry rather than returning an empty fingerprint
// forever.
func (d *Detector) Detect(ctx context.Context, target string) *TargetFingerprint {
	if raw, ok := d.cache.Load(target); ok {
		entry := raw.(*cacheEntry)
		if time.Since(entry.createdAt) < defaultTTL {
			return entry.fp
		}
		// Expired — drop it so we re-probe.
		d.cache.Delete(target)
	}

	fp := &TargetFingerprint{
		Target:    target,
		Headers:   make(map[string]string),
		TechStack: make(map[string]bool),
	}

	// [批次A-3 修复点] 旧代码直接把字面量 "{{Hostname}}" 作为 Host 头发出,
	// 导致目标服务器收到无效的 Host 头。现在先解析目标 URL 并替换占位符。
	ti := placeholder.ParseTarget(target)
	rawReq := placeholder.New(ti, nil).ReplaceWithEscape(
		"GET / HTTP/1.1\r\nHost: {{Hostname}}\r\nUser-Agent: gosleek-fp/1.0\r\nConnection: close\r\n\r\n",
	)
	resp, err := d.client.SendRaw(ctx, target, rawReq)
	if err != nil {
		// Cache failure briefly to avoid repeated probes for the same target.
		d.cache.Store(target, &cacheEntry{fp: fp, createdAt: time.Now()})
		return fp
	}

	// Extract server header
	if server := resp.GetHeader("Server"); server != "" {
		fp.Server = server
		fp.Headers["Server"] = server
	}

	// Extract title from body
	fp.Titles = extractTitles(resp.Body)

	// Detect common technologies
	d.detectTech(fp)

	// Store all response headers
	for k, vs := range resp.Headers {
		if len(vs) > 0 {
			fp.Headers[k] = vs[0]
		}
	}

	d.cache.Store(target, &cacheEntry{fp: fp, createdAt: time.Now()})
	return fp
}

// Matches checks if a target's fingerprint matches a template's fingerprint rules.
func (d *Detector) Matches(fp *TargetFingerprint, rules []types.FingerprintRule) bool {
	if len(rules) == 0 {
		return true // no fingerprint rules = always match
	}
	for _, rule := range rules {
		if rule.Title != "" {
			for _, title := range fp.Titles {
				if contains(title, rule.Title) {
					return true
				}
			}
		}
		if len(rule.Header) >= 2 {
			key := rule.Header[0]
			pattern := rule.Header[1]
			val := ""
			for k, v := range fp.Headers {
				if strings.EqualFold(k, key) {
					val = v
					break
				}
			}
			if matchPattern(val, pattern) {
				return true
			}
		}
	}
	return false
}

func extractTitles(body string) []string {
	var titles []string
	// Simple <title> extraction
	lower := strings.ToLower(body)
	idx := strings.Index(lower, "<title>")
	for idx >= 0 {
		end := strings.Index(lower[idx:], "</title>")
		if end < 0 {
			break
		}
		title := strings.TrimSpace(body[idx+7 : idx+end])
		titles = append(titles, title)
		lower = lower[idx+end+8:]
		idx = strings.Index(lower, "<title>")
	}
	return titles
}

func (d *Detector) detectTech(fp *TargetFingerprint) {
	server := strings.ToLower(fp.Server)
	for _, title := range fp.Titles {
		t := strings.ToLower(title)
		if strings.Contains(t, "apache") || strings.Contains(server, "apache") {
			fp.TechStack["apache"] = true
		}
		if strings.Contains(t, "nginx") || strings.Contains(server, "nginx") {
			fp.TechStack["nginx"] = true
		}
		if strings.Contains(t, "tomcat") || strings.Contains(server, "tomcat") {
			fp.TechStack["tomcat"] = true
		}
		if strings.Contains(t, "iis") || strings.Contains(server, "iis") {
			fp.TechStack["iis"] = true
		}
		if strings.Contains(t, "php") {
			fp.TechStack["php"] = true
		}
		if strings.Contains(t, "wordpress") {
			fp.TechStack["wordpress"] = true
		}
		if strings.Contains(t, "joomla") {
			fp.TechStack["joomla"] = true
		}
	}
	for k := range fp.Headers {
		switch strings.ToLower(k) {
		case "x-powered-by":
			val := strings.ToLower(fp.Headers[k])
			if strings.Contains(val, "php") {
				fp.TechStack["php"] = true
			}
			if strings.Contains(val, "asp") {
				fp.TechStack["asp"] = true
			}
		case "set-cookie":
			val := strings.ToLower(fp.Headers[k])
			if strings.Contains(val, "phpsessid") {
				fp.TechStack["php"] = true
			}
			if strings.Contains(val, "jsessionid") {
				fp.TechStack["java"] = true
			}
			if strings.Contains(val, "asp.net") {
				fp.TechStack["asp"] = true
			}
		}
	}
}

func contains(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

func matchPattern(val, pattern string) bool {
	// Simple glob: * = any, % = any
	pattern = strings.ReplaceAll(pattern, "*", "")
	pattern = strings.ReplaceAll(pattern, "%", "")
	return contains(val, pattern)
}
