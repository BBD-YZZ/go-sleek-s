package placeholder

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	// Placeholder pattern: {{name}} or {{name(args)}}
	placeholderRe = regexp.MustCompile(`\{\{([^}]+)\}\}`)
	// Function call pattern: func(arg1,arg2)
	funcCallRe = regexp.MustCompile(`^(\w+)\(([^)]*)\)$`)
)

// Engine holds the variable scope for a single template instance execution.
type Engine struct {
	mu        sync.RWMutex
	vars      map[string]string
	target    *TargetInfo
	oobURL    string
	extracted map[string]string
	// Whether to keep $ as literal $$
	escapeDollar bool
}

// TargetInfo holds parsed target URL info.
type TargetInfo struct {
	BaseURL  string // http://example.com:8080
	RootURL  string // http://example.com:8080
	Hostname string // example.com:8080  (host:port, for use in Host header)
	Host     string // example.com:8080  (same as Hostname)
	Port     string // 8080
	Scheme   string // http
	Path     string // /api/v1
}

// ParseTarget parses a URL string into TargetInfo.
//
// {{Hostname}} resolves to host:port (e.g., 192.168.80.128:8080) so it can
// be used directly in the HTTP Host header. If the port is a default port
// (80 for http, 443 for https) and was not explicitly specified in the URL,
// it is omitted (e.g., http://example.com/ → Hostname = "example.com").
func ParseTarget(rawURL string) *TargetInfo {
	// Ensure scheme
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return &TargetInfo{
			BaseURL: rawURL, RootURL: rawURL, Hostname: rawURL,
		}
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	_ = host // retained for potential future use (hostname without port)
	path := u.Path
	if path == "" {
		path = "/"
	}
	// u.Host includes the port if it was specified in the URL.
	// This is exactly what we want for {{Hostname}} — e.g.,
	//   http://192.168.80.128:8080/  →  u.Host = "192.168.80.128:8080"
	//   http://example.com/          →  u.Host = "example.com"
	return &TargetInfo{
		BaseURL:  fmt.Sprintf("%s://%s", u.Scheme, u.Host),
		RootURL:  fmt.Sprintf("%s://%s", u.Scheme, u.Host),
		Hostname: u.Host, // includes port if specified — correct for Host header
		Host:     u.Host,
		Port:     port,
		Scheme:   u.Scheme,
		Path:     path,
	}
}

// New creates a placeholder engine for the given target.
func New(target *TargetInfo, variables map[string]string) *Engine {
	e := &Engine{
		vars:      make(map[string]string),
		target:    target,
		extracted: make(map[string]string),
	}
	// Register static placeholders
	e.vars["baseURL"] = target.BaseURL
	e.vars["RootURL"] = target.RootURL
	e.vars["Hostname"] = target.Hostname
	e.vars["Host"] = target.Host
	e.vars["Port"] = target.Port
	e.vars["Scheme"] = target.Scheme
	e.vars["Path"] = target.Path
	// User-defined variables — evaluate each value through the placeholder
	// engine so that variables can reference generator functions and static
	// placeholders, e.g.:
	//
	//   variables:
	//     route_id: "{{rand_text_alpha(8)}}"   # one random value, reused
	//     callback: "{{Hostname}}/cb"          # can reference {{Hostname}}
	//
	// A value is evaluated once at engine creation; the resolved string is
	// stored, so every subsequent {{route_id}} in a multi-step workflow
	// resolves to the SAME random value (essential for CVE-2022-22947-style
	// templates that create/trigger/delete the same route id).
	//
	// Multi-round evaluation (max 5 rounds) resolves variables that reference
	// other variables, as long as there is no cycle.
	if len(variables) > 0 {
		pending := make(map[string]string, len(variables))
		for k, v := range variables {
			pending[k] = v
		}
		for round := 0; round < 5 && len(pending) > 0; round++ {
			var resolvedThisRound []string
			for k, v := range pending {
				if !placeholderRe.MatchString(v) {
					// No placeholders left — literal value
					e.vars[k] = v
					resolvedThisRound = append(resolvedThisRound, k)
					continue
				}
				got := e.Replace(v)
				e.vars[k] = got
				if got != v && !placeholderRe.MatchString(got) {
					// Fully resolved
					resolvedThisRound = append(resolvedThisRound, k)
				} else if got != v {
					// Partially resolved (may depend on another pending var)
					pending[k] = got
				}
			}
			for _, k := range resolvedThisRound {
				delete(pending, k)
			}
			if len(resolvedThisRound) == 0 {
				break // no progress, avoid infinite loop
			}
		}
		// Store any remaining (cyclic or unresolvable) values as-is
		for k, v := range pending {
			e.vars[k] = v
		}
	}
	return e
}

// SetOOB sets the OOB URL for {{oob}} / {{interactsh-url}}.
func (e *Engine) SetOOB(oobURL string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.oobURL = oobURL
	e.vars["oob"] = oobURL
	e.vars["interactsh-url"] = oobURL
}

// SetExtracted registers an extractor output for reuse.
func (e *Engine) SetExtracted(name, value string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.extracted[name] = value
	e.vars[name] = value
}

// GetExtracted returns an extracted value.
func (e *Engine) GetExtracted(name string) string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.extracted[name]
}

// GetExtractedMap returns a copy of all extracted variables.
func (e *Engine) GetExtractedMap() map[string]string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make(map[string]string, len(e.extracted))
	for k, v := range e.extracted {
		out[k] = v
	}
	return out
}

// Replace substitutes all placeholders in the given string.
func (e *Engine) Replace(s string) string {
	// Handle $$ escape: temporarily replace $$ with placeholder
	if e.escapeDollar {
		s = strings.ReplaceAll(s, "$$", "\x00DOLLAR\x00")
	}
	result := placeholderRe.ReplaceAllStringFunc(s, func(match string) string {
		inner := match[2 : len(match)-2] // strip {{ }}
		inner = strings.TrimSpace(inner)
		return e.resolve(inner)
	})
	if e.escapeDollar {
		result = strings.ReplaceAll(result, "\x00DOLLAR\x00", "$")
	}
	return result
}

// ReplaceWithEscape does $$ → $ escaping (for JNDI payloads etc.)
func (e *Engine) ReplaceWithEscape(s string) string {
	old := e.escapeDollar
	e.escapeDollar = true
	result := e.Replace(s)
	e.escapeDollar = old
	return result
}

func (e *Engine) resolve(expr string) string {
	// 1. Function call with args: rand_int(1,9999), rand_text_alpha(8)
	if m := funcCallRe.FindStringSubmatch(expr); m != nil {
		funcName := m[1]
		args := strings.Split(m[2], ",")
		for i := range args {
			args[i] = strings.TrimSpace(args[i])
		}
		return e.resolveFunc(funcName, args)
	}

	// 2. Bare function name without parens: {{randstr}} == {{randstr()}}.
	// resolveFunc is a pure function (no engine state) so it's safe to call
	// before acquiring the read lock.
	if isBareFunc(expr) {
		return e.resolveFunc(expr, nil)
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	// 3. User variables / static placeholders
	if val, ok := e.vars[expr]; ok {
		return val
	}

	// 4. Extracted
	if val, ok := e.extracted[expr]; ok {
		return val
	}

	// 5. Unknown: return as-is (leave the placeholder)
	return "{{" + expr + "}}"
}

// isBareFunc reports whether name is a known generator function that can be
// invoked without parentheses (e.g. {{randstr}} is equivalent to {{randstr()}}).
func isBareFunc(name string) bool {
	switch name {
	case "randstr", "rand_int", "rand_text_alpha", "rand_text_hex", "rand_text_numeric",
		"timestamp", "uuid":
		return true
	}
	return false
}

// IsBareFunction reports whether name is a known generator function (exported).
func IsBareFunction(name string) bool {
	return isBareFunc(name)
}

func (e *Engine) resolveFunc(name string, args []string) string {
	switch name {
	case "randstr":
		n := 8
		if len(args) > 0 {
			if v := atoiSafe(args[0]); v > 0 {
				n = v
			}
		}
		return randStr(n)
	case "rand_int":
		min := 1
		max := 9999
		if len(args) >= 2 {
			min = atoiSafe(args[0])
			max = atoiSafe(args[1])
		} else if len(args) == 1 {
			max = atoiSafe(args[0])
		}
		return fmt.Sprintf("%d", randInt(min, max))
	case "rand_text_alpha":
		n := 8
		if len(args) > 0 {
			if v := atoiSafe(args[0]); v > 0 {
				n = v
			}
		}
		return randTextAlpha(n)
	case "rand_text_hex":
		n := 16
		if len(args) > 0 {
			if v := atoiSafe(args[0]); v > 0 {
				n = v
			}
		}
		return randTextHex(n)
	case "rand_text_numeric":
		n := 8
		if len(args) > 0 {
			if v := atoiSafe(args[0]); v > 0 {
				n = v
			}
		}
		return randTextNumeric(n)

	// --- String transformation helpers ---
	case "to_upper":
		s := ""
		if len(args) > 0 {
			s = args[0]
		}
		return strings.ToUpper(s)
	case "to_lower":
		s := ""
		if len(args) > 0 {
			s = args[0]
		}
		return strings.ToLower(s)
	case "trim":
		s := ""
		if len(args) > 0 {
			s = args[0]
		}
		return strings.TrimSpace(s)
	case "reverse":
		s := ""
		if len(args) > 0 {
			s = args[0]
		}
		runes := []rune(s)
		for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
			runes[i], runes[j] = runes[j], runes[i]
		}
		return string(runes)
	case "concat":
		return strings.Join(args, "")
	case "repeat":
		s := ""
		n := 1
		if len(args) > 0 {
			s = args[0]
		}
		if len(args) > 1 {
			n = atoiSafe(args[1])
		}
		if n < 0 {
			n = 0
		}
		return strings.Repeat(s, n)

	// --- Encoding helpers ---
	case "base64_encode", "base64":
		s := ""
		if len(args) > 0 {
			s = args[0]
		}
		return base64.StdEncoding.EncodeToString([]byte(s))
	case "base64_decode":
		s := ""
		if len(args) > 0 {
			s = args[0]
		}
		decoded, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return s // return as-is on error
		}
		return string(decoded)
	case "url_encode":
		s := ""
		if len(args) > 0 {
			s = args[0]
		}
		return url.QueryEscape(s)
	case "url_decode":
		s := ""
		if len(args) > 0 {
			s = args[0]
		}
		decoded, err := url.QueryUnescape(s)
		if err != nil {
			return s
		}
		return decoded
	case "hex_encode":
		s := ""
		if len(args) > 0 {
			s = args[0]
		}
		return hex.EncodeToString([]byte(s))
	case "hex_decode":
		s := ""
		if len(args) > 0 {
			s = args[0]
		}
		decoded, err := hex.DecodeString(s)
		if err != nil {
			return s
		}
		return string(decoded)

	// --- Hash helpers ---
	case "md5":
		s := ""
		if len(args) > 0 {
			s = args[0]
		}
		sum := md5.Sum([]byte(s))
		return hex.EncodeToString(sum[:])
	case "sha1":
		s := ""
		if len(args) > 0 {
			s = args[0]
		}
		sum := sha1.Sum([]byte(s))
		return hex.EncodeToString(sum[:])
	case "sha256":
		s := ""
		if len(args) > 0 {
			s = args[0]
		}
		sum := sha256.Sum256([]byte(s))
		return hex.EncodeToString(sum[:])

	// --- Time helpers ---
	case "timestamp":
		return fmt.Sprintf("%d", time.Now().Unix())
	case "date":
		format := "2006-01-02"
		if len(args) > 0 {
			format = args[0]
		}
		return time.Now().Format(format)

	// --- UUID ---
	case "uuid":
		return generateUUID()

	default:
		return "{{" + name + "(" + strings.Join(args, ",") + ")}}"
	}
}

// --- Random generators ---

const (
	alphaChars   = "abcdefghijklmnopqrstuvwxyz"
	hexChars     = "0123456789abcdef"
	numericChars = "0123456789"
)

func randStr(n int) string {
	return randTextHex(n)
}

func randTextAlpha(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphaChars[randIntn(len(alphaChars))]
	}
	return string(b)
}

// RandTextAlpha 生成 n 位随机小写字母字符串。
func RandTextAlpha(n int) string {
	return randTextAlpha(n)
}

// RandTextHex 生成 n 位随机十六进制字符串。
func RandTextHex(n int) string {
	return randTextHex(n)
}

func randTextHex(n int) string {
	b := make([]byte, n/2+1)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

func randTextNumeric(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = numericChars[randIntn(len(numericChars))]
	}
	return string(b)
}

func randInt(min, max int) int {
	if min >= max {
		return min
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	return int(n.Int64()) + min
}

func randIntn(n int) int {
	if n <= 0 {
		return 0
	}
	v, _ := rand.Int(rand.Reader, big.NewInt(int64(n)))
	return int(v.Int64())
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// generateUUID returns a random UUID v4 string.
func generateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	// Set version (4) and variant (10xx)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Base64Encode returns the base64 encoding of data.
func Base64Encode(data string) string {
	return base64.StdEncoding.EncodeToString([]byte(data))
}

// HexEncode returns the hex encoding of data.
func HexEncode(data string) string {
	return hex.EncodeToString([]byte(data))
}
