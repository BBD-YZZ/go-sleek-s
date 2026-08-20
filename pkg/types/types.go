package types

import "time"

// Severity levels
const (
	SeverityInfo     = "info"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// SeverityRank for sorting
var SeverityRank = map[string]int{
	"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5,
}

// TemplateMeta 是 YAML 模板和 Go 插件共用的元数据结构，
// 用于过滤、输出、resume 去重，保证两类检测单元对引擎透明。
type TemplateMeta struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Severity    string   `json:"severity"`
	Author      string   `json:"author,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Reference   []string `json:"reference,omitempty"`
}

// Template is the top-level structure for a YAML vulnerability template.
type Template struct {
	ID            string            `yaml:"id"`
	Name          string            `yaml:"name"`
	Description   string            `yaml:"description"`
	Severity      string            `yaml:"severity"`
	Author        string            `yaml:"author,omitempty"`
	Tags          []string          `yaml:"tags,omitempty"`
	Reference     []string          `yaml:"reference,omitempty"`
	Classification *Classification  `yaml:"classification,omitempty"`

	// Fingerprint pre-filter: only run if target matches
	Fingerprints []FingerprintRule `yaml:"fingerprints,omitempty"`

	// User-defined variables
	Variables map[string]string `yaml:"variables,omitempty"`

	// Single-template HTTP requests (ordered list)
	HTTP []HTTPRequest `yaml:"http,omitempty"`

	// OOB out-of-band verification
	OOB *OOBConfig `yaml:"oob,omitempty"`

	// OOBProvider overrides the global OOB provider for this template.
	// e.g. "ceye" / "dnslog" / "callbackred" — used when the template's
	// verify steps call a specific OOB API (e.g. ceye template with dnslog global).
	OOBProvider string `yaml:"oob-provider,omitempty"`

	// Multi-step workflow
	Workflow []WorkflowStep `yaml:"workflow,omitempty"`

	// Stop at first match across all requests
	StopAtFirstMatch bool `yaml:"stop-at-first-match,omitempty"`

	// Template-level matchers condition (combines across requests)
	MatchersCondition string `yaml:"matchers-condition,omitempty"`

	// Template-level matchers
	Matchers []Matcher `yaml:"matchers,omitempty"`

	// Extractors
	Extractors []Extractor `yaml:"extractors,omitempty"`

	// Internal: not from YAML
	FilePath string `yaml:"-"`
	SHA256   string `yaml:"-"`
}

// Classification holds CVSS/CWE metadata.
type Classification struct {
	CVSSScore float64 `yaml:"cvss-score,omitempty"`
	CVE       string  `yaml:"cve-id,omitempty"`
	CWE       string  `yaml:"cwe,omitempty"`
}

// FingerprintRule determines if a template should run against a target.
type FingerprintRule struct {
	Title  string   `yaml:"title,omitempty"`
	Header []string `yaml:"header,omitempty"` // [key, value-pattern]
}

// HTTPRequest defines a single raw HTTP request block.
type HTTPRequest struct {
	Raw        string      `yaml:"raw"`
	Path       []string    `yaml:"path,omitempty"` // alternative to raw
	Method     string      `yaml:"method,omitempty"`
	Headers    map[string]string `yaml:"headers,omitempty"`
	Body       string      `yaml:"body,omitempty"`
	BodyType   string      `yaml:"body-type,omitempty"` // empty/raw/form/multipart

	Timeout    int         `yaml:"timeout,omitempty"`
	Redirects  *bool       `yaml:"redirects,omitempty"`
	Threads    int         `yaml:"threads,omitempty"`
	RateLimit  int         `yaml:"rate-limit,omitempty"`

	MatchersCondition string         `yaml:"matchers-condition,omitempty"`
	Matchers          []Matcher      `yaml:"matchers,omitempty"`
	Extractors        []Extractor    `yaml:"extractors,omitempty"`
	Wordlist          []WordlistConfig `yaml:"wordlist,omitempty"` // multiple payload dictionaries for cartesian product

	// Control flow
	StopAtFirstMatch bool   `yaml:"stop-at-first-match,omitempty"`
	RunIf            string `yaml:"run-if,omitempty"`
	Probe            bool   `yaml:"probe,omitempty"` // if true, this request is for probing/extraction only, its matcher result won't count toward final verdict

	// Name for workflow reference
	Name string `yaml:"name,omitempty"`
}

// WordlistConfig configures dictionary injection for a request block.
// The placeholder key is replaced by lines from the file.
type WordlistConfig struct {
	// Key is the placeholder key without braces, e.g. "password" → replaces {{password}}
	Key string `yaml:"key"`
	// Path is the file path (absolute or relative to template directory)
	Path string `yaml:"path"`
	// Encoding optional: "url" / "base64" / "hex" applied to each line
	Encoding string `yaml:"encoding,omitempty"`
}

// Matcher defines a single match rule.
type Matcher struct {
	Type             string   `yaml:"type"`
	Part             string   `yaml:"part,omitempty"` // body/header/all/interactsh
	Status           []int    `yaml:"status,omitempty"`
	Words            []string `yaml:"words,omitempty"`
	Regex            []string `yaml:"regex,omitempty"`
	Header           []string `yaml:"header,omitempty"` // deprecated alias for word on header
	Size             []string `yaml:"size,omitempty"`
	Time             string   `yaml:"time,omitempty"`
	Binary           []string `yaml:"binary,omitempty"`
	DSL              []string `yaml:"dsl,omitempty"`
	Condition        string   `yaml:"condition,omitempty"`   // and/or within matcher
	Negative         bool     `yaml:"negative,omitempty"`
	Encoding         string   `yaml:"encoding,omitempty"`
	CaseInsensitive  bool     `yaml:"case-insensitive,omitempty"` // case-insensitive matching for word/regex/header/json-word
	// json-word only: path to JSON array in response body (default "data")
	JSONPath  string `yaml:"json-path,omitempty"`
	// json-word only: field name inside each array element (default "name")
	JSONField string `yaml:"json-field,omitempty"`
	// json-2darray only: column index to match (default 0).
	// Used for dnslog.cn-style responses: [["domain","ip","time"],...]
	JSON2DColumn int `yaml:"json-2darray-column,omitempty"`
}

// Extractor pulls data from responses for reuse.
type Extractor struct {
	Name   string   `yaml:"name"`
	Type   string   `yaml:"type"` // regex/word/kval/json/cookie
	Part   string   `yaml:"part,omitempty"`
	Regex  []string `yaml:"regex,omitempty"`
	Group  int      `yaml:"group,omitempty"`
	Words  []string `yaml:"words,omitempty"`
	KVal   []string `yaml:"kval,omitempty"`
	JSON   []string `yaml:"json,omitempty"`
	Internal bool   `yaml:"internal,omitempty"`
}

// OOBConfig configures out-of-band verification.
type OOBConfig struct {
	Provider string    `yaml:"provider"`
	Poll     int       `yaml:"poll,omitempty"`
	Matchers []Matcher `yaml:"matchers,omitempty"`
}

// WorkflowStep defines a multi-step workflow entry.
type WorkflowStep struct {
	Name     string        `yaml:"name"`
	Template string        `yaml:"template,omitempty"` // reference to another template
	HTTP     []HTTPRequest `yaml:"http,omitempty"`
	Requires []string      `yaml:"requires,omitempty"`
	StopAtFirstMatch bool   `yaml:"stop-at-first-match,omitempty"`
	Delay    int           `yaml:"delay,omitempty"` // seconds to wait before executing this step
	// Provider overrides the global OOB provider for this step only.
	// e.g. "ceye" / "dnslog" / "callbackred" — step is skipped if
	// the active provider doesn't match. Empty = use global provider.
	Provider string `yaml:"provider,omitempty"`
}

// Result represents a scan finding.
type Result struct {
	TemplateID  string    `json:"template-id"`
	Name        string    `json:"name"`
	Severity    string    `json:"severity"`
	Description string    `json:"description,omitempty"`
	Target      string    `json:"target"`
	MatchedAt   string    `json:"matched-at"`
	Tags        []string  `json:"tags,omitempty"`
	Reference   []string  `json:"reference,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
	// Evidence: matcher that fired
	Evidence    string    `json:"evidence,omitempty"`
	// Extracted data
	Extracted   map[string]string `json:"extracted,omitempty"`
	// Raw request/response for replay
	RawRequest  string `json:"raw-request,omitempty"`
	RawResponse string `json:"raw-response,omitempty"`
}

// ScanOptions configures a scan run.
type ScanOptions struct {
	Targets        []string
	TemplateDir    string
	TemplateIDs    []string
	Tags           []string
	Severity       []string
	ExcludeIDs     []string
	FilterSeverity []string // post-scan severity filter
	FilterTags     []string // post-scan tag filter
	Concurrency    int
	RateLimit      int
	Timeout        int
	Proxy          string
	VerifySSL      bool // enable TLS cert verification (default: skip)
	Verbose        int  // 0=normal, 1=-v, 2=-vv
	Silent         bool
	OOBEnabled     bool
	OOBCeyeKey     string
	OOBCeyeDomain  string
	OutputFile     string
	OutputDir      string // auto-timestamp output directory
	OutputFormat   string
	ResumeFile     string
	LogFile        string
	LogLevel       string
	Fingerprints   bool
	PluginsOnly    bool // 仅运行 Go 插件，跳过 YAML 模板
	FollowRedirects bool // CLI-level override for follow-redirects
	Header         map[string]string // global headers injected into every request
}
