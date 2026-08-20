package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gosleek/gosleek/pkg/types"
	"gopkg.in/yaml.v3"
)

// GlobalConfig is the top-level configuration file (configs/config.yaml).
type GlobalConfig struct {
	// HTTP defaults
	UserAgent      string `yaml:"user-agent"`
	DefaultTimeout int    `yaml:"default-timeout"`
	MaxRedirects   int    `yaml:"max-redirects"`
	MaxBodySize    int64  `yaml:"max-body-size"` // max response body size in bytes (0 = unlimited)
	AllowExternal  bool   `yaml:"allow-external-hosts"`

	// Concurrency
	Concurrency int `yaml:"concurrency"`
	RateLimit   int `yaml:"rate-limit"`

	// Retry
	MaxRetries   int    `yaml:"max-retries"`
	RetryBackoff string `yaml:"retry-backoff"` // e.g. "2s"

	// Wordlist cartesian product limit
	MaxCartesianProducts int `yaml:"max-cartesian-products"` // max combinations from wordlist cartesian product

	// OOB
	OOB OOBConfigYAML `yaml:"oob"`

	// Templates
	TemplateDir string `yaml:"template-dir"`

	// Output
	LogFile  string `yaml:"log-file"`
	LogLevel string `yaml:"log-level"`
}

// OOBConfigYAML is the OOB section in config.
type OOBConfigYAML struct {
	Enabled   bool       `yaml:"enabled"`
	Provider  string     `yaml:"provider"`
	Ceye      CeyeConfig `yaml:"ceye"`
	Dnslog    DnslogConfig `yaml:"dnslog"`
	Callbackred CallbackredConfig `yaml:"callbackred"`
}

// CeyeConfig holds ceye.io credentials.
type CeyeConfig struct {
	Token        string `yaml:"token"`
	APIURL       string `yaml:"api-url"`
	Domain       string `yaml:"domain"`
	PollInterval string `yaml:"poll-interval"`
	PollTimeout  string `yaml:"poll-timeout"`
}

// DnslogConfig holds dnslog.cn credentials (none needed, just auto-probe).
type DnslogConfig struct {
	// No credentials needed - auto-probes on demand
}

// CallbackredConfig holds callback.red credentials (none needed, just auto-probe).
type CallbackredConfig struct {
	// No credentials needed - auto-probes on demand
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() *GlobalConfig {
	return &GlobalConfig{
		UserAgent:            "Mozilla/5.0 (compatible; gosleek/1.0)",
		DefaultTimeout:       10,
		MaxRedirects:         3,
		MaxBodySize:          10 * 1024 * 1024, // 10MB default
		AllowExternal:        false,
		Concurrency:          25,
		RateLimit:            150,
		MaxRetries:           2,
		MaxCartesianProducts: 10000,
		RetryBackoff:         "2s",
		TemplateDir:          "templates",
		LogFile:              "logs/gosleek.log",
		LogLevel:             "info",
		OOB: OOBConfigYAML{
			Enabled:  false,
			Provider: "ceye",
			Ceye: CeyeConfig{
				APIURL:       "https://api.ceye.io/v1/records",
				PollInterval: "2s",
				PollTimeout:  "10s",
			},
		},
	}
}

// Load reads config.yaml from the given path. Missing file -> defaults.
// If the main config has empty ceye token/domain, it also tries to load
// configs/oob.yaml as a fallback for OOB credentials.
func Load(path string) (*GlobalConfig, error) {
	cfg := DefaultConfig()
	if path == "" {
		candidates := []string{"config.yaml", "configs/config.yaml"}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				path = c
				break
			}
		}
	}
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] config file %s read failed: %v, using defaults\n", path, err)
		} else if err := yaml.Unmarshal(data, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] config file %s parse failed: %v, using defaults\n", path, err)
		}
	}

	// Fallback: if ceye token/domain are still empty, try oob.yaml
	if cfg.OOB.Ceye.Token == "" || cfg.OOB.Ceye.Domain == "" {
		loadOOBFallback(cfg)
	}

	return cfg, nil
}

// loadOOBFallback tries to load OOB credentials from oob.yaml when the main
// config doesn't have them. Searches oob.yaml, configs/oob.yaml.
func loadOOBFallback(cfg *GlobalConfig) {
	candidates := []string{"oob.yaml", "configs/oob.yaml"}
	var data []byte
	for _, c := range candidates {
		var err error
		data, err = os.ReadFile(c)
		if err == nil {
			break
		}
	}
	if data == nil {
		return
	}
	var wrapper struct {
		OOB OOBConfigYAML `yaml:"oob"`
	}
	if err := yaml.Unmarshal(data, &wrapper); err != nil {
		return
	}
	if cfg.OOB.Ceye.Token == "" && wrapper.OOB.Ceye.Token != "" {
		cfg.OOB.Ceye.Token = wrapper.OOB.Ceye.Token
	}
	if cfg.OOB.Ceye.Domain == "" && wrapper.OOB.Ceye.Domain != "" {
		cfg.OOB.Ceye.Domain = wrapper.OOB.Ceye.Domain
	}
	if !cfg.OOB.Enabled && wrapper.OOB.Enabled {
		cfg.OOB.Enabled = wrapper.OOB.Enabled
	}
	if wrapper.OOB.Provider != "" {
		cfg.OOB.Provider = wrapper.OOB.Provider
	}
	if wrapper.OOB.Ceye.APIURL != "" {
		cfg.OOB.Ceye.APIURL = wrapper.OOB.Ceye.APIURL
	}
	if wrapper.OOB.Ceye.PollInterval != "" {
		cfg.OOB.Ceye.PollInterval = wrapper.OOB.Ceye.PollInterval
	}
	if wrapper.OOB.Ceye.PollTimeout != "" {
		cfg.OOB.Ceye.PollTimeout = wrapper.OOB.Ceye.PollTimeout
	}
	// Auto-probe providers (dnslog/callbackred) need no credentials
	// but oob.yaml can set provider for them
}

// ResolveCeyeToken determines the active ceye API token.
// Priority: config file > flag > env (config wins over CLI for consistency).
func ResolveCeyeToken(flagToken, envToken, cfgToken string) string {
	// Config file has highest priority
	if cfgToken != "" {
		return cfgToken
	}
	// Then flag
	if flagToken != "" {
		return flagToken
	}
	// Last resort: env
	return envToken
}

// ResolveCeyeDomain determines the active ceye domain.
// Priority: config file > flag > env.
func ResolveCeyeDomain(flagDomain, envDomain, cfgDomain string) string {
	if cfgDomain != "" {
		return cfgDomain
	}
	if flagDomain != "" {
		return flagDomain
	}
	return envDomain
}

// ToScanOptions merges global config into scan options.
func (c *GlobalConfig) ToScanOptions() *types.ScanOptions {
	return &types.ScanOptions{
		TemplateDir:  c.TemplateDir,
		Concurrency:  c.Concurrency,
		RateLimit:    c.RateLimit,
		Timeout:      c.DefaultTimeout,
	}
}

// EnsureDir creates the parent directory for a file path.
func EnsureDir(path string) {
	dir := filepath.Dir(path)
	_ = os.MkdirAll(dir, 0755)
}

// ExpandTilde expands ~ in paths (Unix-style).
func ExpandTilde(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, path[2:])
	}
	return path
}
