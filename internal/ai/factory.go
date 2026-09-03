package ai

import (
	"strings"
)

// ProviderFactory 创建 AI 提供商的工厂函数。
type ProviderFactory func() Provider

// ProviderConfig 存储单个 AI 提供商的配置。
type ProviderConfig struct {
	Enabled  bool
	APIKey   string
	BaseURL  string
	Model    string
	Timeout  int
}

// Providers 返回所有支持的 AI 提供商配置映射。
// key 为 provider 名称（用于命令行参数和配置文件）。
func Providers() map[string]ProviderConfig {
	return map[string]ProviderConfig{
		"openai": {
			Enabled: false,
			APIKey:  "",
			BaseURL: "https://api.openai.com/v1",
			Model:   "gpt-4o-mini",
			Timeout: 30,
		},
		"deepseek": {
			Enabled: false,
			APIKey:  "",
			BaseURL: "https://api.deepseek.com/v1",
			Model:   "deepseek-chat",
			Timeout: 30,
		},
		"kimi": {
			Enabled: false,
			APIKey:  "",
			BaseURL: "https://api.moonshot.cn/v1",
			Model:   "moonshot-v1-8k",
			Timeout: 30,
		},
		"glm": {
			Enabled: false,
			APIKey:  "",
			BaseURL: "https://open.bigmodel.cn/api/paas/v4",
			Model:   "glm-4-plus",
			Timeout: 30,
		},
		"ollama": {
			Enabled: false,
			APIKey:  "",
			BaseURL: "http://localhost:11434/api",
			Model:   "llama3",
			Timeout: 60,
		},
		"agnes": {
			Enabled: false,
			APIKey:  "",
			BaseURL: "https://apihub.agnes-ai.com/v1",
			Model:   "agnes-2.5-flash",
			Timeout: 30,
		},
		"azure": {
			Enabled: false,
			APIKey:  "",
			BaseURL: "", // 需要用户自行配置
			Model:   "gpt-4",
			Timeout: 30,
		},
	}
}

// NewProvider 根据名称和配置创建 AI 提供商实例。
// 如果名称不支持，返回 nil。
func NewProvider(name string, cfg ProviderConfig) Provider {
	switch strings.ToLower(name) {
	case "openai":
		return NewOpenAIProvider(cfg.APIKey, cfg.BaseURL, cfg.Model, name, cfg.Timeout)
	case "deepseek":
		return NewOpenAIProvider(cfg.APIKey, cfg.BaseURL, cfg.Model, name, cfg.Timeout)
	case "kimi", "moonshot":
		return NewOpenAIProvider(cfg.APIKey, cfg.BaseURL, cfg.Model, name, cfg.Timeout)
	case "glm", "zhipu":
		return NewOpenAIProvider(cfg.APIKey, cfg.BaseURL, cfg.Model, name, cfg.Timeout)
	case "ollama":
		if cfg.BaseURL == "" {
			cfg.BaseURL = "http://localhost:11434/api"
		}
		return NewOpenAIProvider("", cfg.BaseURL, cfg.Model, "ollama", cfg.Timeout)
	case "agnes":
		return NewOpenAIProvider(cfg.APIKey, cfg.BaseURL, cfg.Model, name, cfg.Timeout)
	case "azure":
		return NewOpenAIProvider(cfg.APIKey, cfg.BaseURL, cfg.Model, name, cfg.Timeout)
	default:
		return nil
	}
}

// BuildAnalysisPromptCompat 构建分析提示词（已在 prompts.go 中定义，此处为兼容保留）。
func BuildAnalysisPromptCompat(req *AnalyzeRequest) string {
	return BuildAnalysisPrompt(req)
}
