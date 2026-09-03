package ai

import (
	"fmt"
	"sync"
)

var (
	// providers 存储所有已注册的 AI 提供商实例。
	providers = make(map[string]Provider)
	// mu 保护 providers 地图的并发访问。
	mu sync.RWMutex
)

// Register 注册一个 AI 提供商。
// 如果同名提供商已注册，将被覆盖。
func Register(name string, provider Provider) {
	mu.Lock()
	defer mu.Unlock()
	providers[name] = provider
}

// Get 获取指定名称的 AI 提供商。
// 第二个返回值表示是否找到。
func Get(name string) (Provider, bool) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := providers[name]
	return p, ok
}

// List 返回所有已注册提供商的名称列表。
func List() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(providers))
	for name := range providers {
		names = append(names, name)
	}
	return names
}

// DefaultProviders 注册所有内置提供商（空占位，实际在 SetAIProvider 中按需创建）。
func DefaultProviders() {
	// 不在此处注册，改为延迟初始化
	// 保留函数签名供测试兼容
}

// SetAIProvider 根据配置创建并注册指定名称的 AI 提供商。
// 返回已创建的 Provider，如果配置为空或名称不支持则返回 nil。
func SetAIProvider(name string, cfg ProviderConfig) Provider {
	p := NewProvider(name, cfg)
	if p != nil && p.Available() {
		Register(name, p)
		return p
	}
	return nil
}

// SetAIProviderFromGlobalConfig 从全局配置创建并注册 AI 提供商。
// name 为空时使用 cfg.Provider（默认 "openai"）。
func SetAIProviderFromGlobalConfig(name string, cfg ProviderConfig) (Provider, error) {
	if name == "" {
		name = "openai"
	}
	p := NewProvider(name, cfg)
	if p == nil {
		return nil, fmt.Errorf("不支持的 AI 提供商: %s（支持: openai, deepseek, kimi, glm, ollama, agnes, azure）", name)
	}
	if !p.Available() {
		return nil, fmt.Errorf("AI 提供商 %s 未正确配置（缺少 API Key 或 Base URL）", name)
	}
	Register(name, p)
	return p, nil
}
