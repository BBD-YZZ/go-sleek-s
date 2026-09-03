package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gosleek/gosleek/pkg/types"
)

// --- Prompt 构建测试 ---

func TestBuildAnalysisPrompt_NonEmpty(t *testing.T) {
	req := &AnalyzeRequest{
		TemplateID:   "test-001",
		TemplateName: "SQL注入检测",
		Severity:     "high",
		Target:       "http://example.com/vuln?id=1",
		RawRequest:   "GET /vuln?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
		RawResponse:  "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<div>hello</div>",
		Evidence:     "sqlmap detected",
	}
	prompt := BuildAnalysisPrompt(req)
	if prompt == "" {
		t.Fatal("提示词不应为空")
	}
	if !contains(prompt, "test-001") {
		t.Error("提示词应包含 TemplateID")
	}
	if !contains(prompt, "SQL注入检测") {
		t.Error("提示词应包含 TemplateName")
	}
	if !contains(prompt, "http://example.com/vuln?id=1") {
		t.Error("提示词应包含 Target")
	}
	if !contains(prompt, "sqlmap detected") {
		t.Error("提示词应包含 Evidence")
	}
}

func TestBuildAnalysisPrompt_Context(t *testing.T) {
	req := &AnalyzeRequest{
		TemplateID:   "test-002",
		TemplateName: "XSS检测",
		Severity:     "medium",
		Target:       "http://example.com/search",
		RawRequest:   "GET /search?q=test HTTP/1.1\r\nHost: example.com\r\n\r\n",
		RawResponse:  "HTTP/1.1 200 OK\r\n\r\nfound: test",
		Context:      "这是一个搜索页面的XSS检测模板",
	}
	prompt := BuildAnalysisPrompt(req)
	if !contains(prompt, "这是一个搜索页面的XSS检测模板") {
		t.Error("提示词应包含 Context")
	}
}

func TestBuildAnalysisPrompt_Extracted(t *testing.T) {
	req := &AnalyzeRequest{
		TemplateID:   "test-003",
		TemplateName: "信息泄露",
		Severity:     "low",
		Target:       "http://example.com/api",
		RawRequest:   "GET /api HTTP/1.1\r\n\r\n",
		RawResponse:  "HTTP/1.1 200 OK\r\n\r\n{\"key\":\"value\"}",
		Extracted:    map[string]string{"api_key": "secret123"},
	}
	prompt := BuildAnalysisPrompt(req)
	if !contains(prompt, "secret123") {
		t.Error("提示词应包含 Extracted 数据")
	}
}

func TestBuildAnalysisPrompt_CriticalSeverity(t *testing.T) {
	req := &AnalyzeRequest{
		TemplateID:   "test-004",
		TemplateName: "RCE",
		Severity:     "critical",
		Target:       "http://example.com/cmd",
		RawRequest:   "POST /cmd HTTP/1.1\r\n\r\n",
		RawResponse:  "HTTP/1.1 200 OK\r\n\r\nuid=0(root)",
	}
	prompt := BuildAnalysisPrompt(req)
	if !contains(prompt, "高危/严重漏洞") {
		t.Error("严重度为 critical 时，提示词应包含高危提示")
	}
}

// --- Prompt 构建测试（二次确认）---

func TestBuildConfirmationPrompt(t *testing.T) {
	result := &types.Result{
		TemplateID:  "test-005",
		Name:        "SSRF检测",
		Severity:    "high",
		Target:      "http://example.com/proxy",
		Evidence:    "internal-ip-detected",
		RawRequest:  "GET /proxy?url=http://169.254.169.254 HTTP/1.1\r\n\r\n",
		RawResponse: "HTTP/1.1 200 OK\r\n\r\n{\"status\":\"ok\"}",
	}
	prompt := BuildConfirmationPrompt(result, "测试上下文")
	if prompt == "" {
		t.Fatal("提示词不应为空")
	}
	if !contains(prompt, "SSRF检测") {
		t.Error("提示词应包含漏洞名称")
	}
	if !contains(prompt, "测试上下文") {
		t.Error("提示词应包含上下文")
	}
}

// --- Provider 注册测试 ---

func TestRegisterAndGet(t *testing.T) {
	// 清理已有注册
	mu.Lock()
	providers = make(map[string]Provider)
	mu.Unlock()

	mock := &mockProvider{name: "mock"}
	Register("mock", mock)

	got, ok := Get("mock")
	if !ok {
		t.Fatal("应能找到注册的提供商")
	}
	if got.Name() != "mock" {
		t.Errorf("期望名称 mock，实际 %s", got.Name())
	}
}

func TestRegister_Override(t *testing.T) {
	mu.Lock()
	providers = make(map[string]Provider)
	mu.Unlock()

	p1 := &mockProvider{name: "v1"}
	p2 := &mockProvider{name: "v2"}
	Register("test", p1)
	Register("test", p2)

	got, _ := Get("test")
	if got.Name() != "v2" {
		t.Error("重复注册应覆盖旧值")
	}
}

func TestList(t *testing.T) {
	mu.Lock()
	providers = make(map[string]Provider)
	mu.Unlock()

	Register("a", &mockProvider{name: "a"})
	Register("b", &mockProvider{name: "b"})

	list := List()
	if len(list) != 2 {
		t.Fatalf("期望 2 个提供商，实际 %d", len(list))
	}
}

func TestDefaultProviders(t *testing.T) {
	mu.Lock()
	providers = make(map[string]Provider)
	mu.Unlock()

	// DefaultProviders 使用延迟初始化，不在此处注册
	DefaultProviders()

	// 测试 NewProvider 支持所有常见提供商
	for _, name := range []string{"openai", "deepseek", "kimi", "glm", "ollama", "agnes", "azure"} {
		p := NewProvider(name, Providers()[name])
		if p == nil {
			t.Errorf("NewProvider(%s) 应返回非 nil", name)
		}
	}
}

// --- OpenAI Provider 测试 ---

func TestOpenAIProvider_Name(t *testing.T) {
	p := NewOpenAIProvider("key", "https://api.openai.com/v1", "gpt-4o", "openai", 30)
	if p.Name() != "openai" {
		t.Errorf("期望名称 openai，实际 %s", p.Name())
	}
}

func TestOpenAIProvider_Available(t *testing.T) {
	// 缺少 BaseURL → 不可用
	p := NewOpenAIProvider("key", "", "gpt-4o", "openai", 30)
	if p.Available() {
		t.Error("缺少 BaseURL 时应不可用")
	}

	// 有 BaseURL 和 APIKey → 可用
	p = NewOpenAIProvider("key", "https://api.openai.com/v1", "gpt-4o", "openai", 30)
	if !p.Available() {
		t.Error("有 BaseURL 和 APIKey 时应可用")
	}

	// Ollama 无 APIKey 也可用
	p = NewOpenAIProvider("", "http://localhost:11434/api", "llama3", "ollama", 30)
	if !p.Available() {
		t.Error("Ollama 无 APIKey 时应可用")
	}
}

func TestOpenAIProvider_Analyze_Success(t *testing.T) {
	// 启动 mock HTTP 服务器
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("期望 POST 请求，实际 %s", r.Method)
		}
		if r.URL.Path != "/chat/completions" {
			t.Errorf("期望路径 /chat/completions，实际 %s", r.URL.Path)
		}

		resp := openaiChatResponse{
			Choices: []openaiChatChoice{
				{
					Message: openaiChatMessage{
						Role:    "assistant",
						Content: `{"confident":true,"confidence":0.95,"suggestions":["手动验证参数"],"risk_assessment":"高风险：响应中包含敏感信息"}`,
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	p := NewOpenAIProvider("test-key", server.URL, "gpt-4o", "openai", 10)
	ctx := context.Background()
	req := &AnalyzeRequest{
		TemplateID:   "test-006",
		TemplateName: "测试",
		Severity:     "high",
		Target:       "http://example.com",
		RawRequest:   "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
		RawResponse:  "HTTP/1.1 200 OK\r\n\r\nHello",
	}

	resp, err := p.Analyze(ctx, req)
	if err != nil {
		t.Fatalf("Analyze 不应报错: %v", err)
	}
	if !resp.Confident {
		t.Error("期望 confident=true")
	}
	if resp.Confidence != 0.95 {
		t.Errorf("期望置信度 0.95，实际 %f", resp.Confidence)
	}
	if len(resp.Suggestions) != 1 {
		t.Errorf("期望 1 条建议，实际 %d", len(resp.Suggestions))
	}
}

func TestOpenAIProvider_Analyze_MarkdownWrapped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := openaiChatResponse{
			Choices: []openaiChatChoice{
				{
					Message: openaiChatMessage{
						Role:    "assistant",
						Content: "```json\n{\"confident\":false,\"confidence\":0.3,\"suggestions\":[],\"risk_assessment\":\"低置信度\"}\n```",
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	p := NewOpenAIProvider("", server.URL, "llama3", "ollama", 10)
	ctx := context.Background()
	req := &AnalyzeRequest{
		TemplateID:  "test-007",
		Severity:    "low",
		Target:      "http://example.com",
		RawRequest:  "GET / HTTP/1.1\r\n\r\n",
		RawResponse: "HTTP/1.1 200 OK\r\n\r\n",
	}

	resp, err := p.Analyze(ctx, req)
	if err != nil {
		t.Fatalf("Analyze 不应报错: %v", err)
	}
	if resp.Confident {
		t.Error("期望 confident=false")
	}
}

func TestOpenAIProvider_Analyze_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"Invalid API key","type":"auth_error"}}`))
	}))
	defer server.Close()

	p := NewOpenAIProvider("bad-key", server.URL, "gpt-4o", "openai", 10)
	ctx := context.Background()
	req := &AnalyzeRequest{
		TemplateID:  "test-008",
		Target:      "http://example.com",
		RawRequest:  "GET / HTTP/1.1\r\n\r\n",
		RawResponse: "HTTP/1.1 200 OK\r\n\r\n",
	}

	_, err := p.Analyze(ctx, req)
	if err == nil {
		t.Fatal("期望 Analyze 返回错误")
	}
}

func TestOpenAIProvider_Analyze_ContextTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 故意延迟超过超时时间
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	p := NewOpenAIProvider("", server.URL, "gpt-4o", "openai", 1)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	req := &AnalyzeRequest{
		TemplateID:  "test-009",
		Target:      "http://example.com",
		RawRequest:  "GET / HTTP/1.1\r\n\r\n",
		RawResponse: "HTTP/1.1 200 OK\r\n\r\n",
	}

	_, err := p.Analyze(ctx, req)
	if err == nil {
		t.Fatal("期望 Analyze 因超时而返回错误")
	}
}

func TestOpenAIProvider_Analyze_NilRequest(t *testing.T) {
	p := NewOpenAIProvider("key", "https://api.openai.com/v1", "gpt-4o", "openai", 10)
	ctx := context.Background()

	_, err := p.Analyze(ctx, nil)
	if err == nil {
		t.Fatal("期望传入 nil 时返回错误")
	}
}

func TestOpenAIProvider_Analyze_EmptyChoices(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := openaiChatResponse{Choices: []openaiChatChoice{}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	p := NewOpenAIProvider("", server.URL, "gpt-4o", "openai", 10)
	ctx := context.Background()
	req := &AnalyzeRequest{
		TemplateID:  "test-010",
		Target:      "http://example.com",
		RawRequest:  "GET / HTTP/1.1\r\n\r\n",
		RawResponse: "HTTP/1.1 200 OK\r\n\r\n",
	}

	_, err := p.Analyze(ctx, req)
	if err == nil {
		t.Fatal("期望空 choices 时返回错误")
	}
}

// --- 辅助函数 ---

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}

// mockProvider 是用于测试的模拟提供商。
type mockProvider struct {
	name string
}

func (m *mockProvider) Name() string {
	return m.name
}

func (m *mockProvider) Analyze(ctx context.Context, req *AnalyzeRequest) (*AnalyzeResponse, error) {
	return &AnalyzeResponse{
		Confident:      true,
		Confidence:     0.8,
		Suggestions:    []string{"mock 建议"},
		RiskAssessment: "mock 评估",
	}, nil
}

func (m *mockProvider) Available() bool {
	return true
}
