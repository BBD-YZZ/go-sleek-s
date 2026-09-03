package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OpenAIProvider 实现 OpenAI 兼容 API 的 AI 提供商。
// 支持 OpenAI 官方 API、Azure OpenAI、DeepSeek、Kimi、GLM、Ollama、Agnes 等所有 OpenAI 兼容服务。
type OpenAIProvider struct {
	// APIKey 用于身份验证的 API Key。
	APIKey string
	// BaseURL 是 API 的基础地址，例如：
	//   "https://api.openai.com/v1"        （OpenAI 官方）
	//   "https://<resource>.openai.azure.com/openai/deployments/<deploy>"（Azure）
	//   "https://api.deepseek.com/v1"       （DeepSeek）
	//   "https://api.moonshot.cn/v1"        （Kimi / Moonshot）
	//   "https://open.bigmodel.cn/api/paas/v4"（GLM / 智谱）
	//   "http://localhost:11434/api"        （Ollama 本地）
	//   "https://api.sapiens.ai/v1"         （Agnes）
	BaseURL   string
	// Model 使用的模型名称，例如 "gpt-4o"、"gpt-4o-mini"、"llama3"、"deepseek-chat"。
	Model     string
	// Timeout 单次请求超时时间（秒），0 表示使用默认值 30s。
	Timeout   int
	// providerName 内部使用的提供商名称（用于日志和调试）。
	providerName string
}

// openaiChatRequest 是发送给 OpenAI 兼容 API 的请求体。
type openaiChatRequest struct {
	Model    string              `json:"model"`
	Messages []openaiChatMessage `json:"messages"`
	// ResponseFormat 强制 JSON 输出（OpenAI 官方及兼容实现支持）。
	ResponseFormat *openaiResponseFormat `json:"response_format,omitempty"`
}

// openaiChatMessage 表示一次对话消息。
type openaiChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// openaiResponseFormat 强制 JSON Schema 输出。
type openaiResponseFormat struct {
	Type string `json:"type"`
}

// openaiChatResponse 是 OpenAI 兼容 API 的响应体。
type openaiChatResponse struct {
	Choices []openaiChatChoice `json:"choices"`
	Error   *openaiAPIError    `json:"error,omitempty"`
}

// openaiChatChoice 是响应中的一个候选结果。
type openaiChatChoice struct {
	Message openaiChatMessage `json:"message"`
}

// openaiAPIError 表示 API 返回的错误信息。
type openaiAPIError struct {
	Message string `json:"message"`
	Type    string `json:"type,omitempty"`
}

// NewOpenAIProvider 创建一个 OpenAI 兼容提供商实例。
// 参数说明：
//   - apiKey:    API 密钥，Ollama 本地部署时可传空字符串
//   - baseURL:   API 基础地址
//   - model:     模型名称
//   - timeout:   超时秒数，0 表示 30s 默认值
func NewOpenAIProvider(apiKey, baseURL, model, providerName string, timeout int) *OpenAIProvider {
	if timeout <= 0 {
		timeout = 30
	}
	if providerName == "" {
		providerName = "openai"
	}
	return &OpenAIProvider{
		APIKey:         apiKey,
		BaseURL:        strings.TrimRight(baseURL, "/"),
		Model:          model,
		Timeout:        timeout,
		providerName:   providerName,
	}
}

// Name 返回提供商名称。
func (p *OpenAIProvider) Name() string {
	return p.providerName
}

// Available 检查提供商是否已正确配置。
// 有效条件：BaseURL 非空。
// 对于需要 API Key 的服务（OpenAI/DeepSeek/Kimi/GLM/Azure/Agnes），
// APIKey 也必须非空；Ollama 等本地服务不需要 API Key。
func (p *OpenAIProvider) Available() bool {
	if p.BaseURL == "" {
		return false
	}
	// Ollama 等本地服务不需要 API Key
	if p.providerName == "ollama" {
		return true
	}
	// 其他提供商需要 API Key
	return p.APIKey != ""
}

// Analyze 调用 OpenAI 兼容 API 对漏洞响应进行 AI 分析。
func (p *OpenAIProvider) Analyze(ctx context.Context, req *AnalyzeRequest) (*AnalyzeResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("分析请求不能为空")
	}

	prompt := BuildAnalysisPrompt(req)

	// 构建 API 请求体
	apiReq := openaiChatRequest{
		Model: p.Model,
		Messages: []openaiChatMessage{
			{Role: "system", Content: buildSystemPrompt()},
			{Role: "user", Content: prompt},
		},
		ResponseFormat: &openaiResponseFormat{Type: "json_object"},
	}

	bodyBytes, err := json.Marshal(apiReq)
	if err != nil {
		return nil, fmt.Errorf("序列化请求失败: %w", err)
	}

	// 确定 Chat Completions 端点 URL
	var chatURL string
	if strings.Contains(p.BaseURL, "openai.azure.com") {
		// Azure OpenAI: /openai/deployments/{model}/chat/completions?api-version=...
		chatURL = fmt.Sprintf("%s/chat/completions", p.BaseURL)
	} else {
		// OpenAI / DeepSeek / Kimi / GLM / Ollama / Agnes: {baseURL}/chat/completions
		chatURL = fmt.Sprintf("%s/chat/completions", p.BaseURL)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, chatURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("创建 HTTP 请求失败: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if p.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+p.APIKey)
	}

	client := &http.Client{
		Timeout: time.Duration(p.Timeout) * time.Second,
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("请求被取消: %w", ctx.Err())
		}
		return nil, fmt.Errorf("调用 AI API 失败: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AI API 返回错误状态码 %d: %s", resp.StatusCode, string(respBody))
	}

	var apiResp openaiChatResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("解析 AI 响应失败: %w", err)
	}

	if len(apiResp.Choices) == 0 {
		return nil, fmt.Errorf("AI 响应无结果")
	}

	if apiResp.Error != nil {
		return nil, fmt.Errorf("AI API 错误: %s (type: %s)", apiResp.Error.Message, apiResp.Error.Type)
	}

	content := apiResp.Choices[0].Message.Content
	return parseAnalyzeResponse(content, req)
}

// parseAnalyzeResponse 解析 AI 返回的 JSON 字符串为 AnalyzeResponse。
func parseAnalyzeResponse(content string, req *AnalyzeRequest) (*AnalyzeResponse, error) {
	// 移除可能的 markdown 代码块包装
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)

	var result AnalyzeResponse
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		// 尝试回退：从原始文本中提取关键字段
		result = fallbackParse(content, req)
	}
	return &result, nil
}

// fallbackParse 在 JSON 解析失败时的回退方案，从文本中提取关键字段。
func fallbackParse(content string, req *AnalyzeRequest) AnalyzeResponse {
	result := AnalyzeResponse{
		Confident:      false,
		Confidence:     0.5,
		Suggestions:    []string{},
		RiskAssessment: content,
	}

	// 简单提取置信度
	if strings.Contains(strings.ToLower(content), "high confidence") {
		result.Confidence = 0.9
		result.Confident = true
	} else if strings.Contains(strings.ToLower(content), "low confidence") {
		result.Confidence = 0.3
	}

	return result
}

// --- Fingerprint 识别 ---

// FingerprintResponse 是 AI 指纹识别的输出结构体。
type FingerprintResponse struct {
	Server     string  `json:"server"`
	Technology string  `json:"technology"`
	CMS        string  `json:"cms"`
	Language   string  `json:"language"`
	WAF        string  `json:"waf"`
	Confidence float64 `json:"confidence"`
}

// FingerprintRequest 是 AI 指纹识别的输入结构体。
type FingerprintRequest struct {
	Target      string
	RawResponse string
}

// ParseFingerprintResponse 从 AI 返回的文本中解析指纹信息。
func ParseFingerprintResponse(content string) (*FingerprintResponse, error) {
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)

	var fp FingerprintResponse
	if err := json.Unmarshal([]byte(content), &fp); err != nil {
		return nil, fmt.Errorf("解析指纹响应失败: %w", err)
	}
	if fp.Server == "" && fp.CMS == "" && fp.Technology == "" {
		return nil, fmt.Errorf("AI 返回的指纹信息为空")
	}
	return &fp, nil
}

// AnalyzeFingerprint 调用 OpenAI 兼容 API 进行目标指纹识别。
func (p *OpenAIProvider) AnalyzeFingerprint(ctx context.Context, req *FingerprintRequest) (*FingerprintResponse, error) {
	prompt := BuildFingerprintPrompt(req.Target, req.RawResponse)

	apiReq := openaiChatRequest{
		Model: p.Model,
		Messages: []openaiChatMessage{
			{Role: "system", Content: buildSystemPrompt()},
			{Role: "user", Content: prompt},
		},
		ResponseFormat: &openaiResponseFormat{Type: "json_object"},
	}

	bodyBytes, err := json.Marshal(apiReq)
	if err != nil {
		return nil, fmt.Errorf("序列化指纹请求失败: %w", err)
	}

	chatURL := fmt.Sprintf("%s/chat/completions", p.BaseURL)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, chatURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("创建 HTTP 请求失败: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if p.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+p.APIKey)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("调用 AI 指纹 API 失败: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取指纹响应失败: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AI 指纹 API 返回错误状态码 %d: %s", resp.StatusCode, string(respBody))
	}

	var apiResp openaiChatResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("解析 AI 指纹响应失败: %w", err)
	}

	if len(apiResp.Choices) == 0 {
		return nil, fmt.Errorf("AI 指纹响应无结果")
	}

	if apiResp.Error != nil {
		return nil, fmt.Errorf("AI API 错误: %s", apiResp.Error.Message)
	}

	return ParseFingerprintResponse(apiResp.Choices[0].Message.Content)
}

// BuildFingerprintPrompt 构建指纹识别提示词。
func BuildFingerprintPrompt(target string, rawResponse string) string {
	var sb strings.Builder
	sb.WriteString("## 目标指纹识别任务\n\n")
	sb.WriteString(fmt.Sprintf("- **目标**: %s\n\n", target))
	sb.WriteString("### 目标响应\n\n")
	sb.WriteString("```http\n")
	sb.WriteString(rawResponse)
	sb.WriteString("\n```\n\n")
	sb.WriteString("请分析以上 HTTP 响应的技术特征，识别以下信息并以 JSON 格式返回：\n\n")
	sb.WriteString("- **server**: HTTP 服务器类型\n")
	sb.WriteString("- **technology**: 使用的技术栈\n")
	sb.WriteString("- **cms**: 内容管理系统\n")
	sb.WriteString("- **language**: 编程语言\n")
	sb.WriteString("- **waf**: 安全设备\n")
	sb.WriteString("- **confidence**: 置信度评分（0.0-1.0）\n\n")
	sb.WriteString("请以 JSON 格式返回：\n")
	sb.WriteString(`{"server": "string", "technology": "string", "cms": "string", "language": "string", "waf": "string", "confidence": 0.5}`)
	return sb.String()
}

// buildSystemPrompt 构建系统提示词，设定 AI 的角色和行为准则。
func buildSystemPrompt() string {
	return `你是一个经验丰富的网络安全漏洞分析师，专门从事 Web 应用安全测试和渗透测试。
你的分析风格专业、严谨，善于从 HTTP 请求/响应的细节中找出漏洞证据。

你的职责：
1. 分析给定的 HTTP 请求和响应内容，判断是否存在安全漏洞
2. 提供详细的漏洞证据和验证方法
3. 评估漏洞的实际影响和风险
4. 给出可操作的修复建议

输出要求：
- 必须返回有效的 JSON 格式
- 所有字段都必须填充具体内容，不要留空
- 证据片段应直接从原始请求/响应中提取
- PoC 应简洁明了，攻击者可以据此验证漏洞
- 影响评估要具体说明攻击者能做什么

JSON 字段说明：
  - confident: boolean，是否有足够置信度做出判断
  - confidence: float，置信度评分 0.0-1.0
  - evidence: string，从请求/响应中提取的关键证据片段
  - exploit: string，简要的验证 PoC 步骤
  - impact: string，漏洞被利用后的实际影响
  - remediation: string，具体的修复建议
  - suggestions: string 数组，进一步验证建议
  - risk_assessment: string，综合风险评估描述

请保持客观、专业，仅基于提供的请求/响应内容进行分析，不要臆测。`
}
