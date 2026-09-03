package ai

import (
	"context"

	"github.com/gosleek/gosleek/pkg/types"
)

// Provider 是 LLM 后端的通用接口。
// 所有 AI 提供商（OpenAI、Azure、Ollama 等）均需实现此接口。
type Provider interface {
	// Name 返回提供商名称（如 "openai"、"azure"、"local"）。
	Name() string
	// Analyze 对请求响应内容进行 AI 辅助分析，返回置信度评分与风险建议。
	Analyze(ctx context.Context, req *AnalyzeRequest) (*AnalyzeResponse, error)
	// Available 检查提供商是否已正确配置（API Key、BaseURL 等）。
	Available() bool
}

// AnalyzeRequest 是 AI 分析的输入结构体。
type AnalyzeRequest struct {
	// TemplateID 模板唯一标识。
	TemplateID string `json:"template_id"`
	// TemplateName 模板名称。
	TemplateName string `json:"template_name"`
	// Severity 漏洞严重度（info/low/medium/high/critical）。
	Severity string `json:"severity"`
	// Target 目标 URL。
	Target string `json:"target"`
	// RawRequest 完整原始请求报文。
	RawRequest string `json:"raw_request"`
	// RawResponse 完整原始响应报文。
	RawResponse string `json:"raw_response"`
	// Evidence 命中的证据（匹配器内容）。
	Evidence string `json:"evidence"`
	// Extracted 提取的变量数据。
	Extracted map[string]string `json:"extracted,omitempty"`
	// Context 额外上下文信息（如模板描述、分类信息等）。
	Context string `json:"context,omitempty"`
}

// AnalyzeResponse 是 AI 分析的输出结构体。
type AnalyzeResponse struct {
	// Confident 表示 AI 是否有足够置信度做出判断。
	Confident bool `json:"confident"`
	// Confidence 置信度评分（0.0 ~ 1.0）。
	Confidence float64 `json:"confidence"`
	// Suggestions AI 给出的补充建议（如进一步验证方法）。
	Suggestions []string `json:"suggestions,omitempty"`
	// RiskAssessment 风险评估描述。
	RiskAssessment string `json:"risk_assessment,omitempty"`
	// Evidence 漏洞证据摘要（HTML 格式的命中片段）。
	Evidence string `json:"evidence,omitempty"`
	// Exploit 验证 PoC（攻击者如何利用此漏洞的简明步骤）。
	Exploit string `json:"exploit,omitempty"`
	// Impact 影响评估（漏洞被利用后的实际影响范围）。
	Impact string `json:"impact,omitempty"`
	// Remediation 修复建议（如何修复/缓解此漏洞）。
	Remediation string `json:"remediation,omitempty"`
	// OriginalResult 关联的原始检测结果（不序列化）。
	OriginalResult *types.Result `json:"-"`
}
