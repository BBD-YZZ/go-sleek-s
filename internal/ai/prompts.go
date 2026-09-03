package ai

import (
	"fmt"
	"strings"

	"github.com/gosleek/gosleek/pkg/types"
)

// BuildAnalysisPrompt 构建用于 AI 漏洞分析的提示词。
// 根据请求内容生成结构化的提示，引导 AI 进行专业分析。
func BuildAnalysisPrompt(req *AnalyzeRequest) string {
	var sb strings.Builder

	// 标题
	sb.WriteString("## 漏洞分析报告请求\n\n")
	sb.WriteString(fmt.Sprintf("- **模板ID**: %s\n", req.TemplateID))
	sb.WriteString(fmt.Sprintf("- **模板名称**: %s\n", req.TemplateName))
	sb.WriteString(fmt.Sprintf("- **严重度**: %s\n", req.Severity))
	sb.WriteString(fmt.Sprintf("- **目标**: %s\n\n", req.Target))

	// 原始请求
	sb.WriteString("### 原始 HTTP 请求\n\n")
	sb.WriteString("```http\n")
	sb.WriteString(req.RawRequest)
	sb.WriteString("\n```\n\n")

	// 原始响应
	sb.WriteString("### 原始 HTTP 响应\n\n")
	sb.WriteString("```http\n")
	sb.WriteString(req.RawResponse)
	sb.WriteString("\n```\n\n")

	// 证据
	if req.Evidence != "" {
		sb.WriteString("### 命中证据\n\n")
		sb.WriteString(fmt.Sprintf("```\n%s\n```\n\n", req.Evidence))
	}

	// 提取数据
	if len(req.Extracted) > 0 {
		sb.WriteString("### 提取的变量\n\n")
		sb.WriteString("```json\n")
		for k, v := range req.Extracted {
			sb.WriteString(fmt.Sprintf("%s: %s\n", k, v))
		}
		sb.WriteString("```\n\n")
	}

	// 附加上下文
	if req.Context != "" {
		sb.WriteString("### 附加上下文\n\n")
		sb.WriteString(req.Context)
		sb.WriteString("\n\n")
	}

	// 分析指令
	sb.WriteString("## 分析任务\n\n")
	sb.WriteString("你是一个专业的网络安全漏洞分析师。请根据以下 HTTP 请求和响应内容，进行全面、深入的漏洞分析。\n\n")
	sb.WriteString("**分析要求：**\n\n")
	sb.WriteString("1. **漏洞确认**：详细分析请求/响应，判断是否存在所检测的漏洞。说明你的判断依据。\n")
	sb.WriteString("2. **漏洞证据**：从响应中提取能够证明漏洞存在的关键证据片段。\n")
	sb.WriteString("3. **验证 PoC**：提供简短的可复现验证步骤（1-2 句话），说明攻击者如何进一步确认漏洞。\n")
	sb.WriteString("4. **影响评估**：评估漏洞被利用后的实际影响范围（数据泄露、RCE、权限提升等）。\n")
	sb.WriteString("5. **修复建议**：提供具体可行的修复措施。\n")
	sb.WriteString("6. **置信度**：基于以上分析，给出你的判断置信度（0.0-1.0）。\n\n")

	// 严重度调整指引
	switch req.Severity {
	case "critical", "high":
		sb.WriteString("**注意**：这是高危/严重漏洞，请格外谨慎验证，提供详细的证据和 PoC。\n\n")
	case "medium", "low":
		sb.WriteString("**注意**：这是中低危漏洞，需要确认漏洞是否可被实际利用。\n\n")
	}

	sb.WriteString("## 输出格式\n\n")
	sb.WriteString("请以严格的 JSON 格式返回分析结果，必须包含以下所有字段：\n\n")
	sb.WriteString(`{`)
	sb.WriteString(`"confident": true,`)
	sb.WriteString(`"confidence": 0.95,`)
	sb.WriteString(`"evidence": "从响应中提取的关键证据片段",`)
	sb.WriteString(`"exploit": "1. 发送特定请求 2. 验证回连或响应特征",`)
	sb.WriteString(`"impact": "攻击者可完全控制系统，执行任意命令",`)
	sb.WriteString(`"remediation": "升级至最新安全版本，修补相关配置",`)
	sb.WriteString(`"suggestions": ["建议进一步验证步骤1", "建议进一步验证步骤2"],`)
	sb.WriteString(`"risk_assessment": "Critical: OOB DNS回连确认SpEL注入成功，可完全控制系统"`)
	sb.WriteString(`}`)
	sb.WriteString("\n\n注意：所有字段都必须填充有效内容，不要留空。")

	return sb.String()
}

// BuildConfirmationPrompt 构建漏洞确认提示词。
// 当检测到潜在漏洞时，使用此提示词让 AI 进行二次确认，降低误报率。
func BuildConfirmationPrompt(result *types.Result, context string) string {
	var sb strings.Builder

	sb.WriteString("## 漏洞二次确认\n\n")
	sb.WriteString(fmt.Sprintf("- **模板ID**: %s\n", result.TemplateID))
	sb.WriteString(fmt.Sprintf("- **漏洞名称**: %s\n", result.Name))
	sb.WriteString(fmt.Sprintf("- **严重度**: %s\n", result.Severity))
	sb.WriteString(fmt.Sprintf("- **目标**: %s\n\n", result.Target))

	sb.WriteString("### 原始请求\n\n")
	sb.WriteString("```http\n")
	sb.WriteString(result.RawRequest)
	sb.WriteString("\n```\n\n")

	sb.WriteString("### 原始响应\n\n")
	sb.WriteString("```http\n")
	sb.WriteString(result.RawResponse)
	sb.WriteString("\n```\n\n")

	if result.Evidence != "" {
		sb.WriteString("### 命中证据\n\n")
		sb.WriteString(fmt.Sprintf("```\n%s\n```\n\n", result.Evidence))
	}

	if context != "" {
		sb.WriteString("### 上下文信息\n\n")
		sb.WriteString(context)
		sb.WriteString("\n\n")
	}

	sb.WriteString("## 确认任务\n\n")
	sb.WriteString("基于以上信息，请确认：\n\n")
	sb.WriteString("1. 这是否是一个真实的漏洞？请说明理由。\n")
	sb.WriteString("2. 置信度评分是多少（0.0-1.0）？\n")
	sb.WriteString("3. 是否存在误报的可能性？如果有，请说明原因。\n\n")
	sb.WriteString("请以 JSON 格式返回：")
	sb.WriteString(`{"is_valid": true/false, "confidence": 0.0-1.0, "reason": "确认理由"}`)

	return sb.String()
}

// BuildFingerprintPrompt 构建指纹识别提示词。
// 在扫描开始时，将目标响应发送给 AI 进行自动指纹识别。
