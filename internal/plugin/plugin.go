package plugin

import (
	"context"
	"time"

	"github.com/gosleek/gosleek/internal/httpclient"
	"github.com/gosleek/gosleek/internal/placeholder"
	"github.com/gosleek/gosleek/pkg/types"
)

// Plugin 是 Go 编写的复杂漏洞验证单元，与 YAML 模板地位对等。
// 通过编译期 init() 注册到全局 registry，由 engine 统一调度。
type Plugin interface {
	// Meta 返回元信息（id/name/severity/tags 等），用于过滤、输出、resume 去重
	Meta() types.TemplateMeta

	// Fingerprints 可选：返回指纹预筛规则，命中才执行 Verify。
	// 返回 nil 表示不做指纹过滤，对所有目标执行。
	Fingerprints() []types.FingerprintRule

	// Verify 执行复杂验证。返回 nil 表示未命中。
	// ctx 携带超时和取消信号，PCtx 提供引擎能力（HTTP 客户端、OOB、占位符等）。
	Verify(ctx context.Context, pctx *Context) (*types.Result, error)

	// NeedsOOB 报告插件是否需要带外验证（OOB）。
	// 当返回 true 且未配置 OOB 时，scanner 会跳过该插件并输出警告。
	NeedsOOB() bool
}

// Context 由 engine 注入的执行环境，插件只依赖此结构体。
type Context struct {
	Target     string                  // 目标 URL
	TargetInfo *placeholder.TargetInfo  // 解析后的目标信息
	Client     *httpclient.Client       // 复用现有 HTTP 客户端（含代理/超时/限速）
	Eng        *placeholder.Engine      // 占位符引擎（已注入 OOB/变量）
	Ceye       OOBHandle                // 无回显验证（ceye API 轮询）
	Log        Logger                   // 日志接口
	Reporter   Reporter                 // 与 YAML 工作流对齐的结构化日志输出
	Vars       map[string]string        // 跨请求共享变量（对标 workflow 的 extracted scope）
}

// Reporter 提供与 YAML 工作流一致的日志输出能力 (Burp-style 请求/响应包 + 匹配结果)。
// 引擎注入实现，插件在每个 HTTP 请求/响应步骤调用。
//
// 与 YAML 工作流输出格式对齐:
//
//	[信息] workFlow HTTP request sent    step=... url=...
//	[请求] workFlow[stepName] step[0] req[0]    POST ... HTTP/1.1
//	                     REQUEST
//	POST /path HTTP/1.1
//	...
//	[信息] workFlow HTTP response received    step=... status=... time_ms=...
//	[响应] workFlow[stepName] step[0] req[0]    status=200    9.481s    0 bytes
//	                     RESPONSE
//	HTTP/1.1 200 OK
//	...
//	[信息] workFlow matcher PASS    step=... types=... evidence=...
//	[匹配] workFlow[stepName] step[0] req[0]    PASS    cond=and    types=...    evidence=...
type Reporter interface {
	// LogStep 记录步骤执行开始 (对标 workflow step executing)
	LogStep(stepName string, stepIndex int)
	// LogRequest 记录 HTTP 请求 (对标 [请求] 输出, -vv 级别展示 Burp-style 原始包)
	LogRequest(stepName string, stepIndex int, reqIndex int, raw string)
	// LogResponse 记录 HTTP 响应 (对标 [响应] 输出, -vv 级别展示 Burp-style 原始包)
	LogResponse(stepName string, stepIndex int, reqIndex int, status int, body string, raw string, elapsed time.Duration)
	// LogMatch 记录匹配结果 (对标 [匹配] 输出, -vv 级别展示 PASS/FAIL + 证据)
	LogMatch(stepName string, stepIndex int, reqIndex int, matched bool, condition string, types []string, evidence string)
}

// OOBHandle 带外验证句柄，插件可自主控制 OOB 回连检测逻辑。
type OOBHandle interface {
	// Label 当前 OOB 标签（如 gs-a1b2c3d4）
	Label() string
	// URL 完整回连地址（如 gs-a1b2c3d4.foo.ceye.io）
	URL() string
	// VerifyDNS 检查是否有 DNS 回连记录
	VerifyDNS(ctx context.Context) (bool, error)
	// VerifyHTTP 检查是否有 HTTP 回连记录
	VerifyHTTP(ctx context.Context) (bool, error)
}

// Logger 插件可用的日志接口
type Logger interface {
	Info(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
	Error(msg string, args ...interface{})
}
