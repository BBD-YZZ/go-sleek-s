package plugin

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gosleek/gosleek/internal/httpclient"
	"github.com/gosleek/gosleek/internal/oob"
)

// pluginOOBHandle 封装 OOBHandle 接口，委托给 oob.Provider 实现。
// 支持 ceye / dnslog / callbackred 三种 Provider。
type pluginOOBHandle struct {
	label      string
	oobURL     string
	token      string
	provider   oob.Provider
	httpClient *httpclient.Client
}

// NewOOBHandle 创建 OOB 验证句柄，支持 ceye/dnslog/callbackred。
// 推荐使用此函数替代已废弃的 NewCeyeHandle。
func NewOOBHandle(provider oob.Provider, client *httpclient.Client) OOBHandle {
	if provider == nil {
		return nil
	}
	return &pluginOOBHandle{
		label:      provider.Label(),
		oobURL:     provider.CallbackURL(),
		token:      provider.Token(),
		provider:   provider,
		httpClient: client,
	}
}

// Deprecated: NewCeyeHandle 已废弃，请使用 NewOOBHandle 替代。
// 此函数仅保持向后兼容，内部仍委托给 NewOOBHandle。
func NewCeyeHandle(label, oobURL, ceyeToken string, client *httpclient.Client) OOBHandle {
	// 创建临时的 ceye provider 用于向后兼容
	provider := oob.NewOobProvider("ceye", ceyeToken)
	// 传递共享客户端和日志回调，使 ceye API 请求可被记录
	if provider != nil && client != nil {
		provider.SetClient(client)
		// 注意: 需要调用方传入 onPacket/onRaw 回调，否则 OOB API 无日志
		provider.SetVerbose(2, nil, nil)
	}
	h := NewOOBHandle(provider, client)
	// 覆盖 label 和 oobURL（因为临时 provider 的 Probe 未被调用）
	if h != nil {
		ph := h.(*pluginOOBHandle)
		ph.label = label
		ph.oobURL = oobURL
	}
	return h
}

func (c *pluginOOBHandle) Label() string { return c.label }
func (c *pluginOOBHandle) URL() string   { return c.oobURL }

// VerifyDNS 查询 OOB Provider 是否有 DNS 回连记录。
func (c *pluginOOBHandle) VerifyDNS(ctx context.Context) (bool, error) {
	if c.provider == nil {
		return false, fmt.Errorf("OOB provider not set")
	}
	return c.provider.VerifyDNS(ctx)
}

// VerifyHTTP 查询 OOB Provider 是否有 HTTP 回连记录。
func (c *pluginOOBHandle) VerifyHTTP(ctx context.Context) (bool, error) {
	if c.provider == nil {
		return false, fmt.Errorf("OOB provider not set")
	}
	return c.provider.VerifyHTTP(ctx)
}

// pluginLogger 适配 engine.LoggerIface，实现 plugin.Logger 接口。
type pluginLogger struct {
	target string
	id     string
	inner  interface {
		DebugKV(msg string, args ...interface{})
		InfoKV(msg string, args ...interface{})
		WarnKV(msg string, args ...interface{})
		Error(msg string, args ...interface{})
	}
}

// NewPluginLogger 创建插件日志器。
func NewPluginLogger(id string, inner interface {
	DebugKV(msg string, args ...interface{})
	InfoKV(msg string, args ...interface{})
	WarnKV(msg string, args ...interface{})
	Error(msg string, args ...interface{})
}) Logger {
	return &pluginLogger{id: id, inner: inner}
}

// plugin.Logger 接口的 Info/Debug/Error 语义是 printf-style (msg 含 %s/%d, args 是参数)。
// engine.LoggerIface (InfoKV/DebugKV/Error) 的语义是 slog structured: msg 是裸文本, args 是 KV 对列表。
// 这里先 fmt.Sprintf 格式化好消息, 再把 plugin=id 作为结构化 tag 附加。
func (l *pluginLogger) Info(msg string, args ...interface{}) {
	var formatted string
	if len(args) == 0 {
		formatted = msg
	} else {
		formatted = fmt.Sprintf(msg, args...)
	}
	l.inner.InfoKV(formatted, "plugin", l.id)
}

func (l *pluginLogger) Debug(msg string, args ...interface{}) {
	var formatted string
	if len(args) == 0 {
		formatted = msg
	} else {
		formatted = fmt.Sprintf(msg, args...)
	}
	l.inner.DebugKV(formatted, "plugin", l.id)
}

func (l *pluginLogger) Error(msg string, args ...interface{}) {
	var formatted string
	if len(args) == 0 {
		formatted = msg
	} else {
		formatted = fmt.Sprintf(msg, args...)
	}
	l.inner.Error(formatted, "plugin", l.id)
}

// pluginReporter 实现 Reporter 接口，输出与 YAML 工作流一致的日志格式。
// 对接 engine 的 logger (InfoKV/DebugKV) + onPacket (Burp-style 包输出) + onRaw (匹配结果)。
type pluginReporter struct {
	id      string
	verbose int
	logger  interface {
		InfoKV(msg string, args ...interface{})
		DebugKV(msg string, args ...interface{})
		WarnKV(msg string, args ...interface{})
		Error(msg string, args ...interface{})
	}
	onPacket func(tag string, summary string, raw string)
	onRaw    func(tag string, format string, args ...interface{})
}

// NewPluginReporter 创建 Reporter 实例，注入 engine 的回调。
func NewPluginReporter(
	id string,
	verbose int,
	logger interface {
		InfoKV(msg string, args ...interface{})
		DebugKV(msg string, args ...interface{})
		WarnKV(msg string, args ...interface{})
		Error(msg string, args ...interface{})
	},
	onPacket func(tag string, summary string, raw string),
	onRaw func(tag string, format string, args ...interface{}),
) Reporter {
	return &pluginReporter{
		id:       id,
		verbose:  verbose,
		logger:   logger,
		onPacket: onPacket,
		onRaw:    onRaw,
	}
}

// LogStep 记录步骤执行开始。
func (r *pluginReporter) LogStep(stepName string, stepIndex int) {
	if r.logger != nil {
		r.logger.InfoKV("workflow step executing",
			"step", stepName, "step_index", stepIndex,
			"template", r.id)
	}
}

// LogRequest 记录 HTTP 请求，格式与 YAML 工作流一致。
func (r *pluginReporter) LogRequest(stepName string, stepIndex int, reqIndex int, raw string) {
	method, path := parseMethodPath(raw)

	if r.logger != nil {
		r.logger.InfoKV("workflow HTTP request sent",
			"step", stepName, "step_index", stepIndex, "req", reqIndex,
			"url", path, "method", method)
	}

	if r.verbose >= 2 && r.onPacket != nil {
		summary := fmt.Sprintf("workflow[%s] step[%d] req[%d]  %s %s  %d bytes",
			stepName, stepIndex, reqIndex, method, path, len(raw))
		r.onPacket("请求", summary, raw)
	}
}

// LogResponse 记录 HTTP 响应，格式与 YAML 工作流一致。
func (r *pluginReporter) LogResponse(stepName string, stepIndex int, reqIndex int, status int, body string, raw string, elapsed time.Duration) {
	if r.logger != nil {
		r.logger.InfoKV("workflow HTTP response received",
			"step", stepName, "step_index", stepIndex, "req", reqIndex,
			"status", status, "time_ms", elapsed.Milliseconds(),
			"bytes", len(body))
	}

	if r.verbose >= 2 && r.onPacket != nil {
		summary := fmt.Sprintf("workflow[%s] step[%d] req[%d]  status=%d  %s  %d bytes",
			stepName, stepIndex, reqIndex, status,
			elapsed.Round(time.Millisecond), len(body))
		r.onPacket("响应", summary, raw)
	}
}

// LogMatch 记录匹配结果，格式与 YAML 工作流一致。
func (r *pluginReporter) LogMatch(stepName string, stepIndex int, reqIndex int, matched bool, condition string, types []string, evidence string) {
	typesStr := strings.Join(types, ",")

	if r.logger != nil {
		if matched {
			r.logger.InfoKV("workflow matcher PASS",
				"step", stepName, "step_index", stepIndex, "req", reqIndex,
				"condition", condition,
				"types", typesStr, "evidence", evidence)
		} else {
			r.logger.InfoKV("workflow matcher FAIL",
				"step", stepName, "step_index", stepIndex, "req", reqIndex,
				"condition", condition,
				"types", typesStr)
		}
	}

	if r.verbose >= 2 && r.onRaw != nil {
		status := "FAIL"
		if matched {
			status = "PASS"
		}
		r.onRaw("匹配", "workflow[%s] step[%d] req[%d]  %s  cond=%s  types=%s  evidence=%q",
			stepName, stepIndex, reqIndex, status, condition, typesStr, evidence)
	}
}

// parseMethodPath 从原始 HTTP 请求文本中解析 method 和 path。
func parseMethodPath(raw string) (method, path string) {
	firstLine := strings.SplitN(raw, "\r\n", 2)[0]
	parts := strings.SplitN(firstLine, " ", 3)
	if len(parts) >= 2 {
		return parts[0], parts[1]
	}
	return "?", "?"
}
