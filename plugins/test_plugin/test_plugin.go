package test_plugin

import (
	"context"
	"fmt"
	"strings"

	"github.com/gosleek/gosleek/internal/plugin"
	"github.com/gosleek/gosleek/pkg/types"
)

// TestWebUIPlugin 测试 Web UI 结果集成
// 模拟一个真实场景：检测目标是否暴露管理面板
type TestWebUIPlugin struct{}

func init() { plugin.Register(&TestWebUIPlugin{}) }

func (p *TestWebUIPlugin) Meta() types.TemplateMeta {
	return types.TemplateMeta{
		ID:          "test-webui-plugin",
		Name:        "Web UI 结果集成测试",
		Description: "检测目标是否暴露管理面板路径，结果应自动显示在 Web UI 中",
		Severity:    types.SeverityInfo,
		Author:      "gosleek-test",
		Tags:        []string{"test", "webui", "integration"},
	}
}

func (p *TestWebUIPlugin) Fingerprints() []types.FingerprintRule {
	return nil
}

func (p *TestWebUIPlugin) PreRun(ctx context.Context, pctx *plugin.Context) error {
	return nil
}

func (p *TestWebUIPlugin) Verify(ctx context.Context, pctx *plugin.Context) (*types.Result, error) {
	reporter := pctx.Reporter
	paths := []string{"/admin", "/admin.php", "/wp-admin", "/login", "/api/v1/health"}

	for i, path := range paths {
		reporter.LogStep("path-probe", i)
		rawReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", path, pctx.TargetInfo.Hostname)
		reporter.LogRequest("path-probe", i, 0, rawReq)

		resp, err := pctx.Client.SendRaw(ctx, pctx.Target, rawReq)
		if err != nil {
			reporter.LogResponse("path-probe", i, 0, 0, "", "", 0)
			pctx.Log.Debug("路径 %s 请求失败: %v", path, err)
			continue
		}
		reporter.LogResponse("path-probe", i, 0, resp.StatusCode, resp.Body, resp.Raw, resp.Time)

		if resp.StatusCode >= 200 && resp.StatusCode < 400 &&
			!strings.Contains(resp.Body, "404") && !strings.Contains(resp.Body, "Not Found") {
			reporter.LogMatch("path-probe", i, 0, true, "or", []string{"status", "word"},
				fmt.Sprintf("path=%s, status=%d", path, resp.StatusCode))

			return &types.Result{
				TemplateID:  p.Meta().ID,
				Name:        p.Meta().Name,
				Severity:    p.Meta().Severity,
				Target:      pctx.Target,
				Description: "发现可访问的管理/登录路径: " + path,
				Evidence:    fmt.Sprintf("path=%s, status=%d, body_len=%d", path, resp.StatusCode, len(resp.Body)),
				RawRequest:  rawReq,
				RawResponse: resp.Raw,
			}, nil
		}

		reporter.LogMatch("path-probe", i, 0, false, "or", []string{"status"}, fmt.Sprintf("path=%s, status=%d (404)", path, resp.StatusCode))
	}

	return nil, nil
}

func (p *TestWebUIPlugin) PostRun(ctx context.Context, pctx *plugin.Context) {}
func (p *TestWebUIPlugin) NeedsOOB() bool { return false }

// ─────────────────────────────────────────────────────────────────────────────

// TestReportPlugin 测试报告生成功能
// 模拟一个真实场景：检测安全头缺失
type TestReportPlugin struct{}

func init() { plugin.Register(&TestReportPlugin{}) }

func (p *TestReportPlugin) Meta() types.TemplateMeta {
	return types.TemplateMeta{
		ID:          "test-report-plugin",
		Name:        "报告生成集成测试",
		Description: "检测目标安全头缺失情况，结果应正确出现在 HTML/DOCX 报告中",
		Severity:    types.SeverityLow,
		Author:      "gosleek-test",
		Tags:        []string{"test", "report", "security-headers"},
	}
}

func (p *TestReportPlugin) Fingerprints() []types.FingerprintRule {
	return nil
}

func (p *TestReportPlugin) PreRun(ctx context.Context, pctx *plugin.Context) error {
	return nil
}

func (p *TestReportPlugin) Verify(ctx context.Context, pctx *plugin.Context) (*types.Result, error) {
	reporter := pctx.Reporter
	rawReq := "GET / HTTP/1.1\r\nHost: " + pctx.TargetInfo.Hostname + "\r\n\r\n"
	reporter.LogStep("header-check", 0)
	reporter.LogRequest("header-check", 0, 0, rawReq)

	resp, err := pctx.Client.SendRaw(ctx, pctx.Target, rawReq)
	if err != nil {
		reporter.LogResponse("header-check", 0, 0, 0, "", "", 0)
		pctx.Log.Error("请求失败: %v", err)
		return nil, nil
	}
	reporter.LogResponse("header-check", 0, 0, resp.StatusCode, resp.Body, resp.Raw, resp.Time)

	// 检查多个安全头
	missing := []string{}
	checkHeaders := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Strict-Transport-Security": "max-age",
	}

	for header, expected := range checkHeaders {
		if val := resp.GetHeader(header); val == "" {
			missing = append(missing, header)
		} else if expected != "" && !strings.Contains(strings.ToLower(val), expected) {
			missing = append(missing, header)
		}
	}

	if len(missing) > 0 {
		reporter.LogMatch("header-check", 0, 0, true, "or", []string{"header"},
			fmt.Sprintf("缺失安全头: %s", strings.Join(missing, ", ")))
		return &types.Result{
			TemplateID:  p.Meta().ID,
			Name:        p.Meta().Name,
			Severity:    p.Meta().Severity,
			Target:      pctx.Target,
			Description: "目标缺失安全头",
			Evidence:    fmt.Sprintf("缺失安全头: %s, 状态码: %d", strings.Join(missing, ", "), resp.StatusCode),
			RawRequest:  rawReq,
			RawResponse: resp.Raw,
		}, nil
	}

	reporter.LogMatch("header-check", 0, 0, false, "or", []string{"header"}, "所有安全头存在")
	return nil, nil
}

func (p *TestReportPlugin) PostRun(ctx context.Context, pctx *plugin.Context)       {}
func (p *TestReportPlugin) NeedsOOB() bool                                          { return false }

// ─────────────────────────────────────────────────────────────────────────────

// TestAIPlugin 测试 AI 辅助分析功能
// 模拟一个真实场景：检测潜在的信息泄露
type TestAIPlugin struct{}

func init() { plugin.Register(&TestAIPlugin{}) }

func (p *TestAIPlugin) Meta() types.TemplateMeta {
	return types.TemplateMeta{
		ID:          "test-ai-plugin",
		Name:        "AI 辅助分析集成测试",
		Description: "检测目标响应中是否包含敏感信息，AI 分析应评估泄露风险",
		Severity:    types.SeverityHigh,
		Author:      "gosleek-test",
		Tags:        []string{"test", "ai", "info-leak"},
	}
}

func (p *TestAIPlugin) Fingerprints() []types.FingerprintRule {
	return nil
}

func (p *TestAIPlugin) PreRun(ctx context.Context, pctx *plugin.Context) error {
	return nil
}

func (p *TestAIPlugin) Verify(ctx context.Context, pctx *plugin.Context) (*types.Result, error) {
	reporter := pctx.Reporter
	rawReq := "GET / HTTP/1.1\r\nHost: " + pctx.TargetInfo.Hostname + "\r\n\r\n"
	reporter.LogStep("sensitive-check", 0)
	reporter.LogRequest("sensitive-check", 0, 0, rawReq)

	resp, err := pctx.Client.SendRaw(ctx, pctx.Target, rawReq)
	if err != nil {
		reporter.LogResponse("sensitive-check", 0, 0, 0, "", "", 0)
		pctx.Log.Error("请求失败: %v", err)
		return nil, nil
	}
	reporter.LogResponse("sensitive-check", 0, 0, resp.StatusCode, resp.Body, resp.Raw, resp.Time)

	// 检测常见敏感信息模式
	sensitivePatterns := []string{
		"password", "secret", "api_key", "apikey",
		"private_key", "access_token", "client_secret",
		"database_url", "connection_string",
	}

	matched := false
	var evidence string
	for _, pattern := range sensitivePatterns {
		if strings.Contains(strings.ToLower(resp.Body), pattern) {
			matched = true
			evidence = fmt.Sprintf("响应中包含敏感关键词: %s", pattern)
			break
		}
	}

	if matched && resp.StatusCode == 200 {
		reporter.LogMatch("sensitive-check", 0, 0, true, "or", []string{"word"}, evidence)
		return &types.Result{
			TemplateID:  p.Meta().ID,
			Name:        p.Meta().Name,
			Severity:    p.Meta().Severity,
			Target:      pctx.Target,
			Description: "响应中包含疑似敏感信息",
			Evidence:    evidence,
			Extracted: map[string]string{
				"sensitive_pattern": evidence,
			},
			RawRequest:  rawReq,
			RawResponse: resp.Raw,
		}, nil
	}

	reporter.LogMatch("sensitive-check", 0, 0, false, "or", []string{"word"}, "未检测到敏感信息")
	return nil, nil
}

func (p *TestAIPlugin) PostRun(ctx context.Context, pctx *plugin.Context)       {}
func (p *TestAIPlugin) NeedsOOB() bool                                          { return false }
