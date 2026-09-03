// Package reporter - HTML 报告生成器
// 提供比 output/file.go 中 writeHTML 更专业的增强 HTML 报告页面。
package reporter

import (
	"fmt"
	"html"
	"sort"
	"strings"
	"time"

	"github.com/gosleek/gosleek/pkg/types"
)

// generateHTMLReport 生成增强 HTML 报告内容。
// 包含：执行摘要、漏洞时间线、修复建议、目录、原始证据附录。
func generateHTMLReport(results []*types.Result, scanInfo *ScanInfo, cfg *ReporterConfig) ([]byte, error) {
	var sb strings.Builder

	// 统计信息
	sevCount := countBySeverity(results)
	targetCount := countByTarget(results)

	// 对结果按严重度排序
	sortedResults := make([]*types.Result, len(results))
	copy(sortedResults, results)
	sortResultsBySeverity(sortedResults)

	// HTML 头部
	sb.WriteString("<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n")
	sb.WriteString("<meta charset=\"UTF-8\">\n")
	sb.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n")
	sb.WriteString("<title>")
	sb.WriteString(html.EscapeString(cfg.Title))
	sb.WriteString(" - 安全扫描报告</title>\n")
	sb.WriteString("<style>\n")
	sb.WriteString("*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }\n")
	sb.WriteString("body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background: #0f0f23; color: #e0e0e0; line-height: 1.6; padding: 2em; }\n")
	sb.WriteString("h1 { color: #00d4ff; font-size: 1.8em; margin-bottom: 0.5em; }\n")
	sb.WriteString("h2 { color: #7fdbca; font-size: 1.2em; margin: 1.5em 0 0.5em; }\n")
	sb.WriteString("h3 { color: #aaa; font-size: 1em; margin: 1em 0 0.3em; }\n")
	sb.WriteString("p { color: #aaa; margin-bottom: 1em; }\n")
	sb.WriteString("a { color: #00d4ff; text-decoration: none; }\n")
	sb.WriteString("a:hover { text-decoration: underline; }\n")
	sb.WriteString(".toc { background: #1a1a2e; border-radius: 8px; padding: 1.5em; margin: 1em 0; }\n")
	sb.WriteString(".toc h2 { margin-top: 0; }\n")
	sb.WriteString(".toc ul { list-style: none; }\n")
	sb.WriteString(".toc li { margin: 0.3em 0; }\n")
	sb.WriteString(".toc a { color: #7fdbca; }\n")
	sb.WriteString(".stats { display: flex; gap: 1em; flex-wrap: wrap; margin: 1em 0; }\n")
	sb.WriteString(".stat { background: #1a1a2e; padding: 1em 1.5em; border-radius: 8px; flex: 1; min-width: 120px; text-align: center; }\n")
	sb.WriteString(".stat-value { font-size: 2em; font-weight: bold; color: #00d4ff; }\n")
	sb.WriteString(".stat-label { color: #aaa; font-size: 0.9em; }\n")
	sb.WriteString("table { border-collapse: collapse; width: 100%; margin-top: 1em; background: #1a1a2e; border-radius: 8px; overflow: hidden; }\n")
	sb.WriteString("th { background: #16213e; color: #00d4ff; font-weight: 600; text-align: left; padding: 12px 16px; border: none; }\n")
	sb.WriteString("td { padding: 12px 16px; border-bottom: 1px solid #2a2a4a; }\n")
	sb.WriteString("tr:hover { background: #1e1e3f; }\n")
	sb.WriteString("tr:last-child td { border-bottom: none; }\n")
	sb.WriteString(".badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: 600; }\n")
	sb.WriteString(".badge-critical { background: #ff4d4d22; color: #ff4d4d; }\n")
	sb.WriteString(".badge-high { background: #ff8c0022; color: #ff8c00; }\n")
	sb.WriteString(".badge-medium { background: #ffd70022; color: #ffd700; }\n")
	sb.WriteString(".badge-low { background: #87ceeb22; color: #87ceeb; }\n")
	sb.WriteString(".badge-info { background: #aaa222; color: #aaa; }\n")
	sb.WriteString(".evidence { font-family: 'Consolas', 'Monaco', monospace; font-size: 0.85em; color: #ccc; word-break: break-all; }\n")
	sb.WriteString(".summary { background: #1a1a2e; border-radius: 8px; padding: 1.5em; margin: 1em 0; }\n")
	sb.WriteString(".summary h3 { margin-top: 0; color: #00d4ff; }\n")
	sb.WriteString(".summary ul { padding-left: 1.5em; }\n")
	sb.WriteString(".summary li { margin: 0.3em 0; color: #aaa; }\n")
	sb.WriteString(".timeline { background: #1a1a2e; border-radius: 8px; padding: 1.5em; margin: 1em 0; }\n")
	sb.WriteString(".timeline-item { border-left: 2px solid #00d4ff; padding-left: 1em; margin: 1em 0; }\n")
	sb.WriteString(".timeline-time { color: #7fdbca; font-size: 0.85em; }\n")
	sb.WriteString(".timeline-title { color: #e0e0e0; font-weight: 600; }\n")
	sb.WriteString(".remediation { background: #1a1a2e; border-radius: 8px; padding: 1.5em; margin: 1em 0; }\n")
	sb.WriteString(".remediation h3 { color: #7fdbca; }\n")
	sb.WriteString(".remediation-item { margin: 0.8em 0; padding: 0.8em; background: #16213e; border-radius: 4px; }\n")
	sb.WriteString(".remediation-item h4 { color: #00d4ff; margin-bottom: 0.3em; }\n")
	sb.WriteString(".remediation-item p { color: #aaa; font-size: 0.9em; }\n")
	sb.WriteString(".appendix { background: #1a1a2e; border-radius: 8px; padding: 1.5em; margin: 1em 0; }\n")
	sb.WriteString(".appendix pre { background: #0f0f23; padding: 1em; border-radius: 4px; overflow-x: auto; font-size: 0.85em; color: #ccc; }\n")
	sb.WriteString("@media print {\n  body { background: #fff; color: #000; padding: 1em; }\n  h1, h2 { color: #000; }\n  .stat, .summary, .timeline, .remediation, .appendix, table { background: #f5f5f5; }\n  th { background: #ddd; color: #000; }\n  td { border-bottom: 1px solid #ccc; color: #000; }\n  .badge { border: 1px solid #999; }\n  a { color: #000; }\n  .evidence { color: #333; }\n}\n")
	sb.WriteString("</style>\n")
	sb.WriteString("</head>\n<body>\n")

	// 标题
	sb.WriteString(fmt.Sprintf("<h1>%s</h1>\n", html.EscapeString(cfg.Title)))
	sb.WriteString(fmt.Sprintf("<p>生成时间: %s</p>\n", time.Now().Format("2006-01-02 15:04:05")))

	// 执行摘要
	sb.WriteString("<div class=\"summary\">\n<h2>执行摘要</h2>\n<ul>\n")
	if cfg.Author != "" {
		sb.WriteString(fmt.Sprintf("<li>报告作者: %s</li>\n", html.EscapeString(cfg.Author)))
	}
	if cfg.Version != "" {
		sb.WriteString(fmt.Sprintf("<li>工具版本: %s</li>\n", html.EscapeString(cfg.Version)))
	}
	sb.WriteString(fmt.Sprintf("<li>扫描结果总数: %d</li>\n", len(results)))
	if scanInfo != nil {
		sb.WriteString(fmt.Sprintf("<li>扫描时间: %s ~ %s</li>\n",
			scanInfo.StartTime.Format("2006-01-02 15:04:05"),
			scanInfo.EndTime.Format("2006-01-02 15:04:05")))
		sb.WriteString(fmt.Sprintf("<li>目标数量: %d</li>\n", len(scanInfo.Targets)))
	}
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if count, ok := sevCount[sev]; ok && count > 0 {
			sb.WriteString(fmt.Sprintf("<li><strong>%s</strong>: %d</li>\n", strings.ToUpper(sev), count))
		}
	}
	sb.WriteString("</ul>\n</div>\n")

	// 严重度统计卡片
	sb.WriteString("<div class=\"stats\">\n")
	sb.WriteString(fmt.Sprintf("<div class=\"stat\"><div class=\"stat-value\">%d</div><div class=\"stat-label\">总漏洞数</div></div>\n", len(results)))
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if count, ok := sevCount[sev]; ok && count > 0 {
			sb.WriteString(fmt.Sprintf("<div class=\"stat\"><div class=\"stat-value\" style=\"color: %s;\">%d</div><div class=\"stat-label\">%s</div></div>\n",
				severityColor(sev), count, strings.ToUpper(sev)))
		}
	}
	sb.WriteString("</div>\n")

	// 目录
	sb.WriteString("<div class=\"toc\">\n<h2>目录</h2>\n<ul>\n")
	sb.WriteString("<li><a href=\"#summary\">执行摘要</a></li>\n")
	sb.WriteString("<li><a href=\"#severity\">严重度分布</a></li>\n")
	sb.WriteString("<li><a href=\"#timeline\">漏洞时间线</a></li>\n")
	sb.WriteString("<li><a href=\"#remediation\">修复建议</a></li>\n")
	sb.WriteString("<li><a href=\"#details\">漏洞详情</a></li>\n")
	sb.WriteString("<li><a href=\"#appendix\">附录：原始证据</a></li>\n")
	sb.WriteString("</ul>\n</div>\n")

	// 目标分布统计
	if len(targetCount) > 0 {
		sb.WriteString("<h2 id=\"severity\">目标漏洞分布</h2>\n")
		sb.WriteString("<table>\n<tr><th>目标</th><th>漏洞数</th></tr>\n")
		type targetStat struct {
			target string
			count  int
		}
		targetStats := make([]targetStat, 0, len(targetCount))
		for t, c := range targetCount {
			targetStats = append(targetStats, targetStat{t, c})
		}
		sort.Slice(targetStats, func(i, j int) bool {
			return targetStats[i].count > targetStats[j].count
		})
		for _, ts := range targetStats {
			label := ts.target
			if len(label) > 40 {
				label = label[:37] + "..."
			}
			sb.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%d</td></tr>\n", html.EscapeString(label), ts.count))
		}
		sb.WriteString("</table>\n")
	}

	// 漏洞时间线
	if len(sortedResults) > 0 {
		sb.WriteString("<h2 id=\"timeline\">漏洞时间线</h2>\n")
		sb.WriteString("<div class=\"timeline\">\n")
		for _, r := range sortedResults {
			ts := r.Timestamp.Format("2006-01-02 15:04:05")
			title := truncate(r.Name, 50)
			sb.WriteString(fmt.Sprintf("<div class=\"timeline-item\">\n"))
			sb.WriteString(fmt.Sprintf("<span class=\"timeline-time\">%s</span>\n", ts))
			sb.WriteString(fmt.Sprintf("<span class=\"timeline-title\">[%s] %s</span>\n", strings.ToUpper(r.Severity), html.EscapeString(title)))
			sb.WriteString("</div>\n")
		}
		sb.WriteString("</div>\n")
	}

	// 修复建议
	sb.WriteString("<h2 id=\"remediation\">修复建议</h2>\n")
	sb.WriteString("<div class=\"remediation\">\n")
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if count, ok := sevCount[sev]; ok && count > 0 {
			reco := getRemediationForSeverity(sev)
			sb.WriteString(fmt.Sprintf("<div class=\"remediation-item\">\n"))
			sb.WriteString(fmt.Sprintf("<h4>%s 漏洞 (%d 个)</h4>\n", strings.ToUpper(sev), count))
			sb.WriteString(fmt.Sprintf("<p>%s</p>\n", reco))
			sb.WriteString("</div>\n")
		}
	}
	sb.WriteString("</div>\n")

	// 漏洞详情
	sb.WriteString("<h2 id=\"details\">漏洞详情</h2>\n")
	sb.WriteString("<table>\n<tr><th>严重度</th><th>模板 ID</th><th>名称</th><th>目标</th><th>证据</th></tr>\n")
	for _, r := range sortedResults {
		sevClass := strings.ToLower(r.Severity)
		ev := html.EscapeString(r.Evidence)
		if len(ev) > 150 {
			ev = ev[:150] + "…"
		}
		target := html.EscapeString(r.Target)
		if len(target) > 30 {
			target = target[:27] + "..."
		}
		sb.WriteString(fmt.Sprintf("<tr>\n"))
		sb.WriteString(fmt.Sprintf("<td><span class=\"badge badge-%s\">%s</span></td>\n", sevClass, strings.ToUpper(r.Severity)))
		sb.WriteString(fmt.Sprintf("<td>%s</td>\n", html.EscapeString(r.TemplateID)))
		sb.WriteString(fmt.Sprintf("<td>%s</td>\n", html.EscapeString(r.Name)))
		sb.WriteString(fmt.Sprintf("<td>%s</td>\n", target))
		sb.WriteString(fmt.Sprintf("<td class=\"evidence\">%s</td>\n", ev))
		sb.WriteString("</tr>\n")
	}
	sb.WriteString("</table>\n")

	// 附录：原始证据
	if len(sortedResults) > 0 {
		sb.WriteString("<h2 id=\"appendix\">附录：原始证据</h2>\n")
		sb.WriteString("<div class=\"appendix\">\n")
		for i, r := range sortedResults {
			sb.WriteString(fmt.Sprintf("<h3>%d. %s</h3>\n", i+1, html.EscapeString(r.Name)))
			sb.WriteString(fmt.Sprintf("<pre>模板ID: %s\n", html.EscapeString(r.TemplateID)))
			sb.WriteString(fmt.Sprintf("严重度: %s\n", strings.ToUpper(r.Severity)))
			sb.WriteString(fmt.Sprintf("目标:   %s\n", html.EscapeString(r.Target)))
			sb.WriteString(fmt.Sprintf("时间:   %s\n", r.Timestamp.Format("2006-01-02 15:04:05")))
			sb.WriteString(fmt.Sprintf("证据:   %s\n", html.EscapeString(truncate(r.Evidence, 500))))
			sb.WriteString("</pre>\n")
			if len(r.RawRequest) > 0 {
				sb.WriteString(fmt.Sprintf("<p><strong>原始请求:</strong></p>\n"))
				sb.WriteString(fmt.Sprintf("<pre>%s</pre>\n", html.EscapeString(truncate(r.RawRequest, 800))))
			}
			if len(r.RawResponse) > 0 {
				sb.WriteString(fmt.Sprintf("<p><strong>原始响应:</strong></p>\n"))
				sb.WriteString(fmt.Sprintf("<pre>%s</pre>\n", html.EscapeString(truncate(r.RawResponse, 800))))
			}
			if len(r.Extracted) > 0 {
				sb.WriteString("<p><strong>提取数据:</strong></p>\n<ul>\n")
				for k, v := range r.Extracted {
					sb.WriteString(fmt.Sprintf("<li>%s: %s</li>\n", html.EscapeString(k), html.EscapeString(v)))
				}
				sb.WriteString("</ul>\n")
			}
			sb.WriteString("<hr style=\"border-color: #2a2a4a; margin: 1em 0;\">\n")
		}
		sb.WriteString("</div>\n")
	}

	sb.WriteString("</body>\n</html>")
	return []byte(sb.String()), nil
}

// generatePrintableHTML 生成适合打印的 HTML 报告。
func generatePrintableHTML(results []*types.Result, scanInfo *ScanInfo, cfg *ReporterConfig) ([]byte, error) {
	var sb strings.Builder

	sevCount := countBySeverity(results)
	sortedResults := make([]*types.Result, len(results))
	copy(sortedResults, results)
	sortResultsBySeverity(sortedResults)

	sb.WriteString("<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n")
	sb.WriteString("<meta charset=\"UTF-8\">\n")
	sb.WriteString("<title>gosleek 安全扫描报告 - 打印版</title>\n")
	sb.WriteString("<style>\n")
	sb.WriteString("body { font-family: 'SimSun', 'Microsoft YaHei', serif; color: #000; background: #fff; padding: 2em; }\n")
	sb.WriteString("h1 { text-align: center; font-size: 1.5em; margin-bottom: 1em; }\n")
	sb.WriteString("h2 { font-size: 1.1em; margin: 1.5em 0 0.5em; border-bottom: 1px solid #ccc; padding-bottom: 0.3em; }\n")
	sb.WriteString("table { border-collapse: collapse; width: 100%; margin: 1em 0; }\n")
	sb.WriteString("th, td { border: 1px solid #999; padding: 6px 10px; text-align: left; font-size: 0.9em; }\n")
	sb.WriteString("th { background: #f0f0f0; }\n")
	sb.WriteString(".badge { padding: 2px 6px; border-radius: 3px; font-size: 0.85em; font-weight: bold; }\n")
	sb.WriteString(".badge-critical { background: #ff4d4d; color: #fff; }\n")
	sb.WriteString(".badge-high { background: #ff8c00; color: #fff; }\n")
	sb.WriteString(".badge-medium { background: #ffd700; color: #000; }\n")
	sb.WriteString(".badge-low { background: #87ceeb; color: #000; }\n")
	sb.WriteString(".badge-info { background: #aaa; color: #000; }\n")
	sb.WriteString(".evidence { font-family: monospace; font-size: 0.8em; word-break: break-all; }\n")
	sb.WriteString(".stats { display: flex; gap: 2em; margin: 1em 0; }\n")
	sb.WriteString(".stat { text-align: center; }\n")
	sb.WriteString(".stat-value { font-size: 1.5em; font-weight: bold; }\n")
	sb.WriteString(".stat-label { font-size: 0.9em; color: #666; }\n")
	sb.WriteString(".footer { margin-top: 2em; text-align: center; font-size: 0.8em; color: #666; }\n")
	sb.WriteString("</style>\n")
	sb.WriteString("</head>\n<body>\n")
	sb.WriteString(fmt.Sprintf("<h1>%s</h1>\n", html.EscapeString(cfg.Title)))
	sb.WriteString(fmt.Sprintf("<p style=\"text-align:center;color:#666;\">生成时间: %s</p>\n", time.Now().Format("2006-01-02 15:04:05")))

	// 统计
	sb.WriteString("<div class=\"stats\">\n")
	sb.WriteString(fmt.Sprintf("<div class=\"stat\"><div class=\"stat-value\">%d</div><div class=\"stat-label\">总漏洞数</div></div>\n", len(results)))
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if count, ok := sevCount[sev]; ok && count > 0 {
			sb.WriteString(fmt.Sprintf("<div class=\"stat\"><div class=\"stat-value\" style=\"color:%s;\">%d</div><div class=\"stat-label\">%s</div></div>\n",
				severityColor(sev), count, strings.ToUpper(sev)))
		}
	}
	sb.WriteString("</div>\n")

	// 漏洞表格
	sb.WriteString("<h2>漏洞清单</h2>\n")
	sb.WriteString("<table>\n<tr><th>序号</th><th>严重度</th><th>模板ID</th><th>名称</th><th>目标</th><th>证据</th></tr>\n")
	for i, r := range sortedResults {
		sevClass := strings.ToLower(r.Severity)
		ev := html.EscapeString(r.Evidence)
		if len(ev) > 80 {
			ev = ev[:80] + "…"
		}
		target := html.EscapeString(r.Target)
		if len(target) > 25 {
			target = target[:22] + "..."
		}
		sb.WriteString(fmt.Sprintf("<tr>\n<td>%d</td>\n", i+1))
		sb.WriteString(fmt.Sprintf("<td><span class=\"badge badge-%s\">%s</span></td>\n", sevClass, strings.ToUpper(r.Severity)))
		sb.WriteString(fmt.Sprintf("<td>%s</td>\n", html.EscapeString(r.TemplateID)))
		sb.WriteString(fmt.Sprintf("<td>%s</td>\n", html.EscapeString(r.Name)))
		sb.WriteString(fmt.Sprintf("<td>%s</td>\n", target))
		sb.WriteString(fmt.Sprintf("<td class=\"evidence\">%s</td>\n", ev))
		sb.WriteString("</tr>\n")
	}
	sb.WriteString("</table>\n")
	sb.WriteString(fmt.Sprintf("<div class=\"footer\"><p>本报告由 gosleek 自动生成 | %s</p></div>\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString("</body>\n</html>")

	return []byte(sb.String()), nil
}
