package output

import (
	"embed"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"strings"
	"time"

	"github.com/gosleek/gosleek/pkg/types"
)

//go:embed embeds/chart.umd.min.js
var chartJS embed.FS

// WriteFile writes results to a file in the specified format.
func WriteFile(results []*types.Result, path, format string) error {
	return WriteFileWithVersion(results, path, format, "")
}

// WriteFileWithVersion writes results with an explicit tool version (used for SARIF).
func WriteFileWithVersion(results []*types.Result, path, format, version string) error {
	switch strings.ToLower(format) {
	case "json":
		return writeJSON(results, path)
	case "txt":
		return writeTXT(results, path)
	case "sarif":
		return writeSARIF(results, path, version)
	case "html":
		return writeHTML(results, path)
	case "csv":
		return writeCSV(results, path)
	case "md", "markdown":
		return writeMarkdown(results, path)
	default:
		return writeJSON(results, path)
	}
}

func writeJSON(results []*types.Result, path string) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func writeTXT(results []*types.Result, path string) error {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# gosleek scan results - %s\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("# total findings: %d\n\n", len(results)))

	for _, r := range results {
		sb.WriteString(fmt.Sprintf("[%s] %s\n", strings.ToUpper(r.Severity), r.Name))
		sb.WriteString(fmt.Sprintf("  target:    %s\n", r.Target))
		sb.WriteString(fmt.Sprintf("  template:  %s\n", r.TemplateID))
		if r.Evidence != "" {
			sb.WriteString(fmt.Sprintf("  evidence:  %s\n", r.Evidence))
		}
		if len(r.Extracted) > 0 {
			for k, v := range r.Extracted {
				sb.WriteString(fmt.Sprintf("  %s: %s\n", k, v))
			}
		}
		if len(r.Tags) > 0 {
			sb.WriteString(fmt.Sprintf("  tags:      %s\n", strings.Join(r.Tags, ", ")))
		}
		for _, ref := range r.Reference {
			sb.WriteString(fmt.Sprintf("  ref:       %s\n", ref))
		}
		sb.WriteString("\n")
	}

	return os.WriteFile(path, []byte(sb.String()), 0644)
}

func writeHTML(results []*types.Result, path string) error {
	var sb strings.Builder
	sb.WriteString("<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n")
	sb.WriteString("<meta charset=\"UTF-8\">\n")
	sb.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n")
	sb.WriteString("<title>gosleek 扫描报告</title>\n")
	sb.WriteString("<style>\n")
	sb.WriteString("*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }\n")
	sb.WriteString("body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background: #0f0f23; color: #e0e0e0; line-height: 1.6; padding: 2em; }\n")
	sb.WriteString("h1 { color: #00d4ff; font-size: 1.8em; margin-bottom: 0.5em; }\n")
	sb.WriteString("h2 { color: #7fdbca; font-size: 1.2em; margin: 1.5em 0 0.5em; }\n")
	sb.WriteString("p { color: #aaa; margin-bottom: 1em; }\n")
	sb.WriteString("table { border-collapse: collapse; width: 100%; margin-top: 1em; background: #1a1a2e; border-radius: 8px; overflow: hidden; }\n")
	sb.WriteString("th { background: #16213e; color: #00d4ff; font-weight: 600; text-align: left; padding: 12px 16px; border: none; }\n")
	sb.WriteString("td { padding: 12px 16px; border-bottom: 1px solid #2a2a4a; }\n")
	sb.WriteString("tr:hover { background: #1e1e3f; }\n")
	sb.WriteString("tr:last-child td { border-bottom: none; }\n")
	sb.WriteString(".critical { color: #ff4d4d; font-weight: bold; }\n")
	sb.WriteString(".high { color: #ff8c00; font-weight: bold; }\n")
	sb.WriteString(".medium { color: #ffd700; }\n")
	sb.WriteString(".low { color: #87ceeb; }\n")
	sb.WriteString(".info { color: #aaa; }\n")
	sb.WriteString(".evidence { font-family: 'Consolas', 'Monaco', monospace; font-size: 0.85em; color: #ccc; word-break: break-all; }\n")
	sb.WriteString(".badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: 600; }\n")
	sb.WriteString(".badge-critical { background: #ff4d4d22; color: #ff4d4d; }\n")
	sb.WriteString(".badge-high { background: #ff8c0022; color: #ff8c00; }\n")
	sb.WriteString(".badge-medium { background: #ffd70022; color: #ffd700; }\n")
	sb.WriteString(".badge-low { background: #87ceeb22; color: #87ceeb; }\n")
	sb.WriteString(".badge-info { background: #aaa22; color: #aaa; }\n")
	sb.WriteString(".stats { display: flex; gap: 2em; margin: 1em 0; }\n")
	sb.WriteString(".stat { background: #1a1a2e; padding: 1em 2em; border-radius: 8px; }\n")
	sb.WriteString(".stat-value { font-size: 2em; font-weight: bold; color: #00d4ff; }\n")
	sb.WriteString(".stat-label { color: #aaa; font-size: 0.9em; }\n")
	sb.WriteString(".chart-container { background: #1a1a2e; border-radius: 8px; padding: 1em; margin: 1em 0; }\n")
	sb.WriteString(".chart-row { display: flex; gap: 2em; flex-wrap: wrap; }\n")
	sb.WriteString(".chart-col { flex: 1; min-width: 280px; max-width: 400px; }\n")
	sb.WriteString("canvas { max-width: 100%; max-height: 250px; }\n")
	sb.WriteString("</style>\n")
	// Chart.js - embedded offline by default
	sb.WriteString(fmt.Sprintf("<script>%s</script>\n", getChartJS()))
	sb.WriteString("</head>\n<body>\n")
	sb.WriteString(fmt.Sprintf("<h1>🔍 gosleek 扫描报告</h1>\n"))
	sb.WriteString(fmt.Sprintf("<p>生成时间: %s</p>\n", time.Now().Format("2006-01-02 15:04:05")))

	// 统计严重度分布
	sevCount := make(map[string]int)
	for _, r := range results {
		sevCount[r.Severity]++
	}
	// 统计目标分布
	targetCount := make(map[string]int)
	for _, r := range results {
		targetCount[r.Target]++
	}
	// 统计模板分布
	templateCount := make(map[string]int)
	for _, r := range results {
		templateCount[r.TemplateID]++
	}

	sb.WriteString("<div class=\"stats\">\n")
	sb.WriteString(fmt.Sprintf("<div class=\"stat\"><div class=\"stat-value\">%d</div><div class=\"stat-label\">总漏洞数</div></div>\n", len(results)))
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if count, ok := sevCount[sev]; ok && count > 0 {
			sb.WriteString(fmt.Sprintf("<div class=\"stat\"><div class=\"stat-value\" style=\"color: %s;\">%d</div><div class=\"stat-label\">%s</div></div>\n",
				severityColor(sev), count, strings.ToUpper(sev)))
		}
	}
	sb.WriteString("</div>\n")

	// Charts section
	if len(results) > 0 {
		sb.WriteString("<div class=\"chart-row\">\n")
		// Severity pie chart
		sb.WriteString("<div class=\"chart-col chart-container\">\n")
		sb.WriteString("<h2 style=\"margin-top:0\">严重度分布</h2>\n")
		sb.WriteString("<canvas id=\"sevChart\" width=\"300\" height=\"250\"></canvas>\n")
		sb.WriteString("<script>\n")
		sb.WriteString("new Chart(document.getElementById('sevChart'), {\n")
		sb.WriteString("  type: 'doughnut',\n")
		sb.WriteString("  data: {\n")
		sb.WriteString("    labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],\n")
		sb.WriteString("    datasets: [{\n")
		sb.WriteString("      data: [")
		for i, sev := range []string{"critical", "high", "medium", "low", "info"} {
			if i > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(fmt.Sprintf("%d", sevCount[sev]))
		}
		sb.WriteString("],\n")
		sb.WriteString("      backgroundColor: ['#ff4d4d', '#ff8c00', '#ffd700', '#87ceeb', '#aaa'],\n")
		sb.WriteString("      borderColor: '#1a1a2e', borderWidth: 2\n")
		sb.WriteString("    }]\n")
		sb.WriteString("  },\n")
		sb.WriteString("  options: { maintainAspectRatio: false, plugins: { legend: { labels: { color: '#e0e0e0' } } } }\n")
		sb.WriteString("});\n")
		sb.WriteString("</script>\n")
		sb.WriteString("</div>\n")
		// Target bar chart
		sb.WriteString("<div class=\"chart-col chart-container\">\n")
		sb.WriteString("<h2 style=\"margin-top:0\">目标漏洞分布</h2>\n")
		sb.WriteString("<canvas id=\"targetChart\" width=\"300\" height=\"250\"></canvas>\n")
		sb.WriteString("<script>\n")
		sb.WriteString("new Chart(document.getElementById('targetChart'), {\n")
		sb.WriteString("  type: 'bar',\n")
		sb.WriteString("  data: {\n")
		sb.WriteString("    labels: [")
		targetLabels := make([]string, 0, len(targetCount))
		for t := range targetCount {
			// Truncate long target URLs
			label := t
			if len(label) > 30 {
				label = label[:27] + "..."
			}
			targetLabels = append(targetLabels, "\""+strings.ReplaceAll(label, `"`, `\"`)+"\"")
		}
		sb.WriteString(strings.Join(targetLabels, ", "))
		sb.WriteString("],\n")
		sb.WriteString("    datasets: [{\n")
		sb.WriteString("      label: '漏洞数',\n")
		sb.WriteString("      data: [")
		vals := make([]string, 0, len(targetCount))
		for _, t := range targetLabels {
			target := strings.Trim(t, "\"")
			for orig, cnt := range targetCount {
				if strings.Contains(orig, target[:min(len(orig), len(target))]) {
					vals = append(vals, fmt.Sprintf("%d", cnt))
					break
				}
			}
		}
		// Rebuild with correct mapping
		vals = vals[:0]
		for _, label := range targetLabels {
			label = strings.Trim(label, "\"")
			for orig := range targetCount {
				short := orig
				if len(short) > 30 {
					short = short[:27] + "..."
				}
				if short == label {
					vals = append(vals, fmt.Sprintf("%d", targetCount[orig]))
					break
				}
			}
		}
		sb.WriteString(strings.Join(vals, ", "))
		sb.WriteString("],\n")
		sb.WriteString("      backgroundColor: '#00d4ff',\n")
		sb.WriteString("      borderColor: '#00d4ff', borderWidth: 1\n")
		sb.WriteString("    }]\n")
		sb.WriteString("  },\n")
		sb.WriteString("  options: {\n")
		sb.WriteString("    scales: {\n")
		sb.WriteString("      x: { ticks: { color: '#aaa', maxRotation: 45, minRotation: 15 }, grid: { color: '#2a2a4a' } },\n")
		sb.WriteString("      y: { ticks: { color: '#aaa' }, grid: { color: '#2a2a4a' } }\n")
		sb.WriteString("    }\n")
		sb.WriteString("  }\n")
		sb.WriteString("});\n")
		sb.WriteString("</script>\n")
		sb.WriteString("</div>\n")
		sb.WriteString("</div>\n")
	}

	sb.WriteString("<h2>漏洞详情</h2>\n")
	sb.WriteString("<table>\n<tr><th>严重度</th><th>模板 ID</th><th>名称</th><th>目标</th><th>证据</th></tr>\n")
	for _, r := range results {
		sevClass := strings.ToLower(r.Severity)
		sb.WriteString(fmt.Sprintf("<tr>\n"))
		sb.WriteString(fmt.Sprintf("<td><span class=\"badge badge-%s\">%s</span></td>\n", sevClass, strings.ToUpper(r.Severity)))
		sb.WriteString(fmt.Sprintf("<td>%s</td>\n", html.EscapeString(r.TemplateID)))
		sb.WriteString(fmt.Sprintf("<td>%s</td>\n", html.EscapeString(r.Name)))
		sb.WriteString(fmt.Sprintf("<td>%s</td>\n", html.EscapeString(r.Target)))
		ev := html.EscapeString(r.Evidence)
		if len(ev) > 200 {
			ev = ev[:200] + "…"
		}
		sb.WriteString(fmt.Sprintf("<td class=\"evidence\">%s</td>\n", ev))
		sb.WriteString("</tr>\n")
	}
	sb.WriteString("</table>\n")
	sb.WriteString("</body>\n</html>")
	return os.WriteFile(path, []byte(sb.String()), 0644)
}

func severityColor(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "#ff4d4d"
	case "high":
		return "#ff8c00"
	case "medium":
		return "#ffd700"
	case "low":
		return "#87ceeb"
	default:
		return "#aaa"
	}
}

func writeCSV(results []*types.Result, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	// Header
	w.Write([]string{"severity", "template-id", "name", "target", "evidence", "matched-at"})
	for _, r := range results {
		evidence := strings.ReplaceAll(r.Evidence, "\n", " ")
		w.Write([]string{
			r.Severity,
			r.TemplateID,
			r.Name,
			r.Target,
			evidence,
			r.MatchedAt,
		})
	}
	return nil
}

func writeMarkdown(results []*types.Result, path string) error {
	var sb strings.Builder
	sb.WriteString("# gosleek 扫描报告\n\n")
	sb.WriteString(fmt.Sprintf("**生成时间**: %s\n\n", time.Now().Format("2006-01-02 15:04:05")))

	// 统计严重度分布
	sevCount := make(map[string]int)
	for _, r := range results {
		sevCount[r.Severity]++
	}

	sb.WriteString("## 概览\n\n")
	sb.WriteString(fmt.Sprintf("| 指标 | 数量 |\n|------|------|\n",))
	sb.WriteString(fmt.Sprintf("| 总漏洞数 | %d |\n", len(results)))
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if count, ok := sevCount[sev]; ok && count > 0 {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", strings.ToUpper(sev), count))
		}
	}
	sb.WriteString("\n")

	if len(results) == 0 {
		sb.WriteString("**未发现漏洞**\n")
		return os.WriteFile(path, []byte(sb.String()), 0644)
	}

	sb.WriteString("## 漏洞详情\n\n")
	sb.WriteString("| 严重度 | 模板 ID | 名称 | 目标 | 证据 |\n")
	sb.WriteString("|--------|---------|------|------|------|\n")
	for _, r := range results {
		evidence := strings.ReplaceAll(r.Evidence, "\n", " ")
		if len(evidence) > 100 {
			evidence = evidence[:100] + "..."
		}
		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
			strings.ToUpper(r.Severity),
			r.TemplateID,
			r.Name,
			r.Target,
			evidence,
		))
	}

	return os.WriteFile(path, []byte(sb.String()), 0644)
}

// getChartJS returns the embedded Chart.js library for offline HTML reports.
func getChartJS() string {
	data, err := chartJS.ReadFile("embeds/chart.umd.min.js")
	if err != nil {
		return ""
	}
	return string(data)
}
