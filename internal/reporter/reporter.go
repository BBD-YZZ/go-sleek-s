// Package reporter 提供增强安全报告生成功能，支持 HTML、PDF 和 DOCX 格式。
package reporter

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gosleek/gosleek/pkg/types"
)

// Reporter 生成综合安全报告。
type Reporter struct {
	title     string
	author    string
	version   string
	outputDir string
}

// Option 配置 Reporter 的选项函数。
type Option func(*Reporter)

// New 创建一个新的 Reporter 实例。
func New(title, author, version, outputDir string) *Reporter {
	return &Reporter{
		title:     title,
		author:    author,
		version:   version,
		outputDir: outputDir,
	}
}

// WithTitle 设置报告标题选项。
func WithTitle(title string) Option {
	return func(r *Reporter) {
		r.title = title
	}
}

// WithAuthor 设置报告作者选项。
func WithAuthor(author string) Option {
	return func(r *Reporter) {
		r.author = author
	}
}

// WithVersion 设置报告版本选项。
func WithVersion(version string) Option {
	return func(r *Reporter) {
		r.version = version
	}
}

// WithOutputDir 设置输出目录选项。
func WithOutputDir(dir string) Option {
	return func(r *Reporter) {
		r.outputDir = dir
	}
}

// ScanInfo 保存扫描运行的元数据。
type ScanInfo struct {
	StartTime     time.Time
	EndTime       time.Time
	Targets       []string
	TemplateCount int
	PluginCount   int
	Concurrency   int
	RateLimit     int
	Proxy         string
	OOBEnabled    bool
}

// ReporterConfig 报告配置。
type ReporterConfig struct {
	Title   string
	Author  string
	Version string
}

// GeneratePDF 创建 PDF 报告。
// 由于不引入外部依赖，实际生成高质量的 HTML 报告（可通过浏览器打印为 PDF），
// 同时生成纯文本格式的 PDF 兼容报告。
func (r *Reporter) GeneratePDF(ctx context.Context, results []*types.Result, scanInfo *ScanInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	// 生成 HTML 格式报告（可通过浏览器打印为 PDF）
	if err := r.GenerateHTML(ctx, results, scanInfo); err != nil {
		return err
	}

	// 生成纯文本格式报告（可作为 PDF 基础内容）
	txtPath := filepath.Join(r.outputDir, "report.txt")
	return generateTextReport(results, scanInfo, txtPath)
}

// GenerateHTML 创建增强 HTML 报告。
func (r *Reporter) GenerateHTML(ctx context.Context, results []*types.Result, scanInfo *ScanInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	htmlPath := filepath.Join(r.outputDir, "report.html")
	content, err := generateHTMLReport(results, scanInfo, &ReporterConfig{
		Title:   r.title,
		Author:  r.author,
		Version: r.version,
	})
	if err != nil {
		return err
	}
	return os.WriteFile(htmlPath, content, 0644)
}

// GenerateDOCX 创建 DOCX 报告。
// DOCX 本质是 ZIP 压缩包，包含特定的 XML 文件结构。
func (r *Reporter) GenerateDOCX(ctx context.Context, results []*types.Result, scanInfo *ScanInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	docxPath := filepath.Join(r.outputDir, "report.docx")
	content, err := generateDOCX(results, scanInfo)
	if err != nil {
		return err
	}
	return os.WriteFile(docxPath, content, 0644)
}

// GeneratePDFContent 生成 PDF 兼容的内容（HTML 格式可打印）。
func GeneratePDFContent(results []*types.Result, scanInfo *ScanInfo, cfg *ReporterConfig) ([]byte, error) {
	return generateHTMLReport(results, scanInfo, cfg)
}

// PrintReport 生成适合打印的报告（HTML 格式，可打印为 PDF）。
func PrintReport(results []*types.Result, scanInfo *ScanInfo, cfg *ReporterConfig, outputDir string) error {
	htmlPath := filepath.Join(outputDir, "report-printable.html")
	content, err := generatePrintableHTML(results, scanInfo, cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(htmlPath, content, 0644)
}

// generateTextReport 生成纯文本格式报告（可作为 PDF 基础）。
func generateTextReport(results []*types.Result, scanInfo *ScanInfo, path string) error {
	var sb strings.Builder
	sb.WriteString("============================================================\n")
	sb.WriteString("              gosleek 安全扫描报告 (文本格式)\n")
	sb.WriteString("============================================================\n\n")

	sb.WriteString("报告信息\n")
	sb.WriteString("------------------------------------------------------------\n")
	sb.WriteString(fmt.Sprintf("生成时间: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	if scanInfo != nil {
		sb.WriteString(fmt.Sprintf("扫描开始: %s\n", scanInfo.StartTime.Format("2006-01-02 15:04:05")))
		sb.WriteString(fmt.Sprintf("扫描结束: %s\n", scanInfo.EndTime.Format("2006-01-02 15:04:05")))
		sb.WriteString(fmt.Sprintf("目标数量: %d\n", len(scanInfo.Targets)))
	}
	sb.WriteString("\n")

	// 统计摘要
	sevCount := countBySeverity(results)
	sb.WriteString("严重度统计\n")
	sb.WriteString("------------------------------------------------------------\n")
	sb.WriteString(fmt.Sprintf("总计: %d\n", len(results)))
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if count, ok := sevCount[sev]; ok && count > 0 {
			sb.WriteString(fmt.Sprintf("  %s: %d\n", strings.ToUpper(sev), count))
		}
	}
	sb.WriteString("\n")

	// 漏洞详情
	sb.WriteString("漏洞详情\n")
	sb.WriteString("------------------------------------------------------------\n")
	for i, r := range results {
		sb.WriteString(fmt.Sprintf("[%d] %s\n", i+1, r.Name))
		sb.WriteString(fmt.Sprintf("  严重度: %s\n", strings.ToUpper(r.Severity)))
		sb.WriteString(fmt.Sprintf("  模板ID: %s\n", r.TemplateID))
		sb.WriteString(fmt.Sprintf("  目标:   %s\n", r.Target))
		if r.Evidence != "" {
			sb.WriteString(fmt.Sprintf("  证据:   %s\n", r.Evidence))
		}
		sb.WriteString("\n")
	}

	return os.WriteFile(path, []byte(sb.String()), 0644)
}

// countBySeverity 统计各严重度数量。
func countBySeverity(results []*types.Result) map[string]int {
	counts := make(map[string]int)
	for _, r := range results {
		counts[r.Severity]++
	}
	return counts
}

// countByTarget 统计各目标的漏洞数量。
func countByTarget(results []*types.Result) map[string]int {
	counts := make(map[string]int)
	for _, r := range results {
		counts[r.Target]++
	}
	return counts
}

// countByTemplate 统计各模板的命中数量。
func countByTemplate(results []*types.Result) map[string]int {
	counts := make(map[string]int)
	for _, r := range results {
		counts[r.TemplateID]++
	}
	return counts
}

// severityRank 返回严重度的排序权重（越高越严重）。
func severityRank(sev string) int {
	switch sev {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

// sortResultsBySeverity 按严重度降序排序结果。
func sortResultsBySeverity(results []*types.Result) {
	sort.Slice(results, func(i, j int) bool {
		return severityRank(results[i].Severity) > severityRank(results[j].Severity)
	})
}

// severityColor 返回严重度对应的颜色。
func severityColor(sev string) string {
	switch sev {
	case "critical":
		return "#ff4d4d"
	case "high":
		return "#ff8c00"
	case "medium":
		return "#ffd700"
	case "low":
		return "#87ceeb"
	case "info":
		return "#aaa"
	default:
		return "#888"
	}
}

// truncate 截断字符串，超长部分用省略号代替。
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// getRemediationForSeverity 返回对应严重度的修复建议。
func getRemediationForSeverity(sev string) string {
	switch sev {
	case "critical":
		return "高危漏洞需要立即修复。建议优先处理，进行代码审计和安全测试，修复后重新扫描确认。"
	case "high":
		return "高优先级漏洞建议尽快修复。请评估影响范围，制定修复计划，并在下一个版本中优先处理。"
	case "medium":
		return "中等风险漏洞建议在合适时机修复。请评估业务影响，安排修复计划。"
	case "low":
		return "低风险漏洞可纳入常规修复流程。建议在后续迭代中逐步修复。"
	case "info":
		return "信息类发现供参考。建议评估是否需要对配置或代码进行优化。"
	default:
		return "请根据具体漏洞类型进行修复。"
	}
}
