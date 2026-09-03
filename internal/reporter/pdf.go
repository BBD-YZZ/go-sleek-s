// Package reporter - PDF 报告生成器
// 由于不引入外部依赖，生成高质量的 HTML 报告（可通过浏览器打印为 PDF），
// 同时生成纯文本格式的兼容报告。
package reporter

import (
	"github.com/gosleek/gosleek/pkg/types"
)

// ReporterConfig PDF 报告配置（与 reporter.go 中的定义一致，此处仅为文档说明）。

// generatePDFContent 生成 PDF 兼容的内容（HTML 格式可打印）。
func generatePDFContent(results []*types.Result, scanInfo *ScanInfo, cfg *ReporterConfig) ([]byte, error) {
	return generateHTMLReport(results, scanInfo, cfg)
}
