// Package reporter - DOCX 报告生成器
// 使用 Go 标准库生成 DOCX 文件（ZIP 压缩包 + XML 格式）。
package reporter

import (
	"archive/zip"
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/gosleek/gosleek/pkg/types"
)

// generateDOCX 生成 DOCX 格式的增强报告。
// DOCX 本质是 ZIP 压缩包，包含特定的 XML 文件结构。
func generateDOCX(results []*types.Result, scanInfo *ScanInfo) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	// 1. [Content_Types].xml
	if err := addEntry(zw, "[Content_Types].xml", contentTypesXML()); err != nil {
		zw.Close()
		return nil, fmt.Errorf("写入 Content_Types.xml: %w", err)
	}

	// 2. _rels/.rels
	if err := addEntry(zw, "_rels/.rels", relationsXML()); err != nil {
		zw.Close()
		return nil, fmt.Errorf("写入 .rels: %w", err)
	}

	// 3. word/_rels/document.xml.rels
	if err := addEntry(zw, "word/_rels/document.xml.rels", wordRelationsXML()); err != nil {
		zw.Close()
		return nil, fmt.Errorf("写入 word/document.xml.rels: %w", err)
	}

	// 4. word/document.xml
	docContent, err := buildDocumentContent(results, scanInfo)
	if err != nil {
		zw.Close()
		return nil, fmt.Errorf("构建文档内容: %w", err)
	}
	if err := addEntry(zw, "word/document.xml", docContent); err != nil {
		zw.Close()
		return nil, fmt.Errorf("写入 document.xml: %w", err)
	}

	// 5. word/settings.xml
	if err := addEntry(zw, "word/settings.xml", settingsXML()); err != nil {
		zw.Close()
		return nil, fmt.Errorf("写入 settings.xml: %w", err)
	}

	// 6. word/styles.xml
	if err := addEntry(zw, "word/styles.xml", stylesXML()); err != nil {
		zw.Close()
		return nil, fmt.Errorf("写入 styles.xml: %w", err)
	}

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("关闭 ZIP 写入器: %w", err)
	}

	return buf.Bytes(), nil
}

// addEntry 向 ZIP 写入器添加一个条目。
func addEntry(zw *zip.Writer, name string, content string) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = w.Write([]byte(content))
	return err
}

// contentTypesXML 返回 [Content_Types].xml 内容。
func contentTypesXML() string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`
}

// relationsXML 返回 _rels/.rels 内容。
func relationsXML() string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`
}

// wordRelationsXML 返回 word/_rels/document.xml.rels 内容。
func wordRelationsXML() string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
</Relationships>`
}

// settingsXML 返回 word/settings.xml 内容。
func settingsXML() string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:zoom Percent="100"/>
</w:settings>`
}

// stylesXML 返回 word/styles.xml 内容。
func stylesXML() string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:style w:type="paragraph" w:styleId="Normal">
<w:name w:val="Normal"/>
<w:rPr><w:sz w:val="24"/><w:szCs w:val="24"/></w:rPr>
</w:style>
<w:style w:type="paragraph" w:styleId="Heading1">
<w:name w:val="heading 1"/>
<w:basedOn w:val="Normal"/>
<w:rPr><w:b/><w:sz w:val="36"/><w:szCs w:val="36"/></w:rPr>
</w:style>
<w:style w:type="paragraph" w:styleId="Heading2">
<w:name w:val="heading 2"/>
<w:basedOn w:val="Normal"/>
<w:rPr><w:b/><w:sz w:val="28"/><w:szCs w:val="28"/></w:rPr>
</w:style>
</w:styles>`
}

// buildDocumentContent 构建 word/document.xml 的内容。
func buildDocumentContent(results []*types.Result, scanInfo *ScanInfo) (string, error) {
	var b strings.Builder

	sevCount := countBySeverity(results)
	sortedResults := make([]*types.Result, len(results))
	copy(sortedResults, results)
	sortResultsBySeverity(sortedResults)

	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml">
<w:body>
`)

	// 标题
	b.WriteString("<w:p><w:pPr><w:pStyle w:val=\"Heading1\"/></w:pPr><w:r><w:rPr><w:rStyle w:val=\"Heading1\"/></w:rPr><w:t>gosleek 安全扫描报告</w:t></w:r></w:p>\n")

	// 生成时间
	b.WriteString(fmt.Sprintf("<w:p><w:r><w:t>生成时间: %s</w:t></w:r></w:p>\n", time.Now().Format("2006-01-02 15:04:05")))

	// 执行摘要
	b.WriteString("<w:p><w:pPr><w:pStyle w:val=\"Heading2\"/></w:pPr><w:r><w:rPr><w:rStyle w:val=\"Heading2\"/></w:rPr><w:t>执行摘要</w:t></w:r></w:p>\n")
	b.WriteString(fmt.Sprintf("<w:p><w:r><w:t>扫描结果总数: %d</w:t></w:r></w:p>\n", len(results)))
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if count, ok := sevCount[sev]; ok && count > 0 {
			b.WriteString(fmt.Sprintf("<w:p><w:r><w:t>  %s: %d</w:t></w:r></w:p>\n", strings.ToUpper(sev), count))
		}
	}

	// 扫描信息
	if scanInfo != nil {
		b.WriteString(fmt.Sprintf("<w:p><w:r><w:t>扫描开始: %s</w:t></w:r></w:p>\n", scanInfo.StartTime.Format("2006-01-02 15:04:05")))
		b.WriteString(fmt.Sprintf("<w:p><w:r><w:t>扫描结束: %s</w:t></w:r></w:p>\n", scanInfo.EndTime.Format("2006-01-02 15:04:05")))
		b.WriteString(fmt.Sprintf("<w:p><w:r><w:t>目标数量: %d</w:t></w:r></w:p>\n", len(scanInfo.Targets)))
	}

	// 漏洞清单
	b.WriteString("<w:p><w:pPr><w:pStyle w:val=\"Heading2\"/></w:pPr><w:r><w:rPr><w:rStyle w:val=\"Heading2\"/></w:rPr><w:t>漏洞清单</w:t></w:r></w:p>\n")

	// 漏洞详情
	for i, r := range sortedResults {
		b.WriteString(fmt.Sprintf("<w:p><w:r><w:rPr><w:b/></w:rPr><w:t>%d. %s [%s]</w:t></w:r></w:p>\n", i+1, escapeXML(r.Name), strings.ToUpper(r.Severity)))
		b.WriteString(fmt.Sprintf("<w:p><w:r><w:t>  模板ID: %s</w:t></w:r></w:p>\n", escapeXML(r.TemplateID)))
		b.WriteString(fmt.Sprintf("<w:p><w:r><w:t>  目标:   %s</w:t></w:r></w:p>\n", escapeXML(r.Target)))
		if r.Evidence != "" {
			b.WriteString(fmt.Sprintf("<w:p><w:r><w:t>  证据:   %s</w:t></w:r></w:p>\n", escapeXML(truncate(r.Evidence, 200))))
		}
	}

	b.WriteString("\n</w:body>\n</w:document>")
	return b.String(), nil
}

// escapeXML 转义 XML 中的特殊字符。
func escapeXML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	return s
}
