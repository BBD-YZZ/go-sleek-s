package reporter

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gosleek/gosleek/pkg/types"
)

// makeTestResults 创建测试用的结果数据。
func makeTestResults() []*types.Result {
	return []*types.Result{
		{
			TemplateID:  "test-001",
			Name:        "SQL注入漏洞",
			Severity:    "critical",
			Description: "检测到SQL注入漏洞",
			Target:      "http://example.com/api",
			MatchedAt:   "POST /api/login",
			Tags:        []string{"sqli", "owasp"},
			Reference:   []string{"https://cwe.mitre.org/data/definitions/89.html"},
			Timestamp:   time.Now().Add(-2 * time.Hour),
			Evidence:    "error: near \"SELECT\": syntax error",
			Extracted:   map[string]string{"user": "admin"},
			RawRequest:  "POST /api/login HTTP/1.1\r\nHost: example.com\r\n\r\n",
			RawResponse: "HTTP/1.1 200 OK\r\n\r\nerror: near \"SELECT\"",
		},
		{
			TemplateID:  "test-002",
			Name:        "XSS反射型",
			Severity:    "high",
			Description: "检测到反射型XSS漏洞",
			Target:      "http://example.com/search",
			MatchedAt:   "GET /search?q=<script>alert(1)</script>",
			Tags:        []string{"xss", "owasp"},
			Timestamp:   time.Now().Add(-1 * time.Hour),
			Evidence:    "<script>alert(1)</script>",
		},
		{
			TemplateID:  "test-003",
			Name:        "信息泄露",
			Severity:    "medium",
			Description: "检测到敏感信息泄露",
			Target:      "http://example.com/.env",
			MatchedAt:   "GET /.env",
			Tags:        []string{"info-leak"},
			Timestamp:   time.Now().Add(-30 * time.Minute),
			Evidence:    "DB_PASSWORD=secret123",
		},
		{
			TemplateID:  "test-004",
			Name:        "CORS配置错误",
			Severity:    "low",
			Description: "CORS配置不当",
			Target:      "http://example.com/api",
			MatchedAt:   "OPTIONS /api",
			Timestamp:   time.Now().Add(-15 * time.Minute),
			Evidence:    "Access-Control-Allow-Origin: *",
		},
		{
			TemplateID:  "test-005",
			Name:        "版本信息暴露",
			Severity:    "info",
			Description: "服务器版本信息暴露",
			Target:      "http://example.com",
			MatchedAt:   "GET /",
			Timestamp:   time.Now(),
			Evidence:    "Server: Apache/2.4.41",
		},
	}
}

// makeTestScanInfo 创建测试用的扫描信息。
func makeTestScanInfo() *ScanInfo {
	return &ScanInfo{
		StartTime:     time.Now().Add(-3 * time.Hour),
		EndTime:       time.Now(),
		Targets:       []string{"http://example.com", "http://test.com"},
		TemplateCount: 5,
		PluginCount:   3,
		Concurrency:   10,
		RateLimit:     0,
		Proxy:         "",
		OOBEnabled:    false,
	}
}

// TestNewReporter 测试 Reporter 创建。
func TestNewReporter(t *testing.T) {
	r := New("测试报告", "测试作者", "1.0.0", "/tmp/reports")
	if r == nil {
		t.Fatal("Reporter 创建失败")
	}
	if r.title != "测试报告" {
		t.Errorf("title 不匹配: 期望 %q, 得到 %q", "测试报告", r.title)
	}
	if r.author != "测试作者" {
		t.Errorf("author 不匹配: 期望 %q, 得到 %q", "测试作者", r.author)
	}
	if r.version != "1.0.0" {
		t.Errorf("version 不匹配: 期望 %q, 得到 %q", "1.0.0", r.version)
	}
	if r.outputDir != "/tmp/reports" {
		t.Errorf("outputDir 不匹配: 期望 %q, 得到 %q", "/tmp/reports", r.outputDir)
	}
}

// TestReporterOptions 测试 Reporter 选项函数。
func TestReporterOptions(t *testing.T) {
	// 测试各个选项
	r2 := New("标题", "作者", "版本", "/tmp/reports")
	opts := []Option{
		WithTitle("新标题"),
		WithAuthor("新作者"),
		WithVersion("新版本"),
		WithOutputDir("/new/path"),
	}
	for _, opt := range opts {
		opt(r2)
	}

	if r2.title != "新标题" {
		t.Errorf("title 选项失败: 期望 %q, 得到 %q", "新标题", r2.title)
	}
	if r2.author != "新作者" {
		t.Errorf("author 选项失败: 期望 %q, 得到 %q", "新作者", r2.author)
	}
	if r2.version != "新版本" {
		t.Errorf("version 选项失败: 期望 %q, 得到 %q", "新版本", r2.version)
	}
	if r2.outputDir != "/new/path" {
		t.Errorf("outputDir 选项失败: 期望 %q, 得到 %q", "/new/path", r2.outputDir)
	}
}

// TestGenerateHTML 测试 HTML 报告生成。
func TestGenerateHTML(t *testing.T) {
	tmpDir := t.TempDir()
	r := New("安全扫描报告", "gosleek", "1.0.0", tmpDir)

	results := makeTestResults()
	scanInfo := makeTestScanInfo()

	ctx := context.Background()
	if err := r.GenerateHTML(ctx, results, scanInfo); err != nil {
		t.Fatalf("GenerateHTML 失败: %v", err)
	}

	htmlPath := filepath.Join(tmpDir, "report.html")
	content, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("读取 HTML 文件失败: %v", err)
	}

	htmlStr := string(content)

	// 验证关键元素
	checks := []string{
		"<!DOCTYPE html>",
		"安全扫描报告",
		"执行摘要",
		"漏洞详情",
		"SQL注入漏洞",
		"XSS反射型",
		"信息泄露",
		"CORS配置错误",
		"版本信息暴露",
		"critical",
		"high",
		"medium",
		"low",
		"info",
		"修复建议",
		"漏洞时间线",
		"目录",
	}

	for _, check := range checks {
		if !strings.Contains(htmlStr, check) {
			t.Errorf("HTML 报告缺少关键元素: %q", check)
		}
	}

	// 验证统计正确性
	if !strings.Contains(htmlStr, "5") {
		t.Error("HTML 报告中应包含统计数字 5")
	}
}

// TestGenerateHTML_EmptyResults 测试空结果的 HTML 报告生成。
func TestGenerateHTML_EmptyResults(t *testing.T) {
	tmpDir := t.TempDir()
	r := New("空报告", "测试", "1.0.0", tmpDir)

	ctx := context.Background()
	if err := r.GenerateHTML(ctx, []*types.Result{}, makeTestScanInfo()); err != nil {
		t.Fatalf("GenerateHTML 失败: %v", err)
	}

	htmlPath := filepath.Join(tmpDir, "report.html")
	content, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("读取 HTML 文件失败: %v", err)
	}

	if !strings.Contains(string(content), "总漏洞数") {
		t.Error("HTML 报告应包含总漏洞数字段")
	}
}

// TestGeneratePDF 测试 PDF 报告生成。
func TestGeneratePDF(t *testing.T) {
	tmpDir := t.TempDir()
	r := New("PDF报告", "测试", "1.0.0", tmpDir)

	results := makeTestResults()
	scanInfo := makeTestScanInfo()

	ctx := context.Background()
	if err := r.GeneratePDF(ctx, results, scanInfo); err != nil {
		t.Fatalf("GeneratePDF 失败: %v", err)
	}

	// 验证 HTML 报告已生成
	htmlPath := filepath.Join(tmpDir, "report.html")
	if _, err := os.Stat(htmlPath); os.IsNotExist(err) {
		t.Error("PDF 生成后应创建 HTML 报告")
	}

	// 验证文本报告已生成
	txtPath := filepath.Join(tmpDir, "report.txt")
	if _, err := os.Stat(txtPath); os.IsNotExist(err) {
		t.Error("PDF 生成后应创建文本报告")
	} else {
		content, _ := os.ReadFile(txtPath)
		if !strings.Contains(string(content), "gosleek") {
			t.Error("文本报告内容不正确")
		}
	}
}

// TestGenerateDOCX 测试 DOCX 报告生成。
func TestGenerateDOCX(t *testing.T) {
	tmpDir := t.TempDir()
	r := New("DOCX报告", "测试", "1.0.0", tmpDir)

	results := makeTestResults()
	scanInfo := makeTestScanInfo()

	ctx := context.Background()
	if err := r.GenerateDOCX(ctx, results, scanInfo); err != nil {
		t.Fatalf("GenerateDOCX 失败: %v", err)
	}

	docxPath := filepath.Join(tmpDir, "report.docx")
	if _, err := os.Stat(docxPath); os.IsNotExist(err) {
		t.Error("DOCX 文件未生成")
		return
	}

	// 验证文件内容
	content, err := os.ReadFile(docxPath)
	if err != nil {
		t.Fatalf("读取 DOCX 文件失败: %v", err)
	}

	// DOCX 是 ZIP 格式，开头应为 PK
	if len(content) < 2 || content[0] != 'P' || content[1] != 'K' {
		t.Error("DOCX 文件格式不正确，应为 ZIP 格式")
	}
}

// TestCountBySeverity 测试严重度统计。
func TestCountBySeverity(t *testing.T) {
	results := makeTestResults()
	counts := countBySeverity(results)

	if counts["critical"] != 1 {
		t.Errorf("critical 数量不正确: 期望 1, 得到 %d", counts["critical"])
	}
	if counts["high"] != 1 {
		t.Errorf("high 数量不正确: 期望 1, 得到 %d", counts["high"])
	}
	if counts["medium"] != 1 {
		t.Errorf("medium 数量不正确: 期望 1, 得到 %d", counts["medium"])
	}
	if counts["low"] != 1 {
		t.Errorf("low 数量不正确: 期望 1, 得到 %d", counts["low"])
	}
	if counts["info"] != 1 {
		t.Errorf("info 数量不正确: 期望 1, 得到 %d", counts["info"])
	}
}

// TestSeverityRank 测试严重度排序权重。
func TestSeverityRank(t *testing.T) {
	if severityRank("critical") != 5 {
		t.Error("critical 权重应为 5")
	}
	if severityRank("high") != 4 {
		t.Error("high 权重应为 4")
	}
	if severityRank("medium") != 3 {
		t.Error("medium 权重应为 3")
	}
	if severityRank("low") != 2 {
		t.Error("low 权重应为 2")
	}
	if severityRank("info") != 1 {
		t.Error("info 权重应为 1")
	}
	if severityRank("unknown") != 0 {
		t.Error("未知严重度权重应为 0")
	}
}

// TestSortResultsBySeverity 测试按严重度排序。
func TestSortResultsBySeverity(t *testing.T) {
	results := []*types.Result{
		{Severity: "info"},
		{Severity: "critical"},
		{Severity: "low"},
		{Severity: "high"},
		{Severity: "medium"},
	}
	sortResultsBySeverity(results)

	expected := []string{"critical", "high", "medium", "low", "info"}
	for i, r := range results {
		if r.Severity != expected[i] {
			t.Errorf("排序错误: 期望 %q, 得到 %q (位置 %d)", expected[i], r.Severity, i)
		}
	}
}

// TestSeverityColor 测试严重度颜色。
func TestSeverityColor(t *testing.T) {
	if severityColor("critical") != "#ff4d4d" {
		t.Error("critical 颜色错误")
	}
	if severityColor("high") != "#ff8c00" {
		t.Error("high 颜色错误")
	}
	if severityColor("medium") != "#ffd700" {
		t.Error("medium 颜色错误")
	}
	if severityColor("low") != "#87ceeb" {
		t.Error("low 颜色错误")
	}
	if severityColor("info") != "#aaa" {
		t.Error("info 颜色错误")
	}
}

// TestTruncate 测试字符串截断。
func TestTruncate(t *testing.T) {
	if truncate("hello", 10) != "hello" {
		t.Error("短字符串不应截断")
	}
	if len(truncate("hello world", 8)) != 8 {
		t.Error("长字符串应被截断")
	}
	if !strings.HasSuffix(truncate("hello world", 8), "...") {
		t.Error("截断后应包含省略号")
	}
}

// TestGetRemediationForSeverity 测试修复建议。
func TestGetRemediationForSeverity(t *testing.T) {
	if len(getRemediationForSeverity("critical")) == 0 {
		t.Error("critical 修复建议不应为空")
	}
	if len(getRemediationForSeverity("high")) == 0 {
		t.Error("high 修复建议不应为空")
	}
	if len(getRemediationForSeverity("medium")) == 0 {
		t.Error("medium 修复建议不应为空")
	}
	if len(getRemediationForSeverity("low")) == 0 {
		t.Error("low 修复建议不应为空")
	}
	if len(getRemediationForSeverity("info")) == 0 {
		t.Error("info 修复建议不应为空")
	}
}

// TestGenerateHTML_ContextCancel 测试上下文取消。
func TestGenerateHTML_ContextCancel(t *testing.T) {
	tmpDir := t.TempDir()
	r := New("测试", "测试", "1.0.0", tmpDir)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立即取消

	err := r.GenerateHTML(ctx, makeTestResults(), makeTestScanInfo())
	if err == nil {
		t.Error("取消上下文时应返回错误")
	}
}

// TestGeneratePDF_ContextCancel 测试上下文取消。
func TestGeneratePDF_ContextCancel(t *testing.T) {
	tmpDir := t.TempDir()
	r := New("测试", "测试", "1.0.0", tmpDir)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := r.GeneratePDF(ctx, makeTestResults(), makeTestScanInfo())
	if err == nil {
		t.Error("取消上下文时应返回错误")
	}
}

// TestGenerateDOCX_ContextCancel 测试上下文取消。
func TestGenerateDOCX_ContextCancel(t *testing.T) {
	tmpDir := t.TempDir()
	r := New("测试", "测试", "1.0.0", tmpDir)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := r.GenerateDOCX(ctx, makeTestResults(), makeTestScanInfo())
	if err == nil {
		t.Error("取消上下文时应返回错误")
	}
}

// TestGenerateDOCX_EmptyResults 测试空结果的 DOCX 生成。
func TestGenerateDOCX_EmptyResults(t *testing.T) {
	tmpDir := t.TempDir()
	r := New("空报告", "测试", "1.0.0", tmpDir)

	ctx := context.Background()
	if err := r.GenerateDOCX(ctx, []*types.Result{}, makeTestScanInfo()); err != nil {
		t.Fatalf("GenerateDOCX 失败: %v", err)
	}

	docxPath := filepath.Join(tmpDir, "report.docx")
	content, err := os.ReadFile(docxPath)
	if err != nil {
		t.Fatalf("读取 DOCX 文件失败: %v", err)
	}

	// 验证 DOCX 格式正确
	if len(content) < 2 || content[0] != 'P' || content[1] != 'K' {
		t.Error("DOCX 文件格式不正确")
	}
}

// TestPrintReport 测试打印报告生成。
func TestPrintReport(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &ReporterConfig{
		Title:   "打印报告",
		Author:  "测试",
		Version: "1.0.0",
	}

	results := makeTestResults()
	scanInfo := makeTestScanInfo()

	if err := PrintReport(results, scanInfo, cfg, tmpDir); err != nil {
		t.Fatalf("PrintReport 失败: %v", err)
	}

	htmlPath := filepath.Join(tmpDir, "report-printable.html")
	content, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("读取打印报告失败: %v", err)
	}

	htmlStr := string(content)
	if !strings.Contains(htmlStr, "打印报告") {
		t.Error("打印报告缺少标题")
	}
	if !strings.Contains(htmlStr, "漏洞清单") {
		t.Error("打印报告缺少漏洞清单")
	}
}

// TestGeneratePDFContent 测试 PDF 内容生成。
func TestGeneratePDFContent(t *testing.T) {
	results := makeTestResults()
	scanInfo := makeTestScanInfo()
	cfg := &ReporterConfig{
		Title:   "PDF测试",
		Author:  "测试",
		Version: "1.0.0",
	}

	content, err := generatePDFContent(results, scanInfo, cfg)
	if err != nil {
		t.Fatalf("generatePDFContent 失败: %v", err)
	}

	htmlStr := string(content)
	if !strings.Contains(htmlStr, "PDF测试") {
		t.Error("PDF 内容缺少标题")
	}
	if !strings.Contains(htmlStr, "执行摘要") {
		t.Error("PDF 内容缺少执行摘要")
	}
}

// BenchmarkGenerateHTML 性能基准测试。
func BenchmarkGenerateHTML(b *testing.B) {
	tmpDir := b.TempDir()
	r := New("基准测试", "gosleek", "1.0.0", tmpDir)
	results := makeTestResults()
	scanInfo := makeTestScanInfo()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.GenerateHTML(context.Background(), results, scanInfo)
	}
}

// BenchmarkGenerateDOCX 性能基准测试。
func BenchmarkGenerateDOCX(b *testing.B) {
	tmpDir := b.TempDir()
	r := New("基准测试", "gosleek", "1.0.0", tmpDir)
	results := makeTestResults()
	scanInfo := makeTestScanInfo()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.GenerateDOCX(context.Background(), results, scanInfo)
	}
}
