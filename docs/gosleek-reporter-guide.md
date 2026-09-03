# Go-Sleek 报告生成指南

> 版本：v1.6.0
> 目标读者：安全工程师、项目管理、客户汇报
> 前置知识：了解 gosleek 扫描结果结构

---

## 目录

1. [概述](#1-概述)
2. [支持的报告格式](#2-支持的报告格式)
3. [快速开始](#3-快速开始)
4. [HTML 报告详解](#4-html-报告详解)
5. [PDF 报告](#5-pdf-报告)
6. [DOCX 报告](#6-docx-报告)
7. [编程集成](#7-编程集成)
8. [报告内容结构](#8-报告内容结构)
9. [最佳实践](#9-最佳实践)
10. [常见问题](#10-常见问题)

---

## 1. 概述

gosleek 报告生成模块提供专业级别的安全测试报告，包含执行摘要、漏洞详情、修复建议等完整内容。所有格式均**零外部依赖**，仅使用 Go 标准库。

**核心价值**：
- 自动生成专业报告，无需手动整理
- 多种格式支持，适应不同场景
- 中文本地化，适合国内团队
- 包含原始证据，便于复核

---

## 2. 支持的报告格式

| 格式 | 文件扩展名 | 特点 | 适用场景 |
|------|-----------|------|----------|
| **HTML** | `.html` | 含图表、交互式导航、打印友好 | 日常查看、邮件分享 |
| **PDF** | `.pdf` | 高质量打印版（HTML→打印） | 正式报告交付 |
| **DOCX** | `.docx` | Microsoft Word 格式 | 需要编辑的报告 |
| **TXT** | `.txt` | 纯文本（PDF 基础内容） | 快速查看 |

---

## 3. 快速开始

### 3.1 基本用法

```go
import (
    "context"
    "github.com/gosleek/gosleek/internal/reporter"
    "github.com/gosleek/gosleek/pkg/types"
)

// 创建 Reporter
r := reporter.New(
    "安全测试报告",    // 标题
    "渗透测试团队",    // 作者
    "1.6.0",          // 版本
    "./reports",      // 输出目录
)

// 准备扫描信息
scanInfo := &reporter.ScanInfo{
    StartTime:   time.Now().Add(-2 * time.Hour),
    EndTime:     time.Now(),
    Targets:     []string{"http://example.com"},
    TemplateCount: 150,
    PluginCount:   12,
    Concurrency:   25,
    RateLimit:     150,
    OOBEnabled:    true,
}

// 生成 HTML 报告
ctx := context.Background()
if err := r.GenerateHTML(ctx, results, scanInfo); err != nil {
    panic(err)
}

// 生成 PDF 报告（HTML 打印版 + 纯文本）
if err := r.GeneratePDF(ctx, results, scanInfo); err != nil {
    panic(err)
}

// 生成 DOCX 报告
if err := r.GenerateDOCX(ctx, results, scanInfo); err != nil {
    panic(err)
}
```

### 3.2 一键生成所有格式

```go
reporter.PrintReport(results, scanInfo, &reporter.ReporterConfig{
    Title:   "渗透测试报告",
    Author:  "安全团队",
    Version: "1.6.0",
}, "./reports")
// 输出: reports/report-printable.html
```

---

## 4. HTML 报告详解

### 4.1 报告结构

生成的 HTML 报告包含以下章节：

```
📄 report.html
├── 标题区
│   ├── 报告标题、作者、版本、日期
│   └── 免责声明
│
├── 执行摘要
│   ├── 扫描时间范围
│   ├── 目标数量统计
│   ├── 模板/插件数量
│   └── 漏洞总览卡片
│
├── 目录导航 (TOC)
│   └── 点击跳转到各章节
│
├── 严重度统计
│   ├── Critical / High / Medium / Low / Info 数量卡片
│   └── 严重度分布饼图
│
├── 目标漏洞分布
│   └── 每个目标的命中数量柱图
│
├── 漏洞时间线
│   └── 按时间排序的漏洞发现记录
│
├── 修复建议
│   ├── Critical 修复建议
│   ├── High 修复建议
│   ├── Medium 修复建议
│   └── Low 修复建议
│
├── 详细结果表
│   └── 所有命中的完整信息（表格形式）
│
└── 附录
    ├── 原始请求/响应数据
    └── 提取的变量数据
```

### 4.2 样式特点

- **响应式设计**：适配桌面和移动端
- **打印优化**：`@media print` 样式，适合打印为 PDF
- **深色主题**：专业安全工具风格
- **无外部依赖**：所有 CSS 内联，无需网络连接

### 4.3 严重度颜色映射

| 严重度 | 颜色 |
|--------|------|
| Critical | `#dc2626`（红色） |
| High | `#f97316`（橙色） |
| Medium | `#eab308`（黄色） |
| Low | `#22c55e`（绿色） |
| Info | `#3b82f6`（蓝色） |

---

## 5. PDF 报告

### 5.1 生成方式

由于不引入外部 PDF 库，PDF 报告采用以下方式生成：

1. **HTML 报告**：浏览器可直接打印为 PDF
2. **纯文本报告**：`report.txt`，包含结构化的文本格式报告

### 5.2 浏览器打印

```bash
# 生成 HTML 报告后，在浏览器中打开并打印
go run . reporter --input results.json --format pdf --output ./reports

# 或直接使用 GeneratePDF
```

### 5.3 PDF 兼容内容

```go
// 生成可直接打印的 HTML 内容
content, err := reporter.GeneratePDFContent(results, scanInfo, &reporter.ReporterConfig{
    Title: "报告标题",
})
// content 可直接写入文件，用浏览器打开后打印为 PDF
```

---

## 6. DOCX 报告

### 6.1 生成原理

DOCX 本质是 ZIP 压缩包，包含特定的 XML 文件结构。gosleek 使用 `archive/zip` 手动构建：

```
report.docx
├── [Content_Types].xml       # 内容类型定义
├── _rels/.rels               # 关系定义
└── word/
    └── document.xml          # 文档内容
        ├── 标题
        ├── 执行摘要段落
        ├── 漏洞列表
        └── 附录
```

### 6.2 使用示例

```go
if err := r.GenerateDOCX(ctx, results, scanInfo); err != nil {
    panic(err)
}
// 输出: ./reports/report.docx
```

### 6.3 报告内容

- 标题页（标题、作者、日期）
- 执行摘要（文本格式）
- 漏洞列表（表格形式）
- 附录（原始数据）

---

## 7. 编程集成

### 7.1 与扫描引擎集成

```go
import (
    "github.com/gosleek/gosleek/internal/engine"
    "github.com/gosleek/gosleek/internal/reporter"
)

// 扫描
scanner := engine.NewScanner(cfg, 0, oobCfg, "", true)
results := scanner.Run(ctx, templates, plugins, targets)

// 生成报告
r := reporter.New("安全测试报告", "渗透团队", "1.6.0", "./reports")
scanInfo := &reporter.ScanInfo{
    StartTime:   scanStartTime,
    EndTime:     time.Now(),
    Targets:     targets,
    TemplateCount: len(templates),
    PluginCount: len(plugins),
    Concurrency: cfg.Concurrency,
    RateLimit:   cfg.RateLimit,
    Proxy:       cfg.Proxy,
    OOBEnabled:  oobCfg.Enabled,
}

r.GenerateHTML(ctx, results, scanInfo)
r.GenerateDOCX(ctx, results, scanInfo)
```

### 7.2 从文件结果生成报告

```go
// 从已有的 JSON 结果文件生成报告
results := loadResultsFromFile("results.json")

r := reporter.New("安全测试报告", "安全团队", "1.6.0", "./reports")
scanInfo := &reporter.ScanInfo{
    StartTime:   startTime,
    EndTime:     endTime,
    Targets:     targets,
    TemplateCount: 150,
    PluginCount: 12,
}
r.GenerateHTML(ctx, results, scanInfo)
```

---

## 8. 报告内容结构

### 8.1 ScanInfo 字段说明

| 字段 | 类型 | 说明 |
|------|------|------|
| `StartTime` | `time.Time` | 扫描开始时间 |
| `EndTime` | `time.Time` | 扫描结束时间 |
| `Targets` | `[]string` | 扫描目标列表 |
| `TemplateCount` | `int` | 模板数量 |
| `PluginCount` | `int` | 插件数量 |
| `Concurrency` | `int` | 并发数 |
| `RateLimit` | `int` | 限速 |
| `Proxy` | `string` | 代理地址 |
| `OOBEnabled` | `bool` | OOB 是否启用 |

### 8.2 ReporterConfig 字段说明

| 字段 | 类型 | 说明 |
|------|------|------|
| `Title` | `string` | 报告标题 |
| `Author` | `string` | 报告作者 |
| `Version` | `string` | 报告版本 |

---

## 9. 最佳实践

### 9.1 报告时机

建议在以下时机生成报告：
- 扫描完成后立即生成
- 定期批量扫描后汇总生成
- 客户交付前生成最终版

### 9.2 敏感信息处理

```go
// 生成报告前脱敏
for _, r := range results {
    if r.Extracted != nil {
        for k, v := range r.Extracted {
            if isSensitiveKey(k) {
                r.Extracted[k] = maskValue(v)
            }
        }
    }
}
```

### 9.3 报告归档

```go
// 按日期归档报告
outputDir := fmt.Sprintf("./reports/%s", time.Now().Format("2006-01-02"))
os.MkdirAll(outputDir, 0755)
r := reporter.New("报告", "团队", "1.6.0", outputDir)
```

---

## 10. 常见问题

### 10.1 报告体积过大

**原因**：报告包含所有原始请求/响应数据。

**解决**：
- 使用 `--redact` 减少证据数据量
- 对大响应设置 `max-body-size` 限制
- 仅导出关键漏洞到报告

### 10.2 PDF 打印格式错乱

**原因**：浏览器默认打印设置。

**解决**：
- 在浏览器中打开 HTML 报告
- 选择"另存为 PDF"时勾选"背景图形"
- 调整页边距为"无"

### 10.3 DOCX 中文显示乱码

**原因**：XML 编码问题。

**解决**：确保所有字符串使用 UTF-8 编码，gosleek 已内置处理。

---

*本文档基于 gosleek v1.6.0 编写*
