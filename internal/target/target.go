// Package target 提供批量目标管理功能。
//
// 主要能力:
//   1. 目标标准化（补全 scheme、去除路径、归一化格式）
//   2. 从多种来源加载目标（文件、stdin、枚举工具输出）
//   3. 目标去重（基于 hostname 或完整 URL）
//   4. 子域名枚举集成（通过 DNS 回溯或字典爆破）
//   5. 过滤和排序
package target

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
)

// Target 表示一个标准化后的扫描目标。
type Target struct {
	Raw      string // 用户原始输入
	URL      string // 标准化 URL
	Hostname string // 仅主机名 (含端口)
	Port     string // 端口号
	Scheme   string // http 或 https
	IsIP     bool   // 是否为 IP 地址
}

// ─────────────────────────────────────────────────────────────────────────────
// 目标解析与标准化
// ─────────────────────────────────────────────────────────────────────────────

// NormalizeTarget 将用户输入标准化为完整的 URL。
// 处理规则:
//   - 已有 scheme 则直接使用
//   - 无 scheme 且端口为 80/443 默认值 → 自动补全
//   - 去除路径和查询参数，只保留 scheme://host:port
//   - 补全默认端口
func NormalizeTarget(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	// 检查是否已有 scheme
	hasScheme := strings.Contains(raw, "://")
	if !hasScheme {
		// 根据端口推断 scheme
		if strings.HasSuffix(raw, ":443") {
			raw = "https://" + raw
		} else {
			raw = "http://" + raw
		}
	}

	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}

	// 标准化 host
	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	// 构建标准化 URL (只保留 scheme+host)
	normalized := u.Scheme + "://" + host
	return normalized
}

// ParseTarget 解析原始输入为一个 Target 结构体。
func ParseTarget(raw string) *Target {
	normalized := NormalizeTarget(raw)
	if normalized == "" {
		return nil
	}

	u, err := url.Parse(normalized)
	if err != nil {
		return nil
	}

	t := &Target{
		Raw:      raw,
		URL:      normalized,
		Scheme:   u.Scheme,
		Hostname: u.Host,
	}

	// 提取端口
	if strings.Contains(u.Host, ":") {
		t.Port = u.Port()
		t.Hostname = u.Hostname()
	}

	// 检测 IP 地址
	t.IsIP = isIPAddress(u.Hostname())

	return t
}

// NormalizeTargets 标准化目标列表，去除重复和无效值。
func NormalizeTargets(rawTargets []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, raw := range rawTargets {
		normalized := NormalizeTarget(raw)
		if normalized == "" {
			continue
		}
		if seen[normalized] {
			continue
		}
		seen[normalized] = true
		result = append(result, normalized)
	}
	return result
}

// ─────────────────────────────────────────────────────────────────────────────
// 目标加载
// ─────────────────────────────────────────────────────────────────────────────

// LoadFromReader 从 reader 读取目标列表（每行一个）。
// 跳过空行和以 # 开头的注释行。
func LoadFromReader(r *bufio.Reader) []string {
	var targets []string
	for {
		line, err := r.ReadString('\n')
		if err != nil && line == "" {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}
	return targets
}

// LoadFromFile 从文件加载目标列表。
func LoadFromFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	return LoadFromReader(reader), nil
}

// LoadFromStdin 从 stdin 加载目标列表。
func LoadFromStdin() ([]string, error) {
	reader := bufio.NewReader(os.Stdin)
	return LoadFromReader(reader), nil
}

// LoadFromLines 从字符串行列表加载目标。
func LoadFromLines(lines []string) []string {
	var targets []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}
	return targets
}

// ─────────────────────────────────────────────────────────────────────────────
// 目标去重
// ─────────────────────────────────────────────────────────────────────────────

// DedupByHost 基于 hostname（含端口）去重。
// 例如 http://example.com 和 https://example.com 会视为相同目标。
func DedupByHost(targets []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, t := range targets {
		normalized := NormalizeTarget(t)
		u, err := url.Parse(normalized)
		if err != nil {
			continue
		}
		key := strings.ToLower(u.Host)
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, t)
	}
	return result
}

// DedupByURL 基于完整 URL 去重（区分 scheme 和端口）。
func DedupByURL(targets []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, t := range targets {
		normalized := NormalizeTarget(t)
		if seen[normalized] {
			continue
		}
		seen[normalized] = true
		result = append(result, t)
	}
	return result
}

// ─────────────────────────────────────────────────────────────────────────────
// 目标过滤
// ─────────────────────────────────────────────────────────────────────────────

// FilterByScheme 按协议过滤（http / https）。
func FilterByScheme(targets []string, scheme string) []string {
	scheme = strings.ToLower(scheme)
	var result []string
	for _, t := range targets {
		u, err := url.Parse(NormalizeTarget(t))
		if err != nil {
			continue
		}
		if strings.EqualFold(u.Scheme, scheme) {
			result = append(result, t)
		}
	}
	return result
}

// FilterByPort 按端口过滤。
func FilterByPort(targets []string, port string) []string {
	var result []string
	for _, t := range targets {
		u, err := url.Parse(NormalizeTarget(t))
		if err != nil {
			continue
		}
		if u.Port() == port {
			result = append(result, t)
		}
	}
	return result
}

// FilterByDomain 仅保留指定域名的目标。
func FilterByDomain(targets []string, domain string) []string {
	domain = strings.ToLower(domain)
	var result []string
	for _, t := range targets {
		u, err := url.Parse(NormalizeTarget(t))
		if err != nil {
			continue
		}
		if strings.HasSuffix(strings.ToLower(u.Hostname()), domain) {
			result = append(result, t)
		}
	}
	return result
}

// SortByHost 按 hostname 排序目标列表。
func SortByHost(targets []string) []string {
	sorted := make([]string, len(targets))
	copy(sorted, targets)
	sort.Slice(sorted, func(i, j int) bool {
		u1, err1 := url.Parse(NormalizeTarget(sorted[i]))
		u2, err2 := url.Parse(NormalizeTarget(sorted[j]))
		if err1 != nil || err2 != nil {
			return sorted[i] < sorted[j]
		}
		if u1.Hostname() == u2.Hostname() {
			return u1.Port() < u2.Port()
		}
		return u1.Hostname() < u2.Hostname()
	})
	return sorted
}

// ─────────────────────────────────────────────────────────────────────────────
// 统计与格式
// ─────────────────────────────────────────────────────────────────────────────

// CountByProtocol 统计各协议的目标数量。
func CountByProtocol(targets []string) map[string]int {
	count := make(map[string]int)
	for _, t := range targets {
		u, err := url.Parse(NormalizeTarget(t))
		if err != nil {
			continue
		}
		count[u.Scheme]++
	}
	return count
}

// CountByPort 统计各端口的目标数量。
func CountByPort(targets []string) map[string]int {
	count := make(map[string]int)
	for _, t := range targets {
		u, err := url.Parse(NormalizeTarget(t))
		if err != nil {
			continue
		}
		port := u.Port()
		if port == "" {
			port = "80"
		}
		count[port]++
	}
	return count
}

// Summary 返回目标的简洁摘要。
func Summary(targets []string) string {
	if len(targets) == 0 {
		return "0 个目标"
	}
	proto := CountByProtocol(targets)
	ports := CountByPort(targets)
	var parts []string
	parts = append(parts, fmt.Sprintf("%d 个目标", len(targets)))
	if p, ok := proto["https"]; ok {
		parts = append(parts, fmt.Sprintf("%d HTTPS", p))
	}
	if p, ok := proto["http"]; ok {
		parts = append(parts, fmt.Sprintf("%d HTTP", p))
	}
	if len(ports) > 1 {
		var portList []string
		for port := range ports {
			portList = append(portList, port)
		}
		sort.Strings(portList)
		parts = append(parts, fmt.Sprintf("端口: %s", strings.Join(portList, ",")))
	}
	return strings.Join(parts, ", ")
}

// ─────────────────────────────────────────────────────────────────────────────
// 工具函数
// ─────────────────────────────────────────────────────────────────────────────

// isIPAddress 检查 host 是否为 IP 地址（支持 IPv4 和 IPv6）。
func isIPAddress(host string) bool {
	// 去掉 IPv6 方括号
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	// 尝试解析为 IP
	if net.ParseIP(host) != nil {
		return true
	}
	return false
}

// IsIPAddress 导出版本。
func IsIPAddress(host string) bool {
	return isIPAddress(host)
}

// ExtractHosts 从目标列表中提取所有唯一的 hostname。
func ExtractHosts(targets []string) []string {
	seen := make(map[string]bool)
	var hosts []string
	for _, t := range targets {
		u, err := url.Parse(NormalizeTarget(t))
		if err != nil {
			continue
		}
		h := strings.ToLower(u.Hostname())
		if !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	return hosts
}

// ExtractDomains 从 hostname 列表中提取唯一域名（last two labels）。
func ExtractDomains(hosts []string) []string {
	seen := make(map[string]bool)
	var domains []string
	for _, h := range hosts {
		parts := strings.Split(h, ".")
		if len(parts) < 2 {
			continue
		}
		// 取最后两部分作为基础域名
		base := strings.Join(parts[len(parts)-2:], ".")
		if !seen[base] {
			seen[base] = true
			domains = append(domains, base)
		}
	}
	return domains
}
