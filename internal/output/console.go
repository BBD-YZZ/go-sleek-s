package output

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gosleek/gosleek/internal/display"
	"github.com/gosleek/gosleek/internal/replay"
	"github.com/gosleek/gosleek/pkg/types"
	"github.com/pterm/pterm"
)

// ──────────────────────────────────────────────────────────────────────────
// Console unified output design (redesigned 2026-08-07)
//
// Verbosity levels
//   -1 silent  : 仅输出命中的结果卡片
//    0 default : banner / 免责声明 / 扫描配置面板 / 模板加载 / 扫描起止 / 结果卡片
//    1 -v      : INFO 行（任务级进度、请求/响应摘要、匹配结果、跳过原因）
//    2 -vv     : DEBUG 行（每个请求的 raw dump / 每个响应的完整 body / matcher 详情）
//
// 所有输出都通过统一格式:
//
//	[2026-08-07 15:04:05.000]  [TAG  ]  消息文本
//	    ↑                        ↑
//	    带年月日的时间戳            统一 5 字符宽的彩色标签
//
// 标签宽度固定为 5 字符，确保整屏整齐；标题框使用 CJK-aware 的 displayWidth 计算边框
// ──────────────────────────────────────────────────────────────────────────

// tagColors 统一每个 tag 的颜色, 保证层次分明
// 所有 tag 统一使用 2 个中文字符, 保证字数完全一致
var tagColors = map[string]func(a ...interface{}) string{
	"信息": pterm.LightCyan,
	"详细": pterm.LightBlue,
	"调试": pterm.Gray,
	"警告": pterm.Yellow,
	"错误": pterm.Red,
	"成功": pterm.Green,
	"扫描": pterm.LightMagenta,
	"进度": pterm.Cyan,
	"请求": pterm.LightWhite,
	"响应": pterm.LightGreen,
	"匹配": pterm.LightYellow,
	"跳过": pterm.Gray,
	"流程": pterm.LightBlue,
	"外带": pterm.Magenta,
	"指纹": pterm.LightGreen,
	"限速": pterm.Yellow,
}

func tagColor(tag string) func(a ...interface{}) string {
	if c, ok := tagColors[tag]; ok {
		return c
	}
	return pterm.White
}

// ScanConfigInfo holds info for the pre-scan config panel.
type ScanConfigInfo struct {
	Targets        int
	Templates      int
	Plugins        int
	Concurrency    int
	RateLimit      int
	Timeout        int
	MaxRetries     int
	RetryBackoff   string
	MaxRedirects   int
	FollowRedirect bool
	AllowExternal  bool
	Insecure       bool // true = -k / 跳过 TLS 校验
	MaxBodySize    int64
	OOBEnabled     bool
	OOBValid       bool // 是否正确配置
	OOBDomain      string
	OOBProvider    string // ceye / dnslog / callbackred
	Proxy          string
	OutputFile     string
	OutputFormat   string
	AIEnabled      bool
	AIModel        string
	LogFile        string
}

// Console handles terminal output with 3 verbosity levels.
type Console struct {
	verbose   int
	results   []*types.Result
	startedAt time.Time
	mu        sync.Mutex
	lastPct   int64
	// counters for pretty stats
	requests int64
	matched  int64
	failed   int64
	// redact 控制是否脱敏输出（遮蔽证据中的敏感信息）
	redact bool
}

// NewConsole creates a console output handler.
func NewConsole(verbose int) *Console {
	return &Console{
		verbose:   verbose,
		startedAt: time.Now(),
	}
}

// SetMinLevel sets the minimum verbosity level for console output.
// Used by logutil to apply config.yaml log-level when no CLI flags are set.
func (c *Console) SetMinLevel(level int) {
	c.verbose = max(c.verbose, level)
}

// SetRedact enables/disables output redaction.
func (c *Console) SetRedact(v bool) { c.redact = v }

// redactSensitive replaces sensitive patterns in text with masked values.
var sensitivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(api[_-]?key|access[_-]?token|secret|password|auth[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9+/=_\-]{8,})["']?`),
	regexp.MustCompile(`(?i)(Authorization)\s*:\s*Bearer\s+([a-zA-Z0-9._\-]+)`),
	regexp.MustCompile(`(?i)(Bearer\s+)([a-zA-Z0-9._\-]{20,})`),
	regexp.MustCompile(`(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9/+=]{40})["']?`),
	regexp.MustCompile(`(?i)(x-api-key)\s*[:=]\s*["']?([a-zA-Z0-9._\-]{10,})["']?`),
}

func redactText(s string) string {
	for _, re := range sensitivePatterns {
		s = re.ReplaceAllStringFunc(s, func(match string) string {
			// Preserve the key part, mask the value
			if idx := strings.IndexAny(match, ":="); idx >= 0 {
				keyPart := match[:idx+1]
				return keyPart + "***REDACTED***"
			}
			return match[:len(match)-8] + "***REDACTED***"
		})
	}
	return s
}

// RedactEvidence applies redaction to evidence strings.
// Exported so cmd layer can use it when -redact is enabled.
func RedactEvidence(s string) string {
	return redactText(s)
}

// visible returns whether the configured verbosity meets the given minimum.
func (c *Console) visible(min int) bool {
	if c.verbose < 0 {
		return false
	}
	return c.verbose >= min
}

// ──────────────────────────────────────────────────────────────────────────
// Prefix line — the single entry for every styled line
// ──────────────────────────────────────────────────────────────────────────

// contIndent is the number of spaces to indent continuation lines so they
// align with the message column after "[timestamp]  [标签]  ".
// timestamp = "[2006-01-02 15:04:05.000]" = 24 chars, "  " = 2, "[标签]" = 6 display cols, "  " = 2 → 34
const contIndent = "                                    "

// pLine prints a single "[timestamp]  [标签]  message" line.
// All tags are 2 Chinese characters (4 display columns), no padding needed.
// No leading spaces — timestamp is left-aligned at column 0.
func (c *Console) pLine(tag string, levelMin int, format string, args ...interface{}) {
	if !c.visible(levelMin) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	color := tagColor(tag)
	tagFmt := color("[" + tag + "]")
	msg := fmt.Sprintf(format, args...)
	ts := pterm.Gray(timeStampMs())
	lines := strings.Split(msg, "\n")
	if len(lines) == 1 {
		pterm.Printf("%s %s %s\n", ts, tagFmt, lines[0])
		return
	}
	for i, l := range lines {
		if i == 0 {
			pterm.Printf("%s %s %s\n", ts, tagFmt, l)
		} else {
			pterm.Printf("%s %s\n", contIndent, l)
		}
	}
}

// PLine is the exported version of pLine, callable from logutil.
func (c *Console) PLine(tag string, levelMin int, format string, args ...interface{}) {
	c.pLine(tag, levelMin, format, args...)
}

// ──────────────────────────────────────────────────────────────────────────
// Public API — banner & frames
// ──────────────────────────────────────────────────────────────────────────

// PrintBanner prints the ASCII banner. Always shown unless silent.
func (c *Console) PrintBanner(version string) {
	if !c.visible(0) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	lines := []string{
		`
		
  ██████  ▄▄▄       ███▄    █ ▄▄▄█████▓▓█████  ███▄ ▄███▓ ██▓███   ██▓     ▄▄▄      ▄▄▄█████▓▓█████   ██████ 
▒██    ▒ ▒████▄     ██ ▀█   █ ▓  ██▒ ▓▒▓█   ▀ ▓██▒▀█▀ ██▒▓██░  ██▒▓██▒    ▒████▄    ▓  ██▒ ▓▒▓█   ▀ ▒██    ▒ 
░ ▓██▄   ▒██  ▀█▄  ▓██  ▀█ ██▒▒ ▓██░ ▒░▒███   ▓██    ▓██░▓██░ ██▓▒▒██░    ▒██  ▀█▄  ▒ ▓██░ ▒░▒███   ░ ▓██▄   
  ▒   ██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒░ ▓██▓ ░ ▒▓█  ▄ ▒██    ▒██ ▒██▄█▓▒ ▒▒██░    ░██▄▄▄▄██ ░ ▓██▓ ░ ▒▓█  ▄   ▒   ██▒
▒██████▒▒ ▓█   ▓██▒▒██░   ▓██░  ▒██▒ ░ ░▒████▒▒██▒   ░██▒▒██▒ ░  ░░██████▒ ▓█   ▓██▒  ▒██▒ ░ ░▒████▒▒██████▒▒
▒ ▒▓▒ ▒ ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒   ▒ ░░   ░░ ▒░ ░░ ▒░   ░  ░▒▓▒░ ░  ░░ ▒░▓  ░ ▒▒   ▓▒█░  ▒ ░░   ░░ ▒░ ░▒ ▒▓▒ ▒ ░
░ ░▒  ░ ░  ▒   ▒▒ ░░ ░░   ░ ▒░    ░     ░ ░  ░░  ░      ░░▒ ░     ░ ░ ▒  ░  ▒   ▒▒ ░    ░     ░ ░  ░░ ░▒  ░ ░
░  ░  ░    ░   ▒      ░   ░ ░   ░         ░   ░      ░   ░░         ░ ░     ░   ▒     ░         ░   ░  ░  ░  
      ░        ░  ░         ░             ░  ░       ░                ░  ░      ░  ░            ░  ░      ░  
                                                                                                             
		`,
	}
	for _, l := range lines {
		pterm.Println(pterm.LightBlue(l))
	}
	pterm.Println()
	pterm.Printf("  %s %s  %s\n",
		pterm.LightCyan("Go-Sleek-T"),
		pterm.Gray("v"+version),
		pterm.Gray("- 模板驱动的漏洞扫描器"),
	)
	pterm.Println()
}

// PrintBannerRaw is a package-level version of PrintBanner that can be called
// without a Console instance (e.g. for list/validate/help/version commands).
func PrintBannerRaw(version string) {
	lines := []string{
		`

  ██████  ▄▄▄       ███▄    █ ▄▄▄█████▓▓█████  ███▄ ▄███▓ ██▓███   ██▓     ▄▄▄      ▄▄▄█████▓▓█████   ██████
▒██    ▒ ▒████▄     ██ ▀█   █ ▓  ██▒ ▓▒▓█   ▀ ▓██▒▀█▀ ██▒▓██░  ██▒▓██▒    ▒████▄    ▓  ██▒ ▓▒▓█   ▀ ▒██    ▒
░ ▓██▄   ▒██  ▀█▄  ▓██  ▀█ ██▒▒ ▓██░ ▒░▒███   ▓██    ▓██░▓██░ ██▓▒▒██░    ▒██  ▀█▄  ▒ ▓██░ ▒░▒███   ░ ▓██▄
  ▒   ██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒░ ▓██▓ ░ ▒▓█  ▄ ▒██    ▒██ ▒██▄█▓▒ ▒▒██░    ░██▄▄▄▄██ ░ ▓██▓ ░ ▒▓█  ▄   ▒   ██▒
▒██████▒▒ ▓█   ▓██▒▒██░   ▓██░  ▒██▒ ░ ░▒████▒▒██▒   ░██▒▒██▒ ░  ░░██████▒ ▓█   ▓██▒  ▒██▒ ░ ░▒████▒▒██████▒▒
▒ ▒▓▒ ▒ ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒   ▒ ░░   ░░ ▒░ ░░ ▒░   ░  ░▒▓▒░ ░  ░░ ▒░▓  ░ ▒▒   ▓▒█░  ▒ ░░   ░░ ▒░ ░▒ ▒▓▒ ▒ ░
░ ░▒  ░ ░  ▒   ▒▒ ░░ ░░   ░ ▒░    ░     ░ ░  ░░  ░      ░░▒ ░     ░ ░ ▒  ░  ▒   ▒▒ ░    ░     ░ ░  ░░ ░▒  ░ ░
░  ░  ░    ░   ▒      ░   ░ ░   ░         ░   ░      ░   ░░         ░ ░     ░   ▒     ░         ░   ░  ░  ░
      ░        ░  ░         ░             ░  ░       ░                ░  ░      ░  ░            ░  ░      ░

		`,
	}
	for _, l := range lines {
		pterm.Println(pterm.LightBlue(l))
	}
	pterm.Println()
	pterm.Printf("  %s %s  %s\n",
		pterm.LightCyan("Go-Sleek-T"),
		pterm.Gray("v"+version),
		pterm.Gray("- 模板驱动的漏洞扫描器"),
	)
	pterm.Println()
}

// PrintDisclaimer prints the legal disclaimer. Always shown unless silent.
func (c *Console) PrintDisclaimer() {
	if !c.visible(0) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	body := []string{
		cardItem("使用范围", pterm.LightYellow("本工具仅供安全测试和授权评估使用")),
		cardItem("授权要求", "使用者需确保已获得目标系统的合法授权"),
		cardItem("法律风险", pterm.Red("未经授权的扫描行为可能违反相关法律法规")),
		cardItem("免责条款", "作者不对任何滥用行为承担责任"),
	}
	c.printCard(pterm.LightYellow("⚠  免责声明"), pterm.LightYellow, body, 75)
}

// PrintScanConfig prints a config summary before scanning.
func (c *Console) PrintScanConfig(info ScanConfigInfo) {
	if !c.visible(0) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	oobStatus := pterm.Red("✗ 未启用")
	if info.OOBEnabled {
		if info.OOBValid {
			oobStatus = pterm.Green("✓ 已启用") + pterm.Gray("  · "+oobProviderLabel(info.OOBProvider, info.OOBDomain))
		} else {
			oobStatus = pterm.Red("✗ 配置错误") + pterm.Gray("  (OOB 已启用但配置不完整)")
		}
	}
	proxy := info.Proxy
	if proxy == "" {
		proxy = pterm.Gray("— 无")
	}

	// Build left column
	type kv struct{ k, v string }
	left := []kv{
		{"目标数量", fmt.Sprintf("%d", info.Targets)},
		{"模板数量", fmt.Sprintf("%d", info.Templates)},
		{"并发数量", fmt.Sprintf("%d", info.Concurrency)},
		{"速率限制", fmt.Sprintf("%d req/s", info.RateLimit)},
	}
	pluginVal := fmt.Sprintf("%d", info.Plugins)
	if info.Plugins == 0 {
		pluginVal = pterm.Gray("0")
	}
	right := []kv{
		{"超时时间", fmt.Sprintf("%d s", info.Timeout)},
		{"OOB 状态", oobStatus},
		{"代理状态", proxy},
		{"Go  插件", pluginVal},
	}

	// Extra rows: retry, redirects, TLS, external hosts, body size
	if info.MaxRetries > 0 || info.RetryBackoff != "" {
		retryStr := fmt.Sprintf("重试 %d 次", info.MaxRetries)
		if info.RetryBackoff != "" {
			retryStr += " (退避 " + info.RetryBackoff + ")"
		}
		left = append(left, kv{"重试策略", retryStr})
	}
	redirectStr := "跟随"
	if !info.FollowRedirect {
		redirectStr = "不跟随"
	}
	if info.MaxRedirects > 0 {
		redirectStr += fmt.Sprintf(" (最多 %d 次)", info.MaxRedirects)
	}
	left = append(left, kv{"重定向否", redirectStr})

	tlsStr := pterm.Gray("✓ 已校验")
	if info.Insecure {
		tlsStr = pterm.Red("跳过校验 (-k)")
	}
	left = append(left, kv{"TLS 校验", tlsStr})

	externalStr := pterm.Gray("禁止外部")
	if info.AllowExternal {
		externalStr = pterm.Green("允许外部")
	}
	right = append(right, kv{"外部主机", externalStr})

	if info.MaxBodySize > 0 {
		right = append(right, kv{"最大响应", fmt.Sprintf("%d MB", info.MaxBodySize/1024/1024)})
	}

	// Build right column (continued)
	if info.AIEnabled {
		aiModel := info.AIModel
		if aiModel == "" {
			aiModel = "默认"
		}
		right = append(right, kv{"AI 分析", pterm.Green("✓ 已启用") + " (" + aiModel + ")"})
	}
	if info.LogFile != "" {
		right = append(right, kv{"日志文件", info.LogFile})
	}

	// Compute fixed column widths
	maxLK := 0
	maxLV := 0
	for _, it := range left {
		if w := display.DisplayWidth(it.k); w > maxLK {
			maxLK = w
		}
		plainV := display.StripAnsi(it.v)
		if w := display.DisplayWidth(plainV); w > maxLV {
			maxLV = w
		}
	}
	maxRK := 0
	maxRV := 0
	for _, it := range right {
		if w := display.DisplayWidth(it.k); w > maxRK {
			maxRK = w
		}
		plainV := display.StripAnsi(it.v)
		if w := display.DisplayWidth(plainV); w > maxRV {
			maxRV = w
		}
	}
	sepW := 1 + 2
	leftColW := maxLK + sepW + maxLV
	rightColW := maxRK + sepW + maxRV

	var lines []string
	rows := len(left)
	if len(right) > rows {
		rows = len(right)
	}
	for i := 0; i < rows; i++ {
		var s strings.Builder
		if i < len(left) {
			it := left[i]
			seg := fmt.Sprintf("%s%s  %s",
				pterm.LightCyan(display.PadRight(it.k, maxLK)),
				":",
				it.v,
			)
			segW := display.DisplayWidth(display.StripAnsi(seg))
			pad := leftColW - segW
			if pad < 0 {
				pad = 0
			}
			s.WriteString("  " + seg + strings.Repeat(" ", pad))
		} else {
			s.WriteString(strings.Repeat(" ", 2+leftColW))
		}
		s.WriteString("  ")
		if i < len(right) {
			it := right[i]
			seg := fmt.Sprintf("%s%s  %s",
				pterm.LightCyan(display.PadRight(it.k, maxRK)),
				":",
				it.v,
			)
			s.WriteString(seg)
		} else {
			s.WriteString(strings.Repeat(" ", rightColW))
		}
		lines = append(lines, s.String())
	}
	if info.OutputFile != "" {
		lines = append(lines, "")
		lines = append(lines, "  "+pterm.LightCyan("输出文件")+""+pterm.Gray("  · ")+info.OutputFormat+pterm.Gray("  →  ")+info.OutputFile)
	}
	c.printCard(pterm.LightCyan("▸")+"  扫描配置", pterm.LightCyan, lines, 75)
}

// PrintOOBWarning warns when templates or plugins need OOB but the provider is not configured.
func (c *Console) PrintOOBWarning(oobCount int, provider string, missing []string) {
	if !c.visible(0) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	var msg string
	if len(missing) > 0 {
		msg = fmt.Sprintf("检测到 %d 个模板/插件需要 OOB 验证，但配置不完整: %s", oobCount, strings.Join(missing, ", "))
	} else {
		msg = fmt.Sprintf("检测到 %d 个模板/插件需要 OOB 验证，但 OOB 未启用", oobCount)
	}
	lines := []string{
		"",
		"    " + pterm.Yellow(msg),
		"",
		"    " + pterm.White("配置方法:"),
		"      1. ceye:   --oob --oob-provider ceye --ceye-key <token> --ceye-domain <domain>",
		"      2. dnslog:  --oob --oob-provider dnslog (无需配置，自动获取)",
		"      3. callbackred: --oob --oob-provider callbackred (无需配置，自动获取)",
		"",
		"    " + pterm.Gray("或配置 config.yaml: oob.enabled = true"),
		"",
		"    " + pterm.Gray("注册地址: http://ceye.io/"),
		"",
	}
	c.printCard(pterm.LightYellow("⚠  OOB 警告"), pterm.LightYellow, lines, 76)
}

// ──────────────────────────────────────────────────────────────────────────
// Progress & lifecycle
// ──────────────────────────────────────────────────────────────────────────

// PrintInfo prints general info messages (visible with -v or higher).
func (c *Console) PrintInfo(format string, args ...interface{}) {
	c.pLine("信息", 1, format, args...)
}

// PrintVerb prints verbose messages (visible with -v or higher),
// same level as Info but visually tinted blue to distinguish.
func (c *Console) PrintVerb(format string, args ...interface{}) {
	c.pLine("详细", 1, format, args...)
}

// PrintDebug prints detailed debug messages (visible with -vv).
func (c *Console) PrintDebug(format string, args ...interface{}) {
	c.pLine("调试", 2, format, args...)
}

// PrintRaw prints raw multi-line dumps under a given tag (used for 匹配).
// The first line is tagged; subsequent lines keep the indent.
func (c *Console) PrintRaw(tag string, levelMin int, format string, args ...interface{}) {
	if !c.visible(levelMin) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	color := tagColor(tag)
	tagFmt := color("[" + tag + "]")
	msg := fmt.Sprintf(format, args...)
	ts := pterm.Gray(timeStampMs())
	lines := strings.Split(msg, "\n")
	for i, l := range lines {
		if i == 0 {
			pterm.Printf("%s %s %s\n", ts, tagFmt, l)
		} else {
			pterm.Printf("%s %s\n", contIndent, l)
		}
	}
}

// PrintPacket prints a raw HTTP packet in Burp-style format.
// Summary line gets the standard timestamp+tag prefix;
// raw content is printed in a separated block without prefixes,
// so it can be copied directly into Burp Repeater.
func (c *Console) PrintPacket(tag string, levelMin int, summary string, raw string) {
	if !c.visible(levelMin) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	color := tagColor(tag)
	tagFmt := color("[" + tag + "]")
	ts := pterm.Gray(timeStampMs())

	// Summary line with timestamp + tag
	pterm.Printf("%s %s %s\n", ts, tagFmt, summary)

	// Separator with label
	label := " REQUEST "
	if tag == "响应" {
		label = " RESPONSE "
	}
	labelLen := len(label)
	dashTotal := 75 - labelLen
	leftDash := dashTotal / 2
	rightDash := dashTotal - leftDash
	sep := pterm.Gray(strings.Repeat("─", leftDash)) +
		pterm.Cyan(label) +
		pterm.Gray(strings.Repeat("─", rightDash))
	pterm.Println(sep)

	// Raw content — no prefix, clean for copy-paste to Burp
	cleanRaw := strings.ReplaceAll(raw, "\r\n", "\n")
	cleanRaw = strings.TrimRight(cleanRaw, "\n")
	for _, line := range strings.Split(cleanRaw, "\n") {
		pterm.Println(line)
	}

	// Closing separator
	pterm.Println(pterm.Gray(strings.Repeat("─", 75)))
}

// PrintWarning prints warnings. Always shown.
func (c *Console) PrintWarning(format string, args ...interface{}) {
	c.pLine("警告", -1, format, args...)
}

// PrintError prints errors. Always shown.
func (c *Console) PrintError(format string, args ...interface{}) {
	c.pLine("错误", -1, format, args...)
}

// PrintTemplatesLoaded shows template loading summary. Always shown unless silent.
func (c *Console) PrintTemplatesLoaded(count int, dir string) {
	pterm.Println(pterm.Gray(strings.Repeat("─", 75)))
	c.pLine("成功", 0, "已加载 %d 个模板 (来自 %s)", count, dir)
}

// PrintSaved shows output file saved successfully. Always shown unless silent.
func (c *Console) PrintSaved(path, format string) {
	c.pLine("成功", 0, "结果已写入 %s (%s)", path, format)
}

// PrintScanStart shows scan start info. Always shown unless silent.
func (c *Console) PrintScanStart(targets, templates, plugins int) {
	if !c.visible(0) {
		return
	}
	total := targets * (templates + plugins)
	c.pLine("扫描", 0, "开始扫描: %d 个目标 × %d 个模板 = %d 个任务", targets, templates+plugins, total)
	c.mu.Lock()
	pterm.Println(pterm.Gray(strings.Repeat("─", 75)))
	c.mu.Unlock()
}

// PrintProgress shows periodic progress during scan.
func (c *Console) PrintProgress(completed, total int64, msg string) {
	if !c.visible(1) || total <= 0 {
		return
	}
	pct := completed * 100 / total
	last := atomic.LoadInt64(&c.lastPct)
	if pct/5 <= last/5 && pct != 100 {
		return
	}
	atomic.StoreInt64(&c.lastPct, pct)

	// Calculate ETA
	elapsed := time.Since(c.startedAt)
	if completed > 0 {
		perTask := elapsed.Seconds() / float64(completed)
		remaining := float64(total-completed) * perTask
		eta := time.Duration(remaining * float64(time.Second))
		c.pLine("进度", 1, "进度: %d/%d (%d%%)  耗时: %s  预计剩余: %s  %s",
			completed, total, pct,
			elapsed.Round(time.Second),
			eta.Round(time.Second),
			msg)
	} else {
		c.pLine("进度", 1, "进度: %d/%d (%d%%)  %s", completed, total, pct, msg)
	}
}

// IncRequests counts a request (for final stats).
func (c *Console) IncRequests(n int64) { atomic.AddInt64(&c.requests, n) }

// IncFailed counts a failed request.
func (c *Console) IncFailed(n int64) { atomic.AddInt64(&c.failed, n) }

// ──────────────────────────────────────────────────────────────────────────
// Matched result card
// ──────────────────────────────────────────────────────────────────────────

// PrintResult prints a matched vulnerability as a framed card.
func (c *Console) PrintResult(r *types.Result) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.results = append(c.results, r)
	atomic.AddInt64(&c.matched, 1)

	sevLabel := strings.ToUpper(r.Severity)
	sevColor := severityPColor(r.Severity)

	// 头部：严重度徽章 + 模板名称
	headLine := "    " + sevColor("◼ "+sevLabel) + pterm.Gray("   ") + pterm.Bold.Sprint(r.Name)
	var body []string
	body = append(body, headLine)
	// 分隔线（60 个 ·）
	body = append(body, "    "+pterm.Gray(strings.Repeat("·", 80)))
	body = append(body, "")
	body = append(body, resultKV("目标", r.Target))

	// 从 RawRequest 提取漏洞路径、方法和 body，显示完整漏洞信息
	if r.RawRequest != "" {
		method, path, reqBody := parseRawRequest(r.RawRequest)
		if path != "" {
			vulnURL := buildVulnURL(r.Target, path)
			if method != "" {
				body = append(body, resultKV("路径", pterm.LightCyan(method+" "+vulnURL)))
			} else {
				body = append(body, resultKV("路径", pterm.LightCyan(vulnURL)))
			}
			// 如果有 body，显示 POST body 摘要
			if reqBody != "" && (method == "POST" || method == "PUT" || method == "PATCH") {
				bodySummary := truncateStr(reqBody, 60)
				body = append(body, resultKV("Body", pterm.Gray(bodySummary)))
			}
		}
	}

	body = append(body, resultKV("模板", pterm.Cyan(r.TemplateID)))
	if r.Description != "" {
		desc := strings.Join(strings.Fields(r.Description), " ")
		body = append(body, resultKV("描述", display.Truncate(desc, 80)))
	}
	if r.Evidence != "" {
		evidence := r.Evidence
		if c.redact {
			evidence = redactText(evidence)
		}
		body = append(body, resultKV("证据", pterm.LightWhite(display.Truncate(evidence, 100))))
	}
	if len(r.Extracted) > 0 {
		var parts []string
		for k, v := range r.Extracted {
			parts = append(parts, fmt.Sprintf("%s=%s", k, display.Truncate(v, 40)))
		}
		// 提取值按 key 排序，确保输出稳定
		sort.Strings(parts)
		body = append(body, resultKV("提取", pterm.LightWhite(strings.Join(parts, ", "))))
	}
	if len(r.Tags) > 0 {
		var tagList []string
		for _, t := range r.Tags {
			tagList = append(tagList, pterm.Gray("#")+pterm.Cyan(t))
		}
		body = append(body, resultKV("标签", strings.Join(tagList, "  ")))
	}
	if len(r.Reference) > 0 {
		body = append(body, resultKV("参考", pterm.Gray(strings.Join(r.Reference, "  "))))
	}
	if r.MatchedAt != "" {
		body = append(body, resultKV("时间", pterm.Gray(r.MatchedAt)))
	}
	c.printCard("", sevColor, body, 90)
}

// parseRawRequest parses a raw HTTP request and extracts method, path, and body.
func parseRawRequest(raw string) (method, path, body string) {
	firstLine := strings.SplitN(raw, "\r\n", 2)[0]
	parts := strings.Fields(firstLine)
	if len(parts) >= 2 {
		method = parts[0]
		path = parts[1]
	}
	// Extract body: everything after the blank line separator
	sepIdx := strings.Index(raw, "\r\n\r\n")
	if sepIdx >= 0 {
		body = raw[sepIdx+4:]
	}
	return
}

// PrintAIResult prints AI analysis result for a matched vulnerability.
func (c *Console) PrintAIResult(aiConfidence float64, aiConfident bool, aiRiskAssessment string, suggestions []string, result *types.Result) {
	// 从 result.Extracted 读取 AI 扩展字段（由 engine 在分析时注入）
	var evidence, exploit, impact, remediation string
	if result != nil && result.Extracted != nil {
		evidence = result.Extracted["ai_evidence"]
		exploit = result.Extracted["ai_exploit"]
		impact = result.Extracted["ai_impact"]
		remediation = result.Extracted["ai_remediation"]
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	confPct := int(aiConfidence * 100)
	sevColor := severityPColor(result.Severity)

	pterm.Println()
	pterm.Println(pterm.Bold.Sprint("  ◈ AI 辅助分析"))
	pterm.Println(pterm.Gray(strings.Repeat("─", 75)))
	pterm.Printf("  漏洞:    %s\n", sevColor(result.Name))
	pterm.Printf("  目标:    %s\n", pterm.LightWhite(result.Target))
	pterm.Printf("  模板:    %s\n", pterm.Cyan(result.TemplateID))
	pterm.Printf("  置信度:  %d%%", confPct)
	if aiConfident {
		pterm.Printf("  %s\n", pterm.Green("✓ 已确认"))
	} else {
		pterm.Printf("  %s\n", pterm.Yellow("△ 待确认"))
	}
	pterm.Println()

	if evidence != "" {
		pterm.Printf("  证据:\n    %s\n", pterm.NewStyle(pterm.Italic).Sprint(pterm.Gray(display.Truncate(evidence, 120))))
	}
	if exploit != "" {
		pterm.Printf("  PoC:     %s\n", pterm.Yellow(exploit))
	}
	if impact != "" {
		pterm.Printf("  影响:    %s\n", pterm.Red(impact))
	}
	if remediation != "" {
		pterm.Printf("  修复:    %s\n", pterm.Green(remediation))
	}
	if aiRiskAssessment != "" {
		pterm.Printf("  评估:    %s\n", pterm.White(display.Truncate(aiRiskAssessment, 120)))
	}

	if len(suggestions) > 0 {
		pterm.Println()
		pterm.Println("  建议:")
		for _, s := range suggestions {
			pterm.Printf("    • %s\n", pterm.Gray(display.Truncate(s, 80)))
		}
	}
	pterm.Println(pterm.Gray(strings.Repeat("─", 75)))
}

// PrintAIFingerprint prints AI fingerprint recognition result.
func (c *Console) PrintAIFingerprint(server, technology, cms, language, waf string, confidence float64, target string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	confPct := int(confidence * 100)

	pterm.Println()
	pterm.Println("  " + pterm.Bold.Sprint("◈ AI 指纹识别"))
	pterm.Println("  " + pterm.Gray(strings.Repeat("─", 80)))
	pterm.Printf("  目标:    %s\n", pterm.LightWhite(target))
	if server != "" {
		pterm.Printf("  Server:  %s\n", pterm.Cyan(server))
	}
	if cms != "" {
		pterm.Printf("  CMS:     %s\n", pterm.Green(cms))
	}
	if language != "" {
		pterm.Printf("  语言:    %s\n", pterm.Yellow(language))
	}
	if technology != "" {
		pterm.Printf("  技术栈:  %s\n", pterm.Blue(technology))
	}
	if waf != "" && waf != "None" {
		pterm.Printf("  WAF:     %s\n", pterm.Red(waf))
	}
	pterm.Printf("  置信度:  %d%%\n", confPct)
	pterm.Println("  " + pterm.Gray(strings.Repeat("─", 80)))
}

// Scan end summary
// ──────────────────────────────────────────────────────────────────────────

// PrintScanEnd prints the final summary.
func (c *Console) PrintScanEnd(total, matched int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	elapsed := time.Since(c.startedAt)

	pterm.Println()
	pterm.Println()

	if matched > 0 {
		pterm.Printf("  %s  %s\n",
			pterm.Red("⚠"),
			pterm.LightRed(pterm.Bold.Sprint(fmt.Sprintf("发现 %d 个漏洞", matched))),
		)
	} else {
		pterm.Printf("  %s  %s\n",
			pterm.Green("✓"),
			pterm.LightGreen(pterm.Bold.Sprint("未发现漏洞")),
		)
	}
	pterm.Println()

	// Build left column (core stats)
	type kv struct{ k, v string }
	leftItems := []kv{
		{"总任务数", fmt.Sprintf("%d", total)},
		{"命中数量", fmt.Sprintf("%d", matched)},
		{"任务耗时", elapsed.Round(time.Millisecond).String()},
	}

	// Build right column (rate + severity)
	var rightItems []kv
	if elapsed.Seconds() > 0 && total > 0 {
		rate := float64(total) / elapsed.Seconds()
		rightItems = append(rightItems, kv{"扫描速率", fmt.Sprintf("%.1f req/s", rate)})
	}
	if total > 0 {
		pct := float64(matched) * 100 / float64(total)
		rightItems = append(rightItems, kv{"漏洞命中", fmt.Sprintf("%.1f%%", pct)})
	}
	// Severity counts
	sevCount := make(map[string]int)
	for _, r := range c.results {
		sevCount[r.Severity]++
	}
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if count, ok := sevCount[sev]; ok && count > 0 {
			rightItems = append(rightItems, kv{
				strings.ToUpper(sev),
				severityPColor(sev)(fmt.Sprintf("%d", count)),
			})
		}
	}

	// Separate severity items from rate/pct items
	knownSev := map[string]bool{
		"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true, "INFO": true,
	}
	var ratePctItems []kv
	var sevItems []kv
	for _, it := range rightItems {
		if knownSev[it.k] {
			sevItems = append(sevItems, it)
		} else {
			ratePctItems = append(ratePctItems, it)
		}
	}

	// Compute fixed column widths (key + sep + max_value) for alignment
	// seg format: "%s%s  %s" = key(maxLK) + fullwidth_colon(2) + 2spaces + value
	leftSepW := 2 + 2 // "：" + "  "
	rightSepW := 2 + 2
	maxLK, maxLV := 0, 0
	for _, it := range leftItems {
		if w := display.DisplayWidth(it.k); w > maxLK {
			maxLK = w
		}
		if w := display.DisplayWidth(display.StripAnsi(it.v)); w > maxLV {
			maxLV = w
		}
	}
	maxRK, maxRV := 0, 0
	for _, it := range ratePctItems {
		if w := display.DisplayWidth(it.k); w > maxRK {
			maxRK = w
		}
		if w := display.DisplayWidth(display.StripAnsi(it.v)); w > maxRV {
			maxRV = w
		}
	}
	leftColW := maxLK + leftSepW + maxLV
	rightColW := maxRK + rightSepW + maxRV

	// Render left column + right column side by side (fixed widths)
	rows := len(leftItems)
	if len(ratePctItems) > rows {
		rows = len(ratePctItems)
	}
	for i := 0; i < rows; i++ {
		var line string
		// Left cell — fixed width
		if i < len(leftItems) {
			it := leftItems[i]
			seg := fmt.Sprintf("%s%s  %s",
				pterm.LightCyan(display.PadRight(it.k, maxLK)),
				"：",
				it.v,
			)
			segW := display.DisplayWidth(display.StripAnsi(seg))
			pad := leftColW - segW
			if pad < 0 {
				pad = 0
			}
			line = "  " + seg + strings.Repeat(" ", pad)
		} else {
			line = strings.Repeat(" ", 2+leftColW)
		}
		// Gap
		line += "  "
		// Right cell — fixed width
		if i < len(ratePctItems) {
			it := ratePctItems[i]
			seg := fmt.Sprintf("%s%s  %s",
				pterm.LightCyan(display.PadRight(it.k, maxRK)),
				"：",
				it.v,
			)
			line += seg
		} else {
			line += strings.Repeat(" ", rightColW)
		}
		pterm.Println(line)
	}

	// Severity distribution on its own line
	if len(sevItems) > 0 {
		pterm.Println()
		var parts []string
		for _, it := range sevItems {
			parts = append(parts, fmt.Sprintf("%s%s%s",
				pterm.Gray("["),
				severityPColor(strings.ToLower(it.k))(it.k),
				pterm.Gray("] "+it.v),
			))
		}
		pterm.Println("  " + pterm.Gray("严重度分布") + "  " + strings.Join(parts, "    "))
	}
	pterm.Println()
}

// PrintVulnSummary prints a table of all discovered vulnerabilities below the scan end summary.
func (c *Console) PrintVulnSummary(results []*types.Result) {
	if !c.visible(0) || len(results) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	// Sort by severity (critical first)
	sort.Slice(results, func(i, j int) bool {
		return types.SeverityRank[results[i].Severity] > types.SeverityRank[results[j].Severity]
	})

	// Build table data
	tableData := pterm.TableData{{"严重度", "模板ID", "目标", "漏洞名称"}}
	for _, r := range results {
		tableData = append(tableData, []string{
			severityPColor(r.Severity)(strings.ToUpper(r.Severity)),
			pterm.Cyan(r.TemplateID),
			pterm.LightWhite(r.Target),
			pterm.LightYellow(r.Name),
		})
	}

	pterm.Println()
	pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
	pterm.Println()
}

// ──────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────

// timeStampMs returns current time as [2006-01-02 15:04:05.000].
func timeStampMs() string {
	return "[" + time.Now().Format("2006-01-02 15:04:05.000") + "]"
}

// ──────────────────────────────────────────────────────────────────────────
// Always indented with 4 spaces for alignment with resultKV.
func cardItem(label, value string) string {
	return fmt.Sprintf("    %s %s %s",
		pterm.Gray(label),
		pterm.Gray("·"),
		value,
	)
}

// resultKV is a result-card specific key/value line.
// It uses a fixed key width for alignment and a subtle "›" separator.
func resultKV(key, value string) string {
	const keyW = 6
	k := display.PadRight(key, keyW)
	return fmt.Sprintf("    %s%s  %s",
		pterm.LightMagenta(k),
		pterm.Gray("›"),
		value,
	)
}

// printCard draws a clean card with:
//   - optional title at the top, surrounded by dashes
//   - body lines with left indent, no side borders
//   - a bottom dash line to close the card
//
// With title:
//
//	── ▸ 扫描配置 ─────────────────────────────
//	   目标数量  :  1
//	   模板数量  :  13
//	──────────────────────────────────────────
//
// Without title (used for vulnerability cards):
//
//	──────────────────────────────────────────
//	  ◼ HIGH   Name of the template
//	  ····································
//	    目标   ›  value
//	──────────────────────────────────────────
func (c *Console) printCard(title string, accent func(a ...interface{}) string, body []string, width int) {
	if title != "" {
		titleW := display.DisplayWidth(title)
		// "── " (3) + title + " " (1) + "─*"
		used := 3 + titleW + 1
		dashes := width - used
		if dashes < 0 {
			dashes = 0
		}
		top := pterm.Gray("── ") + accent(title) + " " +
			pterm.Gray(strings.Repeat("─", dashes))
		pterm.Println(top)
	} else {
		pterm.Println(pterm.Gray(strings.Repeat("─", width)))
	}
	for _, line := range body {
		pterm.Println(line)
	}
	pterm.Println(pterm.Gray(strings.Repeat("─", width)))
	pterm.Println()
}

// severityPColor returns the pterm color function for a severity.
func severityPColor(sev string) func(a ...interface{}) string {
	switch strings.ToLower(sev) {
	case "critical":
		return pterm.LightRed
	case "high":
		return pterm.Red
	case "medium":
		return pterm.Yellow
	case "low":
		return pterm.LightBlue
	case "info":
		return pterm.Gray
	default:
		return pterm.White
	}
}

// oobProviderLabel returns a human-readable label for the OOB provider.
func oobProviderLabel(provider, domain string) string {
	switch provider {
	case "dnslog":
		return "dnslog.cn (auto)"
	case "callbackred":
		return "callback.red (auto)"
	case "ceye", "":
		if domain != "" {
			return domain
		}
		return "ceye.io"
	default:
		return provider
	}
}

// parseRequestMethodPath extracts HTTP method and path from a raw request string.
// Returns ("", "") if parsing fails.
func parseRequestMethodPath(raw string) (method, path string) {
	firstLine := strings.SplitN(raw, "\r\n", 2)[0]
	parts := strings.Fields(firstLine)
	if len(parts) >= 2 {
		return parts[0], parts[1]
	}
	if len(parts) == 1 {
		return parts[0], ""
	}
	return "", ""
}

// buildVulnURL constructs the full vulnerability URL from target base and request path.
// Handles three cases:
//   - Absolute URL in path (http://... or https://...) → use directly
//   - Relative path starting with / → append to target base
//   - Relative path without / → append to target base path
func buildVulnURL(target, path string) string {
	// If path is an absolute URL, return it directly
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	// Parse the base target URL
	base, err := url.Parse(target)
	if err != nil {
		return target + path
	}
	// If path starts with /, replace the path entirely
	if strings.HasPrefix(path, "/") {
		base.Path = path
		base.RawQuery = ""
		base.Fragment = ""
		return base.String()
	}
	// Relative path without / - append to base path
	if base.Path != "" && !strings.HasSuffix(base.Path, "/") {
		base.Path = base.Path + "/" + path
	} else {
		base.Path = base.Path + path
	}
	base.RawQuery = ""
	base.Fragment = ""
	return base.String()
}

// truncateStr truncates s to max display width with ellipsis.
func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// ──────────────────────────────────────────────────────────────────────────
// Replay output
// ──────────────────────────────────────────────────────────────────────────

// PrintReplayResult prints a replay result card with status, timing and summary.
func (c *Console) PrintReplayResult(r *replay.Result) {
	c.mu.Lock()
	defer c.mu.Unlock()

	pterm.Println()
	pterm.Println(pterm.Bold.Sprint("  请求回放"))
	pterm.Println(pterm.Gray(strings.Repeat("─", 75)))
	pterm.Println()

	// Status indicator
	statusColor := pterm.Green
	if r.Error != nil {
		statusColor = pterm.Red
	} else if r.StatusCode >= 400 {
		statusColor = pterm.Yellow
	} else if r.StatusCode >= 300 {
		statusColor = pterm.Cyan
	}

	pterm.Printf("  %s  %s\n", statusColor("◼"),
		statusColor(fmt.Sprintf("HTTP %d", r.StatusCode)))
	pterm.Println()

	// Details
	pterm.Println(pterm.Bold.Sprint("  信息:"))
	pterm.Println(pterm.Gray(strings.Repeat("─", 75)))
	pterm.Println(fmt.Sprintf("    %s%s  %s",
		pterm.LightMagenta(display.PadRight("目标", 8)),
		pterm.Gray("›"),
		r.Target))
	pterm.Println(fmt.Sprintf("    %s%s  %s",
		pterm.LightMagenta(display.PadRight("状态", 8)),
		pterm.Gray("│"),
		statusColor(fmt.Sprintf("%d %s", r.StatusCode, httpStatusText(r.StatusCode)))))
	pterm.Println(fmt.Sprintf("    %s%s  %s",
		pterm.LightMagenta(display.PadRight("耗时", 8)),
		pterm.Gray("│"),
		pterm.LightCyan(r.ResponseTime.String())))
	pterm.Println(fmt.Sprintf("    %s%s  %s",
		pterm.LightMagenta(display.PadRight("保存", 8)),
		pterm.Gray("│"),
		pterm.LightWhite(r.SavedPath)))
	if r.Compare.HasDiff {
		changeColor := pterm.Red
		if !r.Compare.StatusChanged {
			changeColor = pterm.Yellow
		}
		pterm.Println(fmt.Sprintf("    %s%s  %s",
			pterm.LightMagenta(display.PadRight("差异", 8)),
			pterm.Gray("│"),
			changeColor("有差异 (状态变化, 响应变化)")))
	}
	pterm.Println()
}

// PrintReplayDiff prints the diff between two responses.
func (c *Console) PrintReplayDiff(diff replay.CompareResult) {
	if !c.visible(1) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	pterm.Println(pterm.Bold.Sprint("  响应差异:"))
	pterm.Println(pterm.Gray(strings.Repeat("─", 75)))

	if diff.StatusChanged {
		pterm.Println(pterm.Red("  ⚠ 状态码发生变化"))
	}
	if diff.HeaderDiff != "" {
		pterm.Println(pterm.Yellow("  响应头变化:"))
		lines := strings.Split(strings.TrimSpace(diff.HeaderDiff), "\n")
		for _, line := range lines {
			pterm.Println("    " + pterm.Gray(line))
		}
	}
	if diff.BodyChanged && c.verbose >= 1 {
		pterm.Println(pterm.Yellow("  响应体变化:"))
		lines := strings.Split(strings.TrimSpace(diff.BodyDiff), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "-") {
				pterm.Println("    " + pterm.Red(line))
			} else if strings.HasPrefix(line, "+") {
				pterm.Println("    " + pterm.Green(line))
			} else {
				pterm.Println("    " + pterm.Gray(line))
			}
		}
	}
	pterm.Println()
}

// PrintReplayRaw prints raw request/response content for debugging.
func (c *Console) PrintReplayRaw(tag, raw string) {
	if !c.visible(2) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	color := tagColor(tag)
	tagFmt := color("[" + tag + "]")
	ts := pterm.Gray(timeStampMs())

	pterm.Printf("%s %s %s\n", ts, tagFmt, tag)

	// Separator
	label := " REQUEST "
	if tag == "响应" {
		label = " RESPONSE "
	}
	labelLen := len(label)
	dashTotal := 75 - labelLen
	leftDash := dashTotal / 2
	rightDash := dashTotal - leftDash
	sep := pterm.Gray(strings.Repeat("─", leftDash)) +
		pterm.Cyan(label) +
		pterm.Gray(strings.Repeat("─", rightDash))
	pterm.Println(sep)

	// Raw content — no prefix, clean for copy-paste
	cleanRaw := strings.ReplaceAll(raw, "\r\n", "\n")
	cleanRaw = strings.TrimRight(cleanRaw, "\n")
	for _, line := range strings.Split(cleanRaw, "\n") {
		pterm.Println(line)
	}
	pterm.Println()
}

// httpStatusText returns the standard HTTP status text for a given code.
func httpStatusText(code int) string {
	switch code {
	case 200:
		return "OK"
	case 201:
		return "Created"
	case 204:
		return "No Content"
	case 301:
		return "Moved Permanently"
	case 302:
		return "Found"
	case 304:
		return "Not Modified"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 500:
		return "Internal Server Error"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	default:
		return ""
	}
}
