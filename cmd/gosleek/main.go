package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "github.com/gosleek/gosleek/plugins" // 触发插件 init() 注册
	"github.com/gosleek/gosleek/internal/ai"
	"github.com/gosleek/gosleek/internal/config"
	"github.com/gosleek/gosleek/internal/display"
	"github.com/gosleek/gosleek/internal/distributed"
	"github.com/gosleek/gosleek/internal/engine"
	"github.com/gosleek/gosleek/internal/httpclient"
	"github.com/gosleek/gosleek/internal/logutil"
	"github.com/gosleek/gosleek/internal/output"
	"github.com/gosleek/gosleek/internal/plugin"
	"github.com/gosleek/gosleek/internal/replay"
	"github.com/gosleek/gosleek/internal/reporter"
	"github.com/gosleek/gosleek/internal/target"
	"github.com/gosleek/gosleek/internal/template"
	"github.com/gosleek/gosleek/internal/webui"
	"github.com/gosleek/gosleek/internal/wordlist"
	"github.com/gosleek/gosleek/pkg/constants"
	"github.com/gosleek/gosleek/pkg/types"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

// ────────────────────────────────────────────────────────────────────────
// Entry point
// ────────────────────────────────────────────────────────────────────────

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// ────────────────────────────────────────────────────────────────────────
// Root command
// ────────────────────────────────────────────────────────────────────────

var rootCmd = &cobra.Command{
	Use:   "gosleek",
	Short: "模板驱动的漏洞扫描器",
	Long:  fmt.Sprintf("Go-Sleek v%s - 模板驱动的漏洞扫描器", constants.Version),
}

// ────────────────────────────────────────────────────────────────────────
// scan command
// ────────────────────────────────────────────────────────────────────────

func newScanCmd() *cobra.Command {
	var (
		singleTarget, targetsFile string
		stdinTargets              bool
		templatesDir, templateID  string
		tags, severity, exclude   string
		pluginsOnly               bool
		pluginID                  string
		wordlistDir, builtin      string
		outputFile, outputFormat  string
		outputDir                 string
		concurrency, rateLimit, timeout int
		proxy                     string
		verifySSL, followRedirects bool
		oob, allowExternal        bool
		oobProvider, ceyeKey, ceyeDomain string
		resumeFile, logFile, logLevel string
		redact                    bool
		filterSeverity, filterTags, webuiURL string
		aiEnabled                 bool
		aiProvider, aiModel       string
		aiBaseURL, aiAPIKey       string
		aiMinConfidence           float64
		globalHeaders             []string
	)

	cmd := &cobra.Command{
		Use:     "scan [flags] [target...]",
		Short:   "扫描目标漏洞",
		Long: fmt.Sprintf("Go-Sleek v%s - 扫描一个或多个目标的 Web 漏洞，支持 YAML 模板和 Go 插件两种方式。\n\n"+
			"示例:\n  gosleek scan -t http://example.com\n  gosleek scan -l targets.txt -vv -o results.json\n  gosleek scan http://example.com --plugin CVE-2022-22963-go\n\n"+
			"参数分类:\n"+
			"  目标     -t/--target, -l/--list, --stdin\n"+
			"  模板     -T/--templates, -i/--tid, --tags, --severity, -e/--exclude\n"+
			"           --plugins-only, --plugin, --wordlist-dir, --builtin\n"+
			"  输出     -o/--output, -f/--format, --output-dir\n"+
			"  详细度   -v/--verbose, -vv, --silent\n"+
			"  网络     -c/--concurrency, -r/--rate-limit, --timeout\n"+
			"           -p/--proxy, -k/--verify-ssl, --follow-redirects, --header\n"+
			"  OOB      --oob, --oob-provider, --ceye-key, --ceye-domain, --allow-external-hosts\n"+
			"  AI       --ai, --ai-provider, --ai-model, --ai-base-url, --ai-api-key, --ai-min-confidence\n"+
			"  其他     --resume, --log-file, --log-level, --redact\n"+
			"           --filter-severity, --filter-tags, --webui-url",
			constants.Version,
		),
		Example: "  gosleek scan -t http://example.com\n  gosleek scan -l targets.txt -vv -o results.json\n  gosleek scan http://example.com --plugin CVE-2022-22963-go",
		Args:    cobra.MinimumNArgs(0),
		RunE: func(c *cobra.Command, args []string) error {
			for _, a := range args {
				if a != "" && !strings.HasPrefix(a, "-") {
					singleTarget = a
				}
			}
			verb := computeVerbosity(c, os.Args)
			return runScanParsed(
				singleTarget, targetsFile, stdinTargets,
				templatesDir, templateID, tags, severity, exclude,
				pluginsOnly, pluginID, wordlistDir, builtin,
				outputFile, outputFormat, outputDir,
				verb,
				concurrency, rateLimit, timeout,
				c.Flags().Changed("timeout"),
				c.Flags().Changed("rate-limit"),
				c.Flags().Changed("concurrency"),
				proxy, verifySSL, followRedirects,
				oob, allowExternal,
				c.Flags().Changed("allow-external-hosts"),
				c.Flags().Changed("oob"),
				c.Flags().Changed("oob-provider"),
				c.Flags().Changed("ceye-key"),
				c.Flags().Changed("ceye-domain"),
				oobProvider, ceyeKey, ceyeDomain,
				resumeFile, logFile, logLevel,
				redact, filterSeverity, filterTags, webuiURL,
				aiEnabled, aiProvider, aiModel, aiBaseURL, aiAPIKey, aiMinConfidence,
				globalHeaders,
			)
		},
	}

	// 目标
	cmd.Flags().StringVarP(&singleTarget, "target", "t", "", "单个目标 URL (可多次)")
	cmd.Flags().StringVarP(&targetsFile, "list", "l", "", "目标列表文件（每行一个 URL）")
	cmd.Flags().BoolVar(&stdinTargets, "stdin", false, "从 stdin 读取目标列表（管道输入）")
	// 模板/插件
	cmd.Flags().StringVarP(&templatesDir, "templates", "T", "templates", "模板目录（默认: templates）")
	cmd.Flags().StringVarP(&templateID, "tid", "i", "", "指定漏洞 ID（同时作用于模板和插件）")
	cmd.Flags().StringVar(&tags, "tags", "", "按标签筛选模板")
	cmd.Flags().StringVar(&severity, "severity", "", "按严重度筛选")
	cmd.Flags().StringVarP(&exclude, "exclude", "e", "", "排除指定模板 ID")
	cmd.Flags().BoolVar(&pluginsOnly, "plugins-only", false, "仅使用 Go 插件扫描")
	cmd.Flags().StringVar(&pluginID, "plugin", "", "指定 Go 插件 ID 扫描")
	cmd.Flags().StringVar(&wordlistDir, "wordlist-dir", "wordlists", "wordlist 文件基础目录")
	cmd.Flags().StringVar(&builtin, "builtin", "", "注入内置词表 (sqli/xss/ssrf/lfi/rce/path)")
	// 输出
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "结果写入文件")
	cmd.Flags().StringVarP(&outputFormat, "format", "f", "json", "输出格式: json,txt,sarif,html,csv,markdown")
	cmd.Flags().StringVar(&outputDir, "output-dir", "", "结果输出目录（自动生成时间戳文件名）")
	// 详细度
	cmd.Flags().BoolVar(&vvFlag, "vv", false, "极详细输出")
	cmd.Flags().BoolP("verbose", "v", false, "详细输出")
	cmd.Flags().BoolVar(&silentVerb, "silent", false, "静默模式")
	// 网络
	cmd.Flags().IntVarP(&concurrency, "concurrency", "c", 25, "并发数（默认: 25）")
	cmd.Flags().IntVarP(&rateLimit, "rate-limit", "r", 150, "每秒请求限制（默认: 150）")
	cmd.Flags().IntVar(&timeout, "timeout", 10, "请求超时秒数")
	cmd.Flags().StringVarP(&proxy, "proxy", "p", "", "HTTP/SOCKS5 代理")
	cmd.Flags().BoolVarP(&verifySSL, "verify-ssl", "k", false, "启用 TLS 证书校验")
	cmd.Flags().BoolVar(&followRedirects, "follow-redirects", true, "全局跟随重定向")
	cmd.Flags().StringArrayVar(&globalHeaders, "header", []string{}, "全局请求头注入 (可多次)")
	// OOB
	cmd.Flags().BoolVar(&oob, "oob", false, "启用 OOB 占位符")
	cmd.Flags().StringVar(&oobProvider, "oob-provider", "", "OOB 提供商: ceye/dnslog/callbackred")
	cmd.Flags().StringVar(&ceyeKey, "ceye-key", "", "ceye.io API Token")
	cmd.Flags().StringVar(&ceyeDomain, "ceye-domain", "", "ceye.io 识别域名")
	cmd.Flags().BoolVar(&allowExternal, "allow-external-hosts", false, "允许 Host 头重定向到外部主机")
	// 其他
	cmd.Flags().StringVar(&resumeFile, "resume", "", "从保存的状态断点续扫")
	cmd.Flags().StringVar(&logFile, "log-file", "", "将结构化日志以 JSON 写入指定文件")
	cmd.Flags().StringVar(&logLevel, "log-level", "", "日志最小级别: debug/info/warn/error")
	cmd.Flags().BoolVar(&redact, "redact", false, "脱敏输出")
	cmd.Flags().StringVar(&filterSeverity, "filter-severity", "", "结果过滤: 仅保留指定严重度")
	cmd.Flags().StringVar(&filterTags, "filter-tags", "", "结果过滤: 仅保留指定标签")
	cmd.Flags().StringVar(&webuiURL, "webui-url", "", "Web UI 地址（扫描结果自动推送）")
	// AI
	cmd.Flags().BoolVar(&aiEnabled, "ai", false, "启用 AI 实时分析")
	cmd.Flags().StringVar(&aiProvider, "ai-provider", "", "AI 提供商")
	cmd.Flags().StringVar(&aiModel, "ai-model", "", "AI 模型")
	cmd.Flags().Float64Var(&aiMinConfidence, "ai-min-confidence", 0.0, "AI 最小置信度")
	cmd.Flags().StringVar(&aiBaseURL, "ai-base-url", "", "AI API Base URL")
	cmd.Flags().StringVar(&aiAPIKey, "ai-api-key", "", "AI API Key")

	return cmd
}

// silentVerb is a helper bool used only to bind the --silent flag; verbosity is computed in RunE.
var silentVerb bool
var vvFlag bool

func runScanParsed(
	singleTarget, targetsFile string, stdinTargets bool,
	templatesDir, templateID, tags, severity, exclude string,
	pluginsOnly bool, pluginID, wordlistDir, builtin string,
	outputFile, outputFormat, outputDir string,
	verb int,
	concurrency, rateLimit, timeout int,
	// flagChanged: whether user explicitly passed these flags (to avoid default-value overwrite)
	timeoutExplicitlySet, rateLimitExplicitlySet, concurrencyExplicitlySet bool,
	proxy string, verifySSL, followRedirects bool,
	oob, allowExternal bool,
	allowExternalExplicitlySet bool,
	oobEnabledExplicitlySet, oobProviderExplicitlySet, ceyeKeyExplicitlySet, ceyeDomainExplicitlySet bool,
	oobProvider, ceyeKey, ceyeDomain string,
	resumeFile, logFile, logLevel string,
	redact bool,
	filterSeverity, filterTags, webuiURL string,
	aiEnabled bool, aiProvider, aiModel, aiBaseURL, aiAPIKey string, aiMinConfidence float64,
	globalHeaders []string,
) error {
	output.PrintBannerRaw(constants.Version)

	cfg := config.DefaultConfig()
	cfgPath := findConfig()
	if cfgPath != "" {
		if loaded, err := config.Load(cfgPath); err == nil {
			cfg = loaded
		}
	}
	if rateLimitExplicitlySet && rateLimit > 0 {
		cfg.RateLimit = rateLimit
	}
	if timeoutExplicitlySet {
		cfg.DefaultTimeout = timeout
	}
	if concurrencyExplicitlySet && concurrency > 0 {
		cfg.Concurrency = concurrency
	}

	if templatesDir == "templates" && cfg.TemplateDir != "" {
		templatesDir = cfg.TemplateDir
	}
	if !followRedirects && cfg.AllowExternal {
		// CLI explicitly disabled
	} else if followRedirects && !cfg.FollowRedirect {
		followRedirects = cfg.FollowRedirect
	}
	if !allowExternal && !allowExternalExplicitlySet && cfg.AllowExternal {
		allowExternal = cfg.AllowExternal
	}

	// OOB 配置：config.yaml 和 CLI 参数完全独立，只有优先级
	// 优先级：CLI 显式设置 > config.yaml > 默认值
	//
	// 逻辑：
	// 1. config.yaml oob.enabled=true → 自动启用，使用 config 的 provider 和凭据
	//    - ceye: 使用 config 的 token/domain
	//    - dnslog/callbackred: 无需凭据
	// 2. config.yaml oob.enabled=false 且 CLI 传 --oob → 启用 OOB，使用 CLI 参数
	//    - 必须指定 --oob-provider
	//    - ceye: 需要 --ceye-key 和 --ceye-domain
	//    - dnslog/callbackred: 无需凭据
	// 3. CLI 显式设置时优先（Changed 检测）
	oobEnabled := oob || cfg.OOB.Enabled
	oobProviderValue := oobProvider
	if oobProviderValue == "" {
		// CLI 未指定 provider，尝试 config
		if oobEnabled && !oobProviderExplicitlySet && cfg.OOB.Provider != "" {
			oobProviderValue = cfg.OOB.Provider
		} else {
			oobProviderValue = "ceye" // 仅当 CLI 显式启用 OOB 时的默认值
		}
	}
	ceyeKeyValue := ceyeKey
	ceyeDomainValue := ceyeDomain

	// config.yaml enabled=true 时，使用 config 的完整 OOB 配置
	// 但 CLI 显式设置时优先
	if cfg.OOB.Enabled && !oobEnabled {
		// config 启用但 CLI 未显式指定 --oob，使用 config 配置
		if oobProvider == "" && cfg.OOB.Provider != "" {
			oobProviderValue = cfg.OOB.Provider
		}
		if ceyeKey == "" && cfg.OOB.Ceye.Token != "" {
			ceyeKeyValue = cfg.OOB.Ceye.Token
		}
		if ceyeDomain == "" && cfg.OOB.Ceye.Domain != "" {
			ceyeDomainValue = cfg.OOB.Ceye.Domain
		}
	} else if cfg.OOB.Enabled && oobEnabled {
		// config 和 CLI 都启用了，CLI 显式设置的参数优先
		if !oobProviderExplicitlySet && cfg.OOB.Provider != "" {
			oobProviderValue = cfg.OOB.Provider
		}
		if !ceyeKeyExplicitlySet && cfg.OOB.Ceye.Token != "" {
			ceyeKeyValue = cfg.OOB.Ceye.Token
		}
		if !ceyeDomainExplicitlySet && cfg.OOB.Ceye.Domain != "" {
			ceyeDomainValue = cfg.OOB.Ceye.Domain
		}
	}

	var targets []string
	if singleTarget != "" {
		targets = append(targets, singleTarget)
	}
	if targetsFile != "" {
		if t, err := target.LoadFromFile(targetsFile); err == nil {
			targets = append(targets, t...)
		}
	}
	if (stdinTargets || targetsFile == "") && len(targets) == 0 {
		if t, err := target.LoadFromStdin(); err == nil {
			targets = append(targets, t...)
		}
	}
	targets = target.NormalizeTargets(targets)
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "未指定目标，使用 -t <url> 或 -l <file> 指定")
		os.Exit(1)
	}

	console := output.NewConsole(verb)
	// Register global logger BEFORE any submodule logging (templates, OOB, fingerprint)
	logutil.SetConsole(console)
	logutil.SetEffectiveVerb(verb)

	if verb >= 0 {
		console.PrintDisclaimer()
	}

	var tmplList []*types.Template
	var tagFilter, sevFilter, excludeFilter []string
	if tags != "" {
		tagFilter = strings.Split(tags, ",")
	}
	if severity != "" {
		sevFilter = []string{severity}
	}
	if exclude != "" {
		excludeFilter = strings.Split(exclude, ",")
	}
	if !pluginsOnly {
		var idFilter []string
		if templateID != "" {
			idFilter = []string{templateID}
		}
		// Load templates silently first - logs will be displayed after config panel
		if loaded, err := template.LoadDirSilent(templatesDir); err == nil {
			tmplList = template.ExcludeByID(
				template.FilterBySeverity(
					template.FilterByTag(
						template.FilterByID(loaded, idFilter), tagFilter),
					sevFilter), excludeFilter)
		}
	}

	allPlugins := plugin.All()
	pluginFilterID := pluginID
	if pluginFilterID == "" && templateID != "" {
		pluginFilterID = templateID
	}
	var pluginFilterIDs []string
	if pluginFilterID != "" {
		pluginFilterIDs = []string{pluginFilterID}
	}
	pluginList := plugin.Filter(allPlugins, plugin.FilterOptions{
		PluginIDs:  pluginFilterIDs,
		Tags:       tagFilter,
		Severity:   sevFilter,
		ExcludeIDs: excludeFilter,
	})
	if pluginsOnly || pluginID != "" {
		tmplList = nil
	}

	if len(tmplList) == 0 && len(pluginList) == 0 {
		fmt.Fprintln(os.Stderr, "未找到匹配的模板或插件")
		os.Exit(1)
	}

	oobCfg := engine.OOBConfig{}
	oobValid := false
	oobNeedsCount := 0
	if oob || cfg.OOB.Enabled {
		oobCfg.Provider = oobProviderValue
		oobCfg.CeyeToken = ceyeKeyValue
		oobCfg.CeyeDomain = ceyeDomainValue
		oobCfg.AllowExternal = allowExternal
		if oobCfg.Provider == "ceye" {
			if oobCfg.CeyeToken != "" && oobCfg.CeyeDomain != "" {
				oobValid = true
			}
		} else if oobCfg.Provider == "dnslog" || oobCfg.Provider == "callbackred" {
			oobValid = true
		}
	}
	if !pluginsOnly {
		for _, tmpl := range tmplList {
			if engine.TemplateNeedsOOB(tmpl) {
				oobNeedsCount++
			}
		}
	}
	for _, p := range pluginList {
		if p.NeedsOOB() {
			oobNeedsCount++
		}
	}

	_ = httpclient.New(httpclient.ClientConfig{
		Timeout:        time.Duration(cfg.DefaultTimeout) * time.Second,
		RateLimit:      cfg.RateLimit,
		UserAgent:      cfg.UserAgent,
		MaxRedirects:   cfg.MaxRedirects,
		Proxy:          proxy,
		Insecure:       !verifySSL,
		FollowRedirect: followRedirects,
		MaxBodySize:    cfg.MaxBodySize,
	})

	scanner := engine.NewScanner(cfg, verb, oobCfg, proxy, !verifySSL)
	scanner.SetWordlistDir(wordlistDir)

	if len(globalHeaders) > 0 {
		scanner.SetGlobalHeaders(parseHeaders(globalHeaders))
	}

	var resumeState *engine.ResumeState
	if resumeFile != "" {
		resumeState = engine.NewResumeState(resumeFile)
		scanner.SetResumeState(resumeState)
	}

	if outputFile != "" {
		output.WriteFile(nil, outputFile, outputFormat)
	} else if outputDir != "" {
		dir := setupOutputDir(outputDir)
		output.WriteFile(nil, dir+"/results."+outputFormat, outputFormat)
	}

	onResult := func(r *types.Result) {
		if redact {
			redacted := *r
			redacted.Evidence = output.RedactEvidence(r.Evidence)
			console.PrintResult(&redacted)
		} else {
			console.PrintResult(r)
		}
		if outputFile != "" {
			output.WriteFile([]*types.Result{r}, outputFile, outputFormat)
		}
	}
	scanner.SetCallbacks(onResult,
		func(completed, total int64, msg string) { console.PrintProgress(completed, total, msg) },
		func(format string, args ...interface{}) { console.PrintVerb(format, args...) },
		func(format string, args ...interface{}) { console.PrintDebug(format, args...) },
		func(tag, format string, args ...interface{}) { console.PrintRaw(tag, 2, format, args...) },
		func(tag, summary, raw string) { console.PrintPacket(tag, 1, summary, raw) },
	)

	// WebUI 结果推送
	var wuiClient *webuiClient
	if webuiURL != "" {
		wuiClient = newWebUIClient(webuiURL, console)
		scanner.OnWebUIAdd(func(r *types.Result) { wuiClient.PushResult(r) })
		// 推送任务创建（带重试，失败时生成本地 fallback ID）
		wuiClient.PushTaskCreate("gosleek scan", targets, func(id string) {
			scanner.SetTaskID(id)
			wuiClient.SetTaskID(id)
		})
	}

	actualLogFile := logFile
	actualLogLevel := logLevel
	if actualLogFile == "" && cfg.LogFile != "" {
		actualLogFile = cfg.LogFile
	}
	if actualLogLevel == "" && cfg.LogLevel != "" {
		actualLogLevel = cfg.LogLevel
	}
	// Apply config log-level to logutil gating only if no CLI verbosity flags set.
	// Note: we do NOT raise scanner.SetMinVerbosity() here — CLI -v/-vv always
	// takes priority. Config log-level only affects logutil's effectiveVerb,
	// which is used by logutil.Log() (not by the engine's direct s.verbose checks).
	if actualLogLevel != "" && verb == 0 {
		ml := logutil.LogLevelToVerbosity(actualLogLevel)
		logutil.SetMinLevel(ml)
	}

	var filterSev, filterTagList []string
	if filterSeverity != "" {
		filterSev = strings.Split(filterSeverity, ",")
	}
	if filterTags != "" {
		filterTagList = strings.Split(filterTags, ",")
	}

	console.PrintScanConfig(output.ScanConfigInfo{
		Targets:        len(targets),
		Templates:      len(tmplList),
		Plugins:        len(pluginList),
		Concurrency:    cfg.Concurrency,
		RateLimit:      cfg.RateLimit,
		Timeout:        cfg.DefaultTimeout,
		MaxRetries:     cfg.MaxRetries,
		RetryBackoff:   cfg.RetryBackoff,
		MaxRedirects:   cfg.MaxRedirects,
		FollowRedirect: followRedirects,
		AllowExternal:  allowExternal,
		Insecure:       !verifySSL, // true = -k 跳过 TLS 校验
		MaxBodySize:    cfg.MaxBodySize,
		OOBEnabled:     oob || cfg.OOB.Enabled,
		OOBValid:       oobValid,
		OOBDomain:      oobCfg.CeyeDomain,
		OOBProvider:    oobCfg.Provider,
		Proxy:          proxy,
		OutputFile:     outputFile,
		OutputFormat:   outputFormat,
		AIEnabled:      aiEnabled || cfg.AI.Enabled,
		AIModel:        cfg.AI.Model,
		LogFile:        actualLogFile,
	})
	console.PrintScanStart(len(targets), len(tmplList), len(pluginList))

	// Print OOB warning AFTER config panel
	if oobNeedsCount > 0 && !oobValid {
		var missing []string
		if !(oob || cfg.OOB.Enabled) {
			missing = append(missing, "未启用")
		} else {
			if oobCfg.Provider == "ceye" {
				if oobCfg.CeyeToken == "" {
					missing = append(missing, "ceye-key")
				}
				if oobCfg.CeyeDomain == "" {
					missing = append(missing, "ceye-domain")
				}
			}
		}
		if len(missing) > 0 {
			console.PrintOOBWarning(oobNeedsCount, oobCfg.Provider, missing)
		} else if !(oob || cfg.OOB.Enabled) {
			console.PrintOOBWarning(oobNeedsCount, "", nil)
		}
	}

	// Print template loading info AFTER the config panel
	if len(tmplList) > 0 {
		console.PrintTemplatesLoaded(len(tmplList), templatesDir)
		for _, t := range tmplList {
			console.PLine("模板", 1, "  - %s (%s) [%s] %s", t.ID, t.Name, t.Severity, t.FilePath)
		}
	} else if !pluginsOnly {
		console.PLine("跳过", 0, "目录 %s 中未找到任何模板文件", templatesDir)
	}

	// AI setup — config.yaml 和 CLI 参数完全独立，只有优先级
	// 逻辑：
	// 1. config.yaml ai.enabled=true → 自动启用，使用 config 的 provider/model/凭据
	// 2. config.yaml ai.enabled=false 且 CLI 传 --ai → 启用 AI，使用 CLI 参数
	// 3. CLI 显式设置的 provider/model/base-url/api-key 覆盖 config 默认值
	aiActive := aiEnabled || cfg.AI.Enabled
	if aiActive {
		p, err := buildAIProvider(aiProvider, aiModel, aiBaseURL, aiAPIKey, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] AI 初始化失败，跳过 AI 分析: %v\n", err)
		} else if p != nil && p.Available() {
			modelName := cfg.AI.Model
			if pObj, ok := p.(*ai.OpenAIProvider); ok {
				modelName = pObj.Model
			}
			console.PrintInfo("AI 助手已启用: %s / %s", p.Name(), modelName)
			scanner.SetAICallback(p, aiMinConfidence,
				func(resp *ai.AnalyzeResponse, r *types.Result) {
					console.PrintAIResult(resp.Confidence, resp.Confident,
						resp.RiskAssessment, resp.Suggestions, r)
				},
				nil)
		} else {
			fmt.Fprintf(os.Stderr, "[WARN] AI 提供商 %s 不可用\n", aiProvider)
		}
	}

	results := scanner.Run(context.Background(), tmplList, pluginList, targets)

	// Wait for AI analysis to complete before printing results
	scanner.WaitForAI(cfg.AI.Timeout)

	// 推送任务完成到 WebUI
	if webuiURL != "" && wuiClient != nil {
		resultCount := len(results)
		completed, matched, _ := scanner.GetStats()
		wuiClient.PushTaskComplete(resultCount, int(completed), int(matched))
	}

	var filtered []*types.Result
	for _, r := range results {
		if matchSeverityFilter(r.Severity, filterSev) && matchTagsFilter(r.Tags, filterTagList) {
			filtered = append(filtered, r)
		}
	}

	console.PrintScanEnd(int64(len(results)), int64(len(filtered)))
	console.PrintVulnSummary(filtered)
	if outputFile != "" {
		console.PrintSaved(outputFile, outputFormat)
	}
	if resumeState != nil {
		resumeState.Save()
	}
	return nil
}

func ceyeKeyExplicitlySet(ceyeKey string) bool  { return ceyeKey != "" }
func ceyeDomainExplicitlySet(ceyeDomain string) bool { return ceyeDomain != "" }

// ────────────────────────────────────────────────────────────────────────
// list command
// ────────────────────────────────────────────────────────────────────────

func newListCmd() *cobra.Command {
	var templatesDir, tags, severity, exclude, id string
	var pluginsOnly bool

	cmd := &cobra.Command{
		Use:   "list [flags]",
		Short: "列出/筛选可用模板",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) > 0 {
				return c.Usage()
			}
			runListParsed(templatesDir, pluginsOnly, tags, severity, exclude, id)
			return nil
		},
	}
	cmd.Flags().StringVarP(&templatesDir, "templates", "T", "templates", "模板目录")
	cmd.Flags().BoolVar(&pluginsOnly, "plugins-only", false, "仅显示 Go 插件")
	cmd.Flags().StringVar(&tags, "tags", "", "按标签筛选")
	cmd.Flags().StringVar(&severity, "severity", "", "按严重度筛选")
	cmd.Flags().StringVarP(&exclude, "exclude", "e", "", "排除指定 ID")
	cmd.Flags().StringVar(&id, "id", "", "筛选指定 ID")
	return cmd
}

func runListParsed(templatesDir string, pluginsOnly bool, tags, severity, exclude, id string) {
	output.PrintBannerRaw(constants.Version)
	var idFilter, sevFilter, tagFilter, excludeFilter []string
	if id != "" {
		idFilter = []string{id}
	}
	if severity != "" {
		sevFilter = []string{severity}
	}
	if tags != "" {
		tagFilter = strings.Split(tags, ",")
	}
	if exclude != "" {
		excludeFilter = strings.Split(exclude, ",")
	}

	var templates []*types.Template
	if loaded, err := template.LoadDir(templatesDir); err == nil {
		templates = template.ExcludeByID(
			template.FilterBySeverity(template.FilterByTag(template.FilterByID(loaded, idFilter), tagFilter), sevFilter), excludeFilter)
	}
	pluginList := plugin.Filter(plugin.All(), plugin.FilterOptions{PluginIDs: idFilter, Tags: tagFilter, Severity: sevFilter, ExcludeIDs: excludeFilter})

	type entry struct{ typ, id, name, sev, author, tags string }
	var entries []entry
	for _, t := range templates {
		entries = append(entries, entry{"YAML", t.ID, t.Name, t.Severity, t.Author, strings.Join(t.Tags, ",")})
	}
	for _, p := range pluginList {
		meta := p.Meta()
		entries = append(entries, entry{"Plugin", meta.ID, meta.Name, meta.Severity, meta.Author, strings.Join(meta.Tags, ",")})
	}

	colWidths := []int{8, 32, 50, 10, 10, 0}
	rowsFn := func() [][]string {
		var r [][]string
		for _, e := range entries {
			r = append(r, []string{typLabel(e.typ), e.id, display.Truncate(e.name, 50), severityBadge(e.sev), display.Truncate(e.author, 10), e.tags})
		}
		return r
	}
	headers := []string{"类型", "ID", "名称", "严重度", "作者", "标签"}
	var countStr string
	if pluginsOnly {
		countStr = fmt.Sprintf("共 %d 个 Go 插件", len(pluginList))
	} else {
		countStr = fmt.Sprintf("共 %d 个 YAML 模板, %d 个 Go 插件", len(templates), len(pluginList))
	}
	PrintTable("模板 / 插件列表", headers, colWidths, rowsFn, countStr)
}

// ────────────────────────────────────────────────────────────────────────
// validate command
// ────────────────────────────────────────────────────────────────────────

func newValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate [flags] <template_file>...",
		Short: "校验模板语法",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return runValidateParsed(args)
		},
	}
}

func runValidateParsed(paths []string) error {
	output.PrintBannerRaw(constants.Version)
	var targets []string
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			targets = append(targets, p)
			continue
		}
		if info.IsDir() {
			files, err := listYAMLFiles(p)
			if err != nil {
				pterm.Printf("  [WARN] %s: %v\n", p, err)
			} else {
				targets = append(targets, files...)
			}
		} else {
			targets = append(targets, p)
		}
	}
	if len(targets) == 0 {
		pterm.Println()
		pterm.Println(pterm.Yellow("  No YAML templates found in the specified paths"))
		return nil
	}
	valid, invalid := 0, 0
	type result struct{ path, id, name, status string }
	var results []result
	for _, path := range targets {
		if tmpl, err := template.LoadFile(path); err == nil {
			name := tmpl.Name
			if name == "" {
				name = "—"
			}
			results = append(results, result{path, tmpl.ID, name, "[OK] Valid"})
			valid++
		} else {
			results = append(results, result{path, "", "—", "[FAIL] " + err.Error()})
			invalid++
		}
	}
	colWidths := []int{40, 32, 40, 0}
	rowsFn := func() [][]string {
		var rows [][]string
		for _, r := range results {
			rows = append(rows, []string{display.Truncate(r.path, 40), r.id, display.Truncate(r.name, 40), r.status})
		}
		return rows
	}
	headers := []string{"Path", "ID", "Name", "Status"}
	var countStr string
	if invalid == 0 {
		countStr = fmt.Sprintf("All passed: %d templates valid", valid)
	} else {
		countStr = fmt.Sprintf("Done: %d valid, %d invalid", valid, invalid)
	}
	PrintTable("Template Validation", headers, colWidths, rowsFn, countStr)
	return nil
}

// ────────────────────────────────────────────────────────────────────────
// replay command
// ────────────────────────────────────────────────────────────────────────

func newReplayCmd() *cobra.Command {
	var (
		requestFile, target, outputDir, proxy, compareWith string
		verbose                                             int
		insecure, save, compare                             bool
	)

	cmd := &cobra.Command{
		Use:   "replay [flags] <request_file>",
		Short: "复放命中的请求（调试用）",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			reqFile := requestFile
			if reqFile == "" && len(args) > 0 {
				reqFile = args[0]
			}
			if reqFile == "" {
				return fmt.Errorf("未指定请求文件，使用 -f <file> 或作为 positional 参数")
			}
			return runReplayParsed(reqFile, target, outputDir, verbose, proxy, insecure, save, compare, compareWith)
		},
	}
	cmd.Flags().StringVarP(&requestFile, "file", "f", "", "请求文件路径（raw HTTP 格式）")
	cmd.Flags().StringVarP(&target, "target", "t", "", "目标 URL（如 http://example.com）")
	cmd.Flags().StringVarP(&outputDir, "output", "o", "./responses", "响应输出目录")
	cmd.Flags().IntVarP(&verbose, "verbose", "v", 0, "详细输出级别（0=普通, 1=-v, 2=-vv）")
	cmd.Flags().StringVar(&proxy, "proxy", "", "HTTP/SOCKS5 代理")
	cmd.Flags().BoolVarP(&insecure, "insecure", "k", false, "跳过 TLS 证书校验")
	cmd.Flags().BoolVar(&save, "save", true, "保存响应到文件（默认: 启用）")
	cmd.Flags().BoolVar(&compare, "compare", false, "与历史响应比对差异")
	cmd.Flags().StringVar(&compareWith, "with", "", "历史响应文件路径")
	return cmd
}

func runReplayParsed(reqFile, baseTarget, outputDir string, verbose int, proxy string, insecure bool, save, compare bool, compareWith string) error {
	output.PrintBannerRaw(constants.Version)
	target := baseTarget
	if target == "" {
		if data, err := os.ReadFile(reqFile); err == nil {
			lines := strings.SplitN(string(data), "\r\n", 2)
			if len(lines) > 0 {
				parts := strings.Fields(lines[0])
				if len(parts) >= 2 && (strings.HasPrefix(parts[1], "http://") || strings.HasPrefix(parts[1], "https://")) {
					target = parts[1]
				}
			}
		}
	}
	if target == "" {
		return fmt.Errorf("未指定目标 URL，使用 -t <url> 或在请求文件中提供完整 URL")
	}
	console := output.NewConsole(verbose)
	session := &replay.Session{
		RequestFile: reqFile, BaseURL: target, Proxy: proxy, Insecure: insecure,
		OutputDir: outputDir, Save: save, Compare: compare, OldPath: compareWith, Verbose: verbose,
	}
	ctx := context.Background()
	result, err := session.Run(ctx)
	if err != nil {
		console.PrintError("replay 失败: %v", err)
		os.Exit(1)
	}
	console.PrintReplayResult(result)
	if compare && result.Compare.HasDiff {
		console.PrintReplayDiff(result.Compare)
	}
	if verbose >= 2 {
		console.PrintReplayRaw("请求", result.Raw)
		console.PrintReplayRaw("响应", result.Raw)
	}
	if save && result.SavedPath != "" {
		console.PrintSaved(result.SavedPath, "txt")
	}
	return nil
}

// ────────────────────────────────────────────────────────────────────────
// webui command
// ────────────────────────────────────────────────────────────────────────

func newWebUICmd() *cobra.Command {
	var addr string
	cmd := &cobra.Command{
		Use:   "webui [flags]",
		Short: "启动 Web UI 可视化界面",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("webui 不接受位置参数")
			}
			return runWebUIParsed(addr)
		},
	}
	cmd.Flags().StringVarP(&addr, "addr", "a", ":8080", "监听地址（默认: :8080）")
	return cmd
}

func runWebUIParsed(addr string) error {
	output.PrintBannerRaw(constants.Version)
	logger := &cmdLogger{}
	srv := webui.NewServer(normalizeAddr(addr), logger)
	if err := srv.Start(); err != nil {
		pterm.Println(pterm.Red("启动失败: " + err.Error()))
		os.Exit(1)
	}
	pterm.Println(pterm.Green("✅ Web UI 已启动"))
	pterm.Printf("   地址: %s\n", pterm.LightCyan(srv.Addr()))
	pterm.Println("   按 Ctrl+C 停止")
	pterm.Println()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	pterm.Println(pterm.Yellow("正在关闭..."))
	ctx, cancel := context.WithTimeout(context.Background(), 5)
	defer cancel()
	srv.Stop(ctx)
	pterm.Println(pterm.Green("✅ Web UI 已停止"))
	return nil
}

// ────────────────────────────────────────────────────────────────────────
// report command
// ────────────────────────────────────────────────────────────────────────

func newReportCmd() *cobra.Command {
	var inputFile, inputDir, outputDir, format, title, author, version string
	cmd := &cobra.Command{
		Use:   "report [flags]",
		Short: "生成安全测试报告 (HTML/PDF/DOCX)",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("report 不接受位置参数")
			}
			if inputFile == "" && inputDir == "" {
				return fmt.Errorf("需要指定 -i（结果文件）或 -d（结果目录）")
			}
			return runReportParsed(inputFile, inputDir, outputDir, format, title, author, version)
		},
	}
	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "扫描结果文件（JSON 格式）")
	cmd.Flags().StringVarP(&inputDir, "input-dir", "d", "", "扫描结果目录（包含 results.json）")
	cmd.Flags().StringVarP(&outputDir, "output", "o", "./reports", "报告输出目录")
	cmd.Flags().StringVarP(&format, "format", "f", "all", "报告格式: html, pdf, docx, all（默认: all）")
	cmd.Flags().StringVar(&title, "title", "安全测试报告", "报告标题")
	cmd.Flags().StringVar(&author, "author", "gosleek", "报告作者")
	cmd.Flags().StringVar(&version, "version", constants.Version, "gosleek 版本")
	return cmd
}

func runReportParsed(inputFile, inputDir, outputDir, format, title, author, version string) error {
	output.PrintBannerRaw(constants.Version)
	results, err := loadResults(inputFile, inputDir)
	if err != nil {
		pterm.Println(pterm.Red("加载结果失败: " + err.Error()))
		os.Exit(1)
	}
	if len(results) == 0 {
		pterm.Println(pterm.Yellow("结果文件中没有漏洞数据"))
		return nil
	}
	cfg := config.DefaultConfig()
	scanInfo := &reporter.ScanInfo{
		StartTime:     time.Now().Add(-1 * time.Hour),
		EndTime:       time.Now(),
		Targets:       extractTargets(results),
		TemplateCount: countTemplates(results),
		PluginCount:   0,
		Concurrency:   cfg.Concurrency,
		RateLimit:     cfg.RateLimit,
		OOBEnabled:    false,
	}
	os.MkdirAll(outputDir, 0755)
	rt := reporter.New(title, author, version, outputDir)
	ctx := context.Background()
	switch format {
	case "html":
		if err := rt.GenerateHTML(ctx, results, scanInfo); err != nil {
			pterm.Println(pterm.Red("HTML 报告生成失败: " + err.Error()))
			os.Exit(1)
		}
		pterm.Println(pterm.Green("✅ HTML 报告已生成"))
		pterm.Printf("   文件: %s/report.html\n", outputDir)
	case "pdf":
		if err := rt.GeneratePDF(ctx, results, scanInfo); err != nil {
			pterm.Println(pterm.Red("PDF 报告生成失败: " + err.Error()))
			os.Exit(1)
		}
		pterm.Println(pterm.Green("✅ PDF 报告已生成"))
		pterm.Printf("   文件: %s/report.html (用浏览器打印为PDF)\n", outputDir)
	case "docx":
		if err := rt.GenerateDOCX(ctx, results, scanInfo); err != nil {
			pterm.Println(pterm.Red("DOCX 报告生成失败: " + err.Error()))
			os.Exit(1)
		}
		pterm.Println(pterm.Green("✅ DOCX 报告已生成"))
		pterm.Printf("   文件: %s/report.docx\n", outputDir)
	default:
		rt.GenerateHTML(ctx, results, scanInfo)
		rt.GeneratePDF(ctx, results, scanInfo)
		rt.GenerateDOCX(ctx, results, scanInfo)
		pterm.Println(pterm.Green("✅ 所有报告已生成"))
		pterm.Printf("   HTML: %s/report.html\n", outputDir)
		pterm.Printf("   PDF:  %s/report.html (打印版)\n", outputDir)
		pterm.Printf("   DOCX: %s/report.docx\n", outputDir)
	}
	pterm.Println()
	pterm.Println(pterm.Bold.Sprint("  漏洞统计:"))
	pterm.Printf("     目标数: %d\n", len(scanInfo.Targets))
	pterm.Printf("     漏洞数: %d\n", len(results))
	pterm.Printf("     格式:   %s\n", format)
	fmt.Println()
	return nil
}

// ────────────────────────────────────────────────────────────────────────
// ai command
// ────────────────────────────────────────────────────────────────────────

func newAICmd() *cobra.Command {
	var inputFile, provider, model, baseURL, apiKey string
	var verbose bool
	cmd := &cobra.Command{
		Use:   "ai [flags]",
		Short: "启动 AI 辅助分析",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("ai 不接受位置参数")
			}
			if inputFile == "" {
				return fmt.Errorf("需要指定 -i（结果文件）")
			}
			return runAIParsed(inputFile, provider, model, baseURL, apiKey, verbose)
		},
	}
	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "扫描结果文件（JSON 格式）")
	cmd.Flags().StringVarP(&provider, "provider", "p", "", "AI 提供商: openai, deepseek, kimi, glm, ollama, agnes, azure")
	cmd.Flags().StringVarP(&model, "model", "m", "", "AI 模型名称")
	cmd.Flags().StringVarP(&baseURL, "base-url", "u", "", "API Base URL")
	cmd.Flags().StringVarP(&apiKey, "api-key", "k", "", "API Key")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "显示详细分析结果")
	return cmd
}

func runAIParsed(inputFile, provider, model, baseURL, apiKey string, verbose bool) error {
	output.PrintBannerRaw(constants.Version)
	results, err := loadResults(inputFile, "")
	if err != nil {
		pterm.Println(pterm.Red("加载结果失败: " + err.Error()))
		os.Exit(1)
	}
	if len(results) == 0 {
		pterm.Println(pterm.Yellow("结果文件中没有漏洞数据"))
		return nil
	}
	cfg := config.DefaultConfig()
	cfgPath := findConfig()
	if cfgPath != "" {
		if loaded, err := config.Load(cfgPath); err == nil {
			cfg = loaded
		}
	}
	p, err := buildAIProvider(provider, model, baseURL, apiKey, cfg)
	if err != nil {
		pterm.Println(pterm.Red("AI 提供商初始化失败: " + err.Error()))
		os.Exit(1)
	}
	if p == nil || !p.Available() {
		pterm.Println(pterm.Red("AI 提供商不可用，请检查 API Key 和 Base URL"))
		os.Exit(1)
	}
	var actualModel string
	if op, ok := p.(*ai.OpenAIProvider); ok {
		actualModel = op.Model
	} else {
		actualModel = model
	}
	pterm.Println(pterm.Bold.Sprint("  AI 辅助分析"))
	pterm.Printf("  Provider:  %s\n", p.Name())
	pterm.Printf("  Model:     %s\n", actualModel)
	pterm.Printf("  结果数:    %d\n", len(results))
	fmt.Println()
	ctx := context.Background()
	succeeded, failed := 0, 0
	for i, result := range results {
		pterm.Printf("  [%d/%d] 分析: %s - %s\n", i+1, len(results), result.TemplateID, result.Name)
		req := &ai.AnalyzeRequest{
			TemplateID: result.TemplateID, TemplateName: result.Name,
			Severity: result.Severity, Target: result.Target,
			RawRequest: result.RawRequest, RawResponse: result.RawResponse,
			Evidence: result.Evidence, Extracted: result.Extracted,
			Context: buildContext(result),
		}
		resp, err := p.Analyze(ctx, req)
		if err != nil {
			pterm.Println(pterm.Red("    分析失败: " + err.Error()))
			failed++
			continue
		}
		confPct := int(resp.Confidence * 100)
		statusIcon := pterm.Green("✓ 已确认")
		if !resp.Confident {
			statusIcon = pterm.Yellow("△ 待确认")
		}
		pterm.Printf("    置信度:    %d%%  %s\n", confPct, statusIcon)
		pterm.Println(pterm.Gray("    ───────────────────────────────────────────────────────────"))
		if resp.Evidence != "" {
			pterm.Printf("    证据:      %s\n", pterm.NewStyle(pterm.Italic).Sprint(pterm.Cyan(resp.Evidence)))
		}
		if resp.Exploit != "" {
			pterm.Printf("    PoC:       %s\n", pterm.Yellow(resp.Exploit))
		}
		if resp.Impact != "" {
			pterm.Printf("    影响:      %s\n", pterm.Red(resp.Impact))
		}
		if resp.Remediation != "" {
			pterm.Printf("    修复:      %s\n", pterm.Green(resp.Remediation))
		}
		if resp.RiskAssessment != "" {
			pterm.Printf("    评估:      %s\n", pterm.White(resp.RiskAssessment))
		}
		if len(resp.Suggestions) > 0 {
			pterm.Println(pterm.Yellow("    建议:"))
			for _, s := range resp.Suggestions {
				pterm.Println(pterm.Gray("      • " + s))
			}
		}
		pterm.Println(pterm.Gray("    ───────────────────────────────────────────────────────────"))
		succeeded++
	}
	fmt.Println()
	pterm.Println(pterm.Bold.Sprint("  分析完成:"))
	pterm.Printf("    成功: %d\n", succeeded)
	pterm.Printf("    失败: %d\n", failed)
	pterm.Printf("    总计: %d\n", len(results))
	return nil
}

// ────────────────────────────────────────────────────────────────────────
// wordlist command
// ────────────────────────────────────────────────────────────────────────

func newWordlistCmd() *cobra.Command {
	var showAll, showStats, showList bool
	cmd := &cobra.Command{
		Use:   "wordlist [flags] [category]",
		Short: "查看/管理内置词表",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return runWordlistParsed(args, showAll, showStats, showList)
		},
	}
	cmd.Flags().BoolVar(&showAll, "all", false, "显示所有词表完整内容")
	cmd.Flags().BoolVar(&showStats, "stats", false, "仅显示统计")
	cmd.Flags().BoolVar(&showList, "list", false, "仅显示分类名称")
	return cmd
}

func runWordlistParsed(args []string, showAll, showStats, showList bool) error {
	output.PrintBannerRaw(constants.Version)
	categories := wordlist.AllBuiltins()
	categoryOrder := []string{"sqli", "xss", "ssrf", "lfi", "rce", "path"}

	if showAll {
		printAllWordlists(categories, categoryOrder)
		return nil
	}
	if showStats {
		printWordlistStats(categories, categoryOrder)
		return nil
	}
	if showList {
		fmt.Println()
		for i, cat := range categoryOrder {
			label := strings.ToUpper(cat)
			for _, m := range categories {
				if entries, ok := m[cat]; ok {
					stats := wordlist.ComputeStats(entries)
					pterm.Printf("  %s\n", pterm.LightCyan(fmt.Sprintf("%s (%d payloads)", label, stats.UniqueValues)))
					break
				}
			}
			if i < len(categoryOrder)-1 {
				fmt.Println()
			}
		}
		fmt.Println()
		pterm.Println(pterm.Gray("  使用: gosleek wordlist <category>"))
		fmt.Println("  使用: gosleek wordlist --all       # 显示全部内容")
		fmt.Println("  使用: gosleek wordlist --stats     # 仅显示统计")
		fmt.Println("  使用: gosleek scan --builtin sqli  # 扫描时注入词表")
		return nil
	}

	if len(args) == 0 {
		printWordlistSummary(categories, categoryOrder)
		return nil
	}
	switch args[0] {
	case "--all":
		printAllWordlists(categories, categoryOrder)
	case "--stats":
		printWordlistStats(categories, categoryOrder)
	case "--list":
		fmt.Println()
		for i, cat := range categoryOrder {
			label := strings.ToUpper(cat)
			for _, m := range categories {
				if entries, ok := m[cat]; ok {
					stats := wordlist.ComputeStats(entries)
					pterm.Printf("  %s\n", pterm.LightCyan(fmt.Sprintf("%s (%d payloads)", label, stats.UniqueValues)))
					break
				}
			}
			if i < len(categoryOrder)-1 {
				fmt.Println()
			}
		}
		fmt.Println()
		pterm.Println(pterm.Gray("  使用: gosleek wordlist <category>"))
		fmt.Println("  使用: gosleek wordlist --all       # 显示全部内容")
		fmt.Println("  使用: gosleek wordlist --stats     # 仅显示统计")
		fmt.Println("  使用: gosleek scan --builtin sqli  # 扫描时注入词表")
	default:
		printSingleWordlist(args[0], categories)
	}
	return nil
}

// ────────────────────────────────────────────────────────────────────────
// worker command
// ────────────────────────────────────────────────────────────────────────

func newWorkerCmd() *cobra.Command {
	var id, addr, templatesDir, configFile string
	var verbose, verbose2, silent bool
	cmd := &cobra.Command{
		Use:   "worker [flags]",
		Short: "启动分布式 Worker 节点",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("worker 不接受位置参数")
			}
			if id == "" {
				return fmt.Errorf("--id 为必填参数")
			}
			return runWorkerParsed(id, addr, templatesDir, configFile, verbose, verbose2, silent)
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "Worker 节点 ID（必填）")
	cmd.Flags().StringVarP(&addr, "addr", "a", ":19234", "监听地址（默认: :19234）")
	cmd.Flags().StringVarP(&templatesDir, "templates", "T", "templates", "模板目录（默认: templates）")
	cmd.Flags().StringVar(&configFile, "config", "", "配置文件路径")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "详细输出")
	cmd.Flags().BoolVar(&verbose2, "vv", false, "极详细输出")
	cmd.Flags().BoolVar(&silent, "silent", false, "静默模式")
	return cmd
}

func runWorkerParsed(id, addr, templatesDir, configFile string, verbose, verbose2, silent bool) error {
	output.PrintBannerRaw(constants.Version)
	verb := 0
	if verbose2 {
		verb = 2
	} else if verbose {
		verb = 1
	}
	if silent {
		verb = -1
	}
	cfg, err := config.Load(configFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, pterm.Red("加载配置失败: "+err.Error()))
		os.Exit(1)
	}
	cfg.TemplateDir = templatesDir
	console := output.NewConsole(verb)
	logger := &distLogger{console: console}
	worker := distributed.NewWorker(id, addr, cfg, logger)
	if err := worker.Start(); err != nil {
		fmt.Fprintln(os.Stderr, pterm.Red("启动 Worker 失败: " + err.Error()))
		os.Exit(1)
	}
	console.PrintInfo("Worker 已启动 (id=%s)", id)
	console.PrintInfo("监听地址: %s", addr)
	console.PrintInfo("模板目录: %s", templatesDir)
	console.PrintInfo("按 Ctrl+C 停止")
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	console.PrintInfo("正在停止 Worker...")
	worker.Stop()
	console.PrintInfo("✅ Worker 已停止")
	return nil
}

// ────────────────────────────────────────────────────────────────────────
// master command
// ────────────────────────────────────────────────────────────────────────

func newMasterCmd() *cobra.Command {
	var addr, templatesDir, configFile string
	var verbose, verbose2, silent bool
	cmd := &cobra.Command{
		Use:   "master [flags]",
		Short: "启动分布式 Master 节点",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("master 不接受位置参数")
			}
			return runMasterParsed(addr, templatesDir, configFile, verbose, verbose2, silent)
		},
	}
	cmd.Flags().StringVarP(&addr, "addr", "a", ":19234", "监听地址（默认: :19234）")
	cmd.Flags().StringVarP(&templatesDir, "templates", "T", "templates", "模板目录（默认: templates）")
	cmd.Flags().StringVar(&configFile, "config", "", "配置文件路径")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "详细输出")
	cmd.Flags().BoolVar(&verbose2, "vv", false, "极详细输出")
	cmd.Flags().BoolVar(&silent, "silent", false, "静默模式")
	return cmd
}

func runMasterParsed(addr, templatesDir, configFile string, verbose, verbose2, silent bool) error {
	output.PrintBannerRaw(constants.Version)
	verb := 0
	if verbose2 {
		verb = 2
	} else if verbose {
		verb = 1
	}
	if silent {
		verb = -1
	}
	cfg, err := config.Load(configFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, pterm.Red("加载配置失败: "+err.Error()))
		os.Exit(1)
	}
	cfg.TemplateDir = templatesDir
	console := output.NewConsole(verb)
	logger := &distLogger{console: console}
	templates, err := distributed.LoadTemplates(cfg.TemplateDir, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, pterm.Red("加载模板失败: "+err.Error()))
		os.Exit(1)
	}
	scheduler := distributed.NewScheduler(logger)
	scheduler.Start(cfg, templates, nil)
	go discoverWorkers(scheduler, logger, verb)
	console.PrintInfo("Master 已启动")
	console.PrintInfo("监听地址: %s", addr)
	console.PrintInfo("模板目录: %s", cfg.TemplateDir)
	console.PrintInfo("发现端口: %s", addr)
	console.PrintInfo("按 Ctrl+C 停止")
	console.PrintInfo("提示: 启动 Worker 后自动发现同一 LAN 内的节点")
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	console.PrintInfo("正在停止 Master...")
	scheduler.Stop()
	console.PrintInfo("✅ Master 已停止")
	return nil
}

func discoverWorkers(scheduler *distributed.Scheduler, logger distributed.LoggerIface, verb int) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		nodes, err := distributed.DiscoverNodes(2 * time.Second)
		if err != nil {
			if logger != nil {
				logger.Debug("节点发现失败: %v", err)
			}
			continue
		}
		for _, node := range nodes {
			if node.Role == distributed.NodeRoleMaster {
				continue
			}
			existing := false
			for _, existingNode := range scheduler.GetNodes() {
				if existingNode.ID == node.ID {
					existing = true
					break
				}
			}
			if !existing {
				scheduler.RegisterNode(node)
				if logger != nil {
					logger.Info("发现新节点", "id", node.ID, "address", node.Address)
				}
			}
		}
	}
}

// ────────────────────────────────────────────────────────────────────────
// version command
// ────────────────────────────────────────────────────────────────────────

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "显示版本信息",
		Run: func(c *cobra.Command, args []string) {
			output.PrintBannerRaw(constants.Version)
			pterm.Println()
			pterm.Println("  " + pterm.Bold.Sprint("Go-Sleek") + "  " + pterm.LightCyan("v"+constants.Version))
			pterm.Println("  " + pterm.Gray("模板驱动的漏洞扫描器"))
			pterm.Println()
		},
	}
}

// ────────────────────────────────────────────────────────────────────────
// help command (hidden, for backward compat)
// ────────────────────────────────────────────────────────────────────────

func newHelpCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "help",
		Short:  "显示帮助信息",
		Hidden: true,
		Run: func(c *cobra.Command, args []string) {
			printGlobalHelp()
		},
	}
}

// ────────────────────────────────────────────────────────────────────────
// init: register all sub-commands
// ────────────────────────────────────────────────────────────────────────

func init() {
	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newListCmd())
	rootCmd.AddCommand(newValidateCmd())
	rootCmd.AddCommand(newReplayCmd())
	rootCmd.AddCommand(newWebUICmd())
	rootCmd.AddCommand(newReportCmd())
	rootCmd.AddCommand(newAICmd())
	rootCmd.AddCommand(newWordlistCmd())
	rootCmd.AddCommand(newWorkerCmd())
	rootCmd.AddCommand(newMasterCmd())
	rootCmd.AddCommand(newVersionCmd())
	rootCmd.AddCommand(newHelpCmd())
}

// ────────────────────────────────────────────────────────────────────────
// shared helper variables/functions
// ────────────────────────────────────────────────────────────────────────

func buildAIProvider(provider, model, baseURL, apiKey string, cfg *config.GlobalConfig) (ai.Provider, error) {
	// 只有当 CLI 没有显式设置 provider 时，才从 config 读取默认值
	name := provider
	if name == "" {
		name = cfg.AI.Provider
	}
	if name == "" {
		return nil, fmt.Errorf("未指定 AI 提供商，请通过 --ai-provider 或 config.yaml 的 ai.provider 指定")
	}
	m := model
	if m == "" {
		m = cfg.AI.Model
	}
	if m == "" {
		if pc, ok := ai.Providers()[name]; ok {
			m = pc.Model
		}
	}
	if m == "" {
		return nil, fmt.Errorf("未指定 AI 模型，请通过 --ai-model 或 config.yaml 的 ai.model 指定")
	}
	url := baseURL
	if url == "" {
		url = cfg.AI.BaseURL
	}
	if url == "" {
		if pc, ok := ai.Providers()[name]; ok {
			url = pc.BaseURL
		}
	}
	key := apiKey
	if key == "" {
		key = cfg.AI.APIKey
	}
	if key == "" {
		if pc, ok := ai.Providers()[name]; ok {
			key = pc.APIKey
		}
	}
	timeout := cfg.AI.Timeout
	if timeout <= 0 {
		timeout = 30
	}
	p := ai.NewOpenAIProvider(key, url, m, name, timeout)
	if !p.Available() {
		return nil, fmt.Errorf("AI 提供商 %s 不可用（缺少 API Key 或 Base URL）", name)
	}
	return p, nil
}

func buildContext(result *types.Result) string {
	var parts []string
	if result.TemplateID != "" {
		parts = append(parts, "模板ID: "+result.TemplateID)
	}
	if result.Severity != "" {
		parts = append(parts, "严重度: "+result.Severity)
	}
	if len(result.Tags) > 0 {
		parts = append(parts, "标签: "+strings.Join(result.Tags, ", "))
	}
	if result.Extracted != nil {
		parts = append(parts, "提取变量: "+fmt.Sprint(result.Extracted))
	}
	if len(parts) > 0 {
		return strings.Join(parts, " | ")
	}
	return ""
}

func loadResults(file, dir string) ([]*types.Result, error) {
	if file != "" {
		return parseResultsFile(file)
	}
	if dir != "" {
		return parseResultsFile(filepath.Join(dir, "results.json"))
	}
	return nil, fmt.Errorf("需要指定 -i 或 -d")
}

func parseResultsFile(path string) ([]*types.Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var results []*types.Result
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("JSON 解析失败: %v", err)
	}
	return results, nil
}

func extractTargets(results []*types.Result) []string {
	seen := make(map[string]bool)
	var targets []string
	for _, r := range results {
		if !seen[r.Target] {
			seen[r.Target] = true
			targets = append(targets, r.Target)
		}
	}
	return targets
}

func countTemplates(results []*types.Result) int {
	seen := make(map[string]bool)
	for _, r := range results {
		seen[r.TemplateID] = true
	}
	return len(seen)
}

func matchSeverityFilter(sev string, filters []string) bool {
	if len(filters) == 0 {
		return true
	}
	for _, f := range filters {
		if strings.EqualFold(sev, f) {
			return true
		}
	}
	return false
}

func matchTagsFilter(tags []string, filters []string) bool {
	if len(filters) == 0 {
		return true
	}
	for _, tag := range tags {
		for _, f := range filters {
			if tag == f {
				return true
			}
		}
	}
	return false
}

// ────────────────────────────────────────────────────────────────────────
// Helper types (webui / distributed logger bridges)
// ────────────────────────────────────────────────────────────────────────

type cmdLogger struct{}

func (l *cmdLogger) DebugKV(msg string, args ...interface{})   { l.printKV("调试", msg, args) }
func (l *cmdLogger) InfoKV(msg string, args ...interface{})    { l.printKV("信息", msg, args) }
func (l *cmdLogger) WarnKV(msg string, args ...interface{})    { l.printKV("警告", msg, args) }
func (l *cmdLogger) Error(msg string, args ...interface{})     { l.printKV("错误", msg, args) }

func (l *cmdLogger) printKV(tag string, msg string, args []interface{}) {
	ts := pterm.Gray(time.Now().Format("2006-01-02 15:04:05.000"))
	tagFmt := tagColor(tag)("[" + tag + "]")
	var parts []string
	parts = append(parts, msg)
	for i := 0; i < len(args); i += 2 {
		parts = append(parts, fmt.Sprintf("%v=%v", args[i], args[i+1]))
	}
	pterm.Printf("%s %s %s\n", ts, tagFmt, strings.Join(parts, " "))
}

func (l *cmdLogger) printFmt(tag string, msg string, args []interface{}) {
	ts := pterm.Gray(time.Now().Format("2006-01-02 15:04:05.000"))
	tagFmt := tagColor(tag)("[" + tag + "]")
	formatted := fmt.Sprintf(msg, args...)
	pterm.Printf("%s %s %s\n", ts, tagFmt, formatted)
}

func tagColor(tag string) func(...interface{}) string {
	switch tag {
	case "调试":
		return pterm.Gray
	case "信息":
		return pterm.LightCyan
	case "警告":
		return pterm.Yellow
	case "错误":
		return pterm.Red
	default:
		return func(s ...interface{}) string { return fmt.Sprint(s...) }
	}
}

type distLogger struct {
	console *output.Console
}

func (l *distLogger) Debug(msg string, args ...interface{}) {
	if l.console != nil {
		l.console.PrintDebug("[distributed] "+msg, args...)
	}
}
func (l *distLogger) Info(msg string, args ...interface{}) {
	if l.console != nil {
		l.console.PrintInfo("[distributed] "+msg, args...)
	}
}
func (l *distLogger) Warn(msg string, args ...interface{}) {
	if l.console != nil {
		l.console.PrintWarning("[distributed] "+msg, args...)
	}
}
func (l *distLogger) Error(msg string, args ...interface{}) {
	if l.console != nil {
		l.console.PrintError("[distributed] "+msg, args...)
	}
}

func normalizeAddr(addr string) string {
	if strings.Contains(addr, ":") {
		return addr
	}
	return ":" + addr
}

// ────────────────────────────────────────────────────────────────────────
// Wordlist helpers (moved from cmd_wordlist.go)
// ────────────────────────────────────────────────────────────────────────

func printWordlistSummary(categories []map[string][]wordlist.Entry, order []string) {
	fmt.Println()
	pterm.Println(pterm.Bold.Sprint("  内置词表"))
	fmt.Println()
	pterm.Println(pterm.Gray(strings.Repeat("─", 75)))
	pterm.Println(pterm.Bold.Sprint("  按分类查看词表:"))
	fmt.Println()
	for _, cat := range order {
		for _, m := range categories {
			entries, ok := m[cat]
			if !ok {
				continue
			}
			stats := wordlist.ComputeStats(entries)
			label := strings.ToUpper(cat)
			pterm.Printf("  %s\n", pterm.Bold.Sprint("  "+label+"  ("+pterm.LightCyan(fmt.Sprintf("%d payloads)", stats.UniqueValues))))
			pterm.Println(pterm.Gray("    基础探测:"))
			preview := entries
			if len(preview) > 5 {
				preview = preview[:5]
			}
			for _, e := range preview {
				val := e.Value
				if len(val) > 55 {
					val = val[:52] + "..."
				}
				fmt.Println("      " + pterm.Gray("'"+strings.TrimSpace(val)+"'") + "  " + pterm.Gray("// "+e.Category))
			}
			if len(entries) > 5 {
				fmt.Println("      " + pterm.Gray("      ... 还有 "+fmt.Sprintf("%d 条", len(entries)-5)+" 条"))
			}
			fmt.Println()
			break
		}
	}
	pterm.Println(pterm.Bold.Sprint("  使用方式:"))
	fmt.Println()
	fmt.Println("    " + pterm.LightYellow("gosleek wordlist <category>") + "  " + pterm.Gray("# 查看指定词表的完整内容"))
	fmt.Println("    " + pterm.LightYellow("gosleek wordlist --all") + "      " + pterm.Gray("# 查看所有词表的完整内容"))
	fmt.Println("    " + pterm.LightYellow("gosleek wordlist --stats") + "      " + pterm.Gray("# 仅显示词表统计"))
	fmt.Println("    " + pterm.LightYellow("gosleek scan --builtin sqli") + "  " + pterm.Gray("# 扫描时注入 SQLi 词表"))
	fmt.Println()
}

func printWordlistStats(categories []map[string][]wordlist.Entry, order []string) {
	fmt.Println()
	pterm.Println(pterm.Bold.Sprint("  词表统计"))
	fmt.Println()
	pterm.Println(pterm.Gray(strings.Repeat("─", 75)))
	totalEntries, totalUnique := 0, 0
	for _, cat := range order {
		for _, m := range categories {
			entries, ok := m[cat]
			if !ok {
				continue
			}
			stats := wordlist.ComputeStats(entries)
			totalEntries += stats.TotalLines
			totalUnique += stats.UniqueValues
			label := strings.ToUpper(cat)
			pterm.Printf("  %-6s  %3d 条  (%d 唯一)\n", label, stats.TotalLines, stats.UniqueValues)
			break
		}
	}
	pterm.Println(pterm.Gray(strings.Repeat("─", 75)))
	pterm.Printf("  %-6s  %3d 条  (%d 唯一)\n", "TOTAL", totalEntries, totalUnique)
	fmt.Println()
}

func printSingleWordlist(category string, categories []map[string][]wordlist.Entry) {
	category = strings.ToLower(category)
	var entries []wordlist.Entry
	for _, m := range categories {
		if e, ok := m[category]; ok {
			entries = e
			break
		}
	}
	if entries == nil {
		pterm.Println(pterm.Red("  未知分类: "+category))
		fmt.Println()
		pterm.Println(pterm.Gray("  可用分类: " + strings.Join([]string{"sqli", "xss", "ssrf", "lfi", "rce", "path"}, ", ")))
		return
	}
	stats := wordlist.ComputeStats(entries)
	fmt.Println()
	label := strings.ToUpper(category)
	pterm.Println(pterm.Bold.Sprint("  " + label + "  —  " + fmt.Sprintf("%d 条 payload (%d 唯一)", stats.TotalLines, stats.UniqueValues)))
	fmt.Println()
	pterm.Println(pterm.Gray(strings.Repeat("─", 75)))
	for _, e := range entries {
		val := e.Value
		if len(val) > 70 {
			val = val[:67] + "..."
		}
		fmt.Println("  " + pterm.LightYellow(strings.TrimSpace(val)) + "  " + pterm.Gray("["+e.Category+"]"))
	}
	fmt.Println()
}

func printAllWordlists(categories []map[string][]wordlist.Entry, order []string) {
	fmt.Println()
	pterm.Println(pterm.Bold.Sprint("  全部内置词表"))
	fmt.Println()
	for _, cat := range order {
		for _, m := range categories {
			entries, ok := m[cat]
			if !ok {
				continue
			}
			stats := wordlist.ComputeStats(entries)
			label := strings.ToUpper(cat)
			pterm.Println(pterm.Bold.Sprint("  " + label + " (" + fmt.Sprintf("%d payloads", stats.UniqueValues) + ")"))
			pterm.Println(pterm.Gray(strings.Repeat("─", 75)))
			for _, e := range entries {
				val := e.Value
				if len(val) > 70 {
					val = val[:67] + "..."
				}
				fmt.Println("  " + pterm.LightYellow(strings.TrimSpace(val)) + "  " + pterm.Gray("["+e.Category+"]"))
			}
			fmt.Println()
			break
		}
	}
}


func showWebUIHelp() {
	pterm.Println()
	pterm.Println(pterm.Bold.Sprint("  用法: gosleek webui [选项]"))
	fmt.Println()
	pterm.Println(pterm.Bold.Sprint("  选项:"))
	pterm.Println(pterm.Gray(strings.Repeat("─", 55)))
	printHelpRow("  -a, --addr <addr>", "  监听地址（默认: :8080）")
	printHelpRow("  -h, --help", "  显示帮助信息")
	pterm.Println(pterm.Gray(strings.Repeat("─", 55)))
	fmt.Println()
	pterm.Println(pterm.Bold.Sprint("  示例:"))
	pterm.Println(pterm.Gray(strings.Repeat("─", 55)))
	fmt.Println("    " + pterm.White("gosleek webui") + "                        " + pterm.Gray("# 启动默认地址 :8080"))
	fmt.Println("    " + pterm.White("gosleek webui -a :9090") + "             " + pterm.Gray("# 指定端口 9090"))
	fmt.Println("    " + pterm.White("gosleek webui -a 0.0.0.0:8080") + "      " + pterm.Gray("# 监听所有接口"))
	fmt.Println()
}

func showReportHelp() {
	pterm.Println()
	pterm.Println(pterm.Bold.Sprint("  用法: gosleek report [选项]"))
	fmt.Println()
	pterm.Println(pterm.Bold.Sprint("  参数:"))
	pterm.Println(pterm.Gray(strings.Repeat("─", 55)))
	printHelpRow("  -i, --input <file>", "  扫描结果 JSON 文件（与 -d 二选一）")
	printHelpRow("  -d, --input-dir <dir>", "  扫描结果目录，读取 results.json")
	printHelpRow("  -o, --output <dir>", "  报告输出目录（默认: ./reports）")
	printHelpRow("  -f, --format <fmt>", "  报告格式: html, pdf, docx, all（默认: all）")
	printHelpRow("  --title <title>", "  报告标题（默认: 安全测试报告）")
	printHelpRow("  --author <name>", "  报告作者（默认: gosleek）")
	printHelpRow("  -h, --help", "      显示帮助信息")
	pterm.Println(pterm.Gray(strings.Repeat("─", 55)))
	fmt.Println()
	pterm.Println(pterm.Bold.Sprint("  示例:"))
	pterm.Println(pterm.Gray(strings.Repeat("─", 55)))
	fmt.Println("    " + pterm.White("gosleek report -i results.json") + "                " + pterm.Gray("# 生成所有格式报告"))
	fmt.Println("    " + pterm.White("gosleek report -i results.json -f html") + "        " + pterm.Gray("# 仅生成 HTML"))
	fmt.Println("    " + pterm.White("gosleek report -d ./output/ -o ./reports/") + "     " + pterm.Gray("# 从目录生成"))
	fmt.Println("    " + pterm.White("gosleek report -i results.json --title '渗透测试'") + "  " + pterm.Gray("# 自定义标题"))
	fmt.Println()
}

func showAIHelp() {
	pterm.Println()
	pterm.Println(pterm.Bold.Sprint("  用法: gosleek ai [选项]"))
	fmt.Println()
	pterm.Println(pterm.Bold.Sprint("  参数:"))
	pterm.Println(pterm.Gray(strings.Repeat("─", 55)))
	printHelpRow("  -i, --input <file>", "  扫描结果 JSON 文件（必填）")
	printHelpRow("  -p, --provider <p>", "  AI 提供商: openai, deepseek, kimi, glm, ollama, agnes, azure")
	printHelpRow("  -m, --model <m>", "  AI 模型名称")
	printHelpRow("  -u, --base-url <url>", "  API Base URL")
	printHelpRow("  -k, --api-key <key>", "  API Key")
	printHelpRow("  -v, --verbose", "      显示详细分析结果（建议、提取变量）")
	printHelpRow("  -h, --help", "      显示帮助信息")
	pterm.Println(pterm.Gray(strings.Repeat("─", 55)))
	fmt.Println()
	pterm.Println(pterm.Bold.Sprint("  示例:"))
	pterm.Println(pterm.Gray(strings.Repeat("─", 55)))
	fmt.Println("    " + pterm.White("gosleek ai -i results.json") + "               " + pterm.Gray("# 分析扫描结果"))
	fmt.Println("    " + pterm.White("gosleek ai -i results.json -p ollama -m llama3") + "  " + pterm.Gray("# 使用本地 Ollama"))
	fmt.Println("    " + pterm.White("gosleek ai -i results.json -v") + "                  " + pterm.Gray("# 显示详细建议"))
	fmt.Println("    " + pterm.White("gosleek ai -i results.json -u https://api.openai.com/v1 -k sk-xxx") + "  " + pterm.Gray("# 指定 OpenAI"))
	fmt.Println()
}

func showWorkerHelp() {
	pterm.Println()
	pterm.Println(pterm.Bold.Sprint("  用法: gosleek worker [选项]"))
	fmt.Println()
	pterm.Println(pterm.Bold.Sprint("  选项:"))
	pterm.Println(pterm.Gray(strings.Repeat("─", 55)))
	printHelpRow("  --id <id>", "  Worker 节点 ID（必填）")
	printHelpRow("  -a, --addr <addr>", "  监听地址（默认: :19234）")
	printHelpRow("  -T, --templates <dir>", "  模板目录（默认: templates）")
	printHelpRow("  --config <path>", "  配置文件路径")
	printHelpRow("  -v, --verbose", "  详细输出")
	printHelpRow("  -vv", "  极详细输出")
	printHelpRow("  --silent", "  静默模式")
	printHelpRow("  -h, --help", "  显示帮助信息")
	pterm.Println(pterm.Gray(strings.Repeat("─", 55)))
	fmt.Println()
	pterm.Println(pterm.Bold.Sprint("  示例:"))
	pterm.Println(pterm.Gray(strings.Repeat("─", 55)))
	fmt.Println("    " + pterm.White("gosleek worker --id worker-1") + "            " + pterm.Gray("# 启动 Worker（默认端口 19234）"))
	fmt.Println("    " + pterm.White("gosleek worker --id w1 -a :8081") + "  " + pterm.Gray("# 指定端口"))
	fmt.Println("    " + pterm.White("gosleek worker --id w1 -T /path/to/templates") + " " + pterm.Gray("# 指定模板目录"))
	fmt.Println()
}

func showMasterHelp() {
	pterm.Println()
	pterm.Println(pterm.Bold.Sprint("  用法: gosleek master [选项]"))
	fmt.Println()
	pterm.Println(pterm.Bold.Sprint("  选项:"))
	pterm.Println(pterm.Gray(strings.Repeat("─", 55)))
	printHelpRow("  -a, --addr <addr>", "  监听地址（默认: :19234）")
	printHelpRow("  -T, --templates <dir>", "  模板目录（默认: templates）")
	printHelpRow("  --config <path>", "  配置文件路径")
	printHelpRow("  -v, --verbose", "  详细输出")
	printHelpRow("  -vv", "  极详细输出")
	printHelpRow("  --silent", "  静默模式")
	printHelpRow("  -h, --help", "  显示帮助信息")
	pterm.Println(pterm.Gray(strings.Repeat("─", 55)))
	fmt.Println()
	pterm.Println(pterm.Bold.Sprint("  示例:"))
	pterm.Println(pterm.Gray(strings.Repeat("─", 55)))
	fmt.Println("    " + pterm.White("gosleek master") + "              " + pterm.Gray("# 启动 Master（默认端口 19234）"))
	fmt.Println("    " + pterm.White("gosleek master -a :8081") + "  " + pterm.Gray("# 指定端口"))
	fmt.Println("    " + pterm.White("gosleek master -T /path/to/templates") + " " + pterm.Gray("# 指定模板目录"))
	fmt.Println()
	pterm.Println(pterm.Bold.Sprint("  工作流程:"))
	fmt.Println("    " + pterm.Cyan("1") + ". 启动 Master:  " + pterm.White("gosleek master"))
	fmt.Println("    " + pterm.Cyan("2") + ". 启动 Worker:  " + pterm.White("gosleek worker --id w1"))
	fmt.Println("    " + pterm.Cyan("3") + ". 扫描目标:     " + pterm.White("gosleek scan -t http://target -d master"))
	fmt.Println()
}

// ────────────────────────────────────────────────────────────────────────
// Path helpers
// ────────────────────────────────────────────────────────────────────────
func computeVerbosity(c *cobra.Command, allArgs []string) int {
	// Cobra silently converts -vv to -v -v (two separate -v flags).
	// Detect -vv by scanning raw args for the literal token.
	for _, a := range allArgs {
		if a == "-vv" || a == "--vv" {
			return 2
		}
	}
	if c.Flags().Changed("silent") || c.PersistentFlags().Changed("silent") {
		return -1
	}
	if c.Flags().Changed("verbose") || c.Flags().Changed("v") ||
		c.PersistentFlags().Changed("verbose") || c.PersistentFlags().Changed("v") {
		return 1
	}
	return 0
}

func filepathExt(path string) string { return filepath.Ext(path) }
func filepathWalk(root string, fn filepath.WalkFunc) error { return filepath.Walk(root, fn) }

// webuiClient pushes scan results to a remote Web UI server via HTTP POST.
type webuiClient struct {
	baseURL string
	client  *http.Client
	taskID  string // 当前任务 ID，用于关联结果和任务
	console *output.Console // 统一日志输出
	retry   int             // 重试次数
}

func newWebUIClient(baseURL string, console *output.Console) *webuiClient {
	return &webuiClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		console: console,
		retry:   3,
	}
}

// SetTaskID 设置任务 ID（由 scanner 回调）。
func (c *webuiClient) SetTaskID(id string) {
	c.taskID = id
}

// PushTaskCreate 创建扫描任务并推送给 WebUI。
// 带重试逻辑：最多重试 retry 次，失败时生成本地 fallback ID。
func (c *webuiClient) PushTaskCreate(name string, targets []string, onCreated func(id string)) {
	payload := struct {
		Name      string   `json:"name"`
		Targets   []string `json:"targets"`
		Templates []string `json:"templates"`
	}{
		Name:    name,
		Targets: targets,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		if c.console != nil {
			c.console.PrintWarning("WebUI 任务创建: JSON 序列化失败: %v", err)
		}
		return
	}

	url := c.baseURL + "/api/tasks"
	for i := 0; i < c.retry; i++ {
		req, err := http.NewRequest("POST", url, bytes.NewReader(data))
		if err != nil {
			if c.console != nil {
				c.console.PrintWarning("WebUI 任务创建 (第 %d 次): 创建请求失败: %v", i+1, err)
			}
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.client.Do(req)
		if err != nil {
			if c.console != nil {
				c.console.PrintWarning("WebUI 任务创建 (第 %d 次): HTTP 请求失败: %v", i+1, err)
			}
			// 短暂等待后重试
			time.Sleep(time.Duration(i+1) * 500 * time.Millisecond)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusCreated {
			var result struct {
				ID string `json:"id"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&result)
			if result.ID != "" {
				if c.console != nil {
					c.console.PrintInfo("WebUI 任务已创建: %s", result.ID)
				}
				onCreated(result.ID)
				return
			}
		}

		if c.console != nil {
			c.console.PrintWarning("WebUI 任务创建 (第 %d 次): 服务器返回状态码 %d", i+1, resp.StatusCode)
		}
		// 等待后重试
		time.Sleep(time.Duration(i+1) * 500 * time.Millisecond)
	}

	// 所有重试均失败，生成本地 fallback ID
	fallbackID := fmt.Sprintf("task-fallback-%d", time.Now().UnixNano())
	if c.console != nil {
		c.console.PrintWarning("WebUI 任务创建失败: 使用本地 ID %s 兜底", fallbackID)
	}
	onCreated(fallbackID)
}

// PushTaskComplete 推送任务完成状态。
func (c *webuiClient) PushTaskComplete(resultCount, total, matched int) {
	if c.taskID == "" {
		if c.console != nil {
			c.console.PrintWarning("WebUI 任务完成: 无任务 ID，跳过")
		}
		return
	}
	payload := struct {
		ResultCount int `json:"result_count"`
		Total       int `json:"total"`
		Matched     int `json:"matched"`
	}{
		ResultCount: resultCount,
		Total:       total,
		Matched:     matched,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		if c.console != nil {
			c.console.PrintWarning("WebUI 任务完成: JSON 序列化失败: %v", err)
		}
		return
	}
	url := fmt.Sprintf("%s/api/tasks/%s/complete", c.baseURL, c.taskID)
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		if c.console != nil {
			c.console.PrintWarning("WebUI 任务完成: 创建请求失败: %v", err)
		}
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		if c.console != nil {
			c.console.PrintWarning("WebUI 任务完成: HTTP 请求失败: %v", err)
		}
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if c.console != nil {
			c.console.PrintWarning("WebUI 任务完成: 服务器返回状态码 %d", resp.StatusCode)
		}
	} else if c.console != nil {
		c.console.PrintInfo("WebUI 任务已完成: %s", c.taskID)
	}
}

func (c *webuiClient) PushResult(r *types.Result) {
	payload := struct {
		TemplateID  string    `json:"template-id"`
		Name        string    `json:"name"`
		Severity    string    `json:"severity"`
		Target      string    `json:"target"`
		MatchedAt   string    `json:"matched-at"`
		Evidence    string    `json:"evidence,omitempty"`
		Timestamp   string    `json:"timestamp"`
		RawRequest  string    `json:"raw-request,omitempty"`
		RawResponse string    `json:"raw-response,omitempty"`
	}{
		TemplateID:  r.TemplateID,
		Name:        r.Name,
		Severity:    r.Severity,
		Target:      r.Target,
		MatchedAt:   r.MatchedAt,
		Evidence:    r.Evidence,
		Timestamp:   r.Timestamp.Format(time.RFC3339),
		RawRequest:  r.RawRequest,
		RawResponse: r.RawResponse,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		if c.console != nil {
			c.console.PrintWarning("WebUI 结果推送: JSON 序列化失败: %v", err)
		}
		return
	}
	req, err := http.NewRequest("POST", c.baseURL+"/api/results", bytes.NewReader(data))
	if err != nil {
		if c.console != nil {
			c.console.PrintWarning("WebUI 结果推送: 创建请求失败: %v", err)
		}
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		if c.console != nil {
			c.console.PrintWarning("WebUI 结果推送: HTTP 请求失败: %v", err)
		}
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		if c.console != nil {
			c.console.PrintWarning("WebUI 结果推送: 服务器返回状态码 %d", resp.StatusCode)
		}
	} else if c.console != nil {
		c.console.PrintInfo("WebUI 结果已推送: %s [%s] %s", r.Name, r.Severity, r.Target)
	}
}
