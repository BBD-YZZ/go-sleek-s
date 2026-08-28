package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gosleek/gosleek/internal/config"
	"github.com/gosleek/gosleek/internal/engine"
	"github.com/gosleek/gosleek/internal/httpclient"
	"github.com/gosleek/gosleek/internal/output"
	"github.com/gosleek/gosleek/internal/plugin"
	"github.com/gosleek/gosleek/internal/template"
	"github.com/gosleek/gosleek/pkg/types"
)

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr) // 抑制 Go 默认的 Usage 输出

	target := fs.String("t", "", "单个目标 URL (可多次)")
	targetsFile := fs.String("l", "", "目标列表文件（每行一个 URL，# 开头为注释）")
	stdinTargets := fs.Bool("stdin", false, "从 stdin 读取目标列表（管道输入）")
	templatesDir := fs.String("T", "templates", "模板目录（默认: templates）")
	templateID := fs.String("id", "", "指定漏洞 ID（同时作用于模板和插件）")
	tags := fs.String("tags", "", "按标签筛选模板")
	severity := fs.String("severity", "", "按严重度筛选 (info,low,medium,high,critical)")
	exclude := fs.String("e", "", "排除指定模板 ID")
	outputFile := fs.String("o", "", "结果写入文件")
	outputFormat := fs.String("format", "json", "输出格式: json, txt, sarif, html, csv, markdown")
	outputDir := fs.String("output-dir", "", "结果输出目录（自动生成时间戳文件名）")
	verbose := fs.Bool("v", false, "详细输出（每步进度、跳过原因、信息提示）")
	verbose2 := fs.Bool("vv", false, "极详细输出（每个请求/响应详情、matcher 命中细节）")
	silent := fs.Bool("silent", false, "静默模式")
	concurrency := fs.Int("c", 25, "并发数（默认: 25）")
	rateLimit := fs.Int("r", 150, "每秒请求限制（默认: 150）")
	timeout := fs.Int("timeout", 10, "请求超时秒数")
	proxy := fs.String("proxy", "", "HTTP/SOCKS5 代理 (支持认证)")
	verifySSL := fs.Bool("k", false, "启用 TLS 证书校验 (默认: 跳过)")
	followRedirects := fs.Bool("follow-redirects", true, "全局跟随重定向")
	oob := fs.Bool("oob", false, "启用 OOB 占位符（注入 {{oob}} {{oob_label}}）")
	allowExternal := fs.Bool("allow-external-hosts", false, "允许 Host 头重定向到外部主机（OOB 必须开启）")
	resumeFile := fs.String("resume", "", "从保存的状态断点续扫")
	logFile := fs.String("log-file", "", "将结构化日志以 JSON 写入指定文件")
	logLevel := fs.String("log-level", "", "日志最小级别: debug/info/warn/error (默认随 -v/-vv 自动)")
	pluginsOnly := fs.Bool("plugins-only", false, "仅使用 Go 插件扫描 (不加载 YAML 模板)")
	pluginID := fs.String("plugin", "", "指定 Go 插件 ID 扫描 (等价 --plugins-only -id)")
	redact := fs.Bool("redact", false, "脱敏输出 (遮蔽证据中的密钥/token)")
	_ = *redact
	filterSeverity := fs.String("filter-severity", "", "结果过滤: 仅保留指定严重度")
	filterTags := fs.String("filter-tags", "", "结果过滤: 仅保留指定标签")
	wordlistDir := fs.String("wordlist-dir", "wordlists", "wordlist 文件基础目录 (默认: wordlists)")

	// Track OOB provider explicitly set by user (vs default value "ceye")
	oobProviderExplicitlySet := false
	oobProviderValue := "ceye" // default
	fs.Func("oob-provider", "OOB 提供商: ceye(默认) / dnslog / callbackred", func(v string) error {
		oobProviderExplicitlySet = true
		oobProviderValue = v
		return nil
	})
	ceyeKeyExplicitlySet := false
	ceyeKeyValue := ""
	fs.Func("ceye-key", "ceye.io API Token", func(v string) error {
		ceyeKeyExplicitlySet = true
		ceyeKeyValue = v
		return nil
	})
	ceyeDomainExplicitlySet := false
	ceyeDomainValue := ""
	fs.Func("ceye-domain", "ceye.io 识别域名（如 abc.ceye.io）", func(v string) error {
		ceyeDomainExplicitlySet = true
		ceyeDomainValue = v
		return nil
	})

	var headers []string
	fs.Func("H", "全局请求头注入 (可多次)", func(v string) error {
		headers = append(headers, v)
		return nil
	})

	// Handle -h/--help
	var showHelp bool
	fs.BoolFunc("h", "显示帮助信息", func(_ string) error {
		showHelp = true
		return nil
	})
	fs.BoolFunc("help", "显示帮助信息", func(_ string) error {
		showHelp = true
		return nil
	})

	// Parse flags, show banner first so it appears on errors too
	output.PrintBannerRaw("1.0.1")
	err := fs.Parse(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr)
		printScanHelp()
		os.Exit(1)
	}

	if showHelp {
		printScanHelp()
		return
	}

	verb := 0
	if *verbose2 {
		verb = 2
	} else if *verbose {
		verb = 1
	}
	if *silent {
		verb = -1
	}

	cfg := config.DefaultConfig()
	cfgPath := findConfig()
	if cfgPath != "" {
		if loaded, err := config.Load(cfgPath); err == nil {
			cfg = loaded
		}
	}
	if *rateLimit > 0 {
		cfg.RateLimit = *rateLimit
	}
	if *timeout > 0 {
		cfg.DefaultTimeout = *timeout
	}
	if *concurrency > 0 {
		cfg.Concurrency = *concurrency
	}

	// Use config values as defaults for flags that weren't explicitly set
	if *templatesDir == "templates" && cfg.TemplateDir != "" {
		templatesDir = &cfg.TemplateDir
	}
	if !*followRedirects && cfg.AllowExternal {
		// CLI explicitly disabled redirects — nothing to do
	} else if *followRedirects && !cfg.FollowRedirect {
		// CLI at default (true) but config says false — respect config
		followRedirects = &cfg.FollowRedirect
	}
	if !*allowExternal && cfg.AllowExternal {
		allowExternal = &cfg.AllowExternal
	}
	if !*oob && cfg.OOB.Enabled {
		// config.yaml oob.enabled=true 时，使用 config 的配置
		oob = &cfg.OOB.Enabled
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
	if *target != "" {
		targets = append(targets, *target)
	}
	if *targetsFile != "" {
		if t, err := readTargetsFile(*targetsFile); err == nil {
			targets = append(targets, t...)
		}
	}
	if (*stdinTargets || *targetsFile == "") && len(targets) == 0 {
		if t, err := readTargetsStdin(); err == nil {
			targets = append(targets, t...)
		}
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "未指定目标，使用 -t <url> 或 -l <file> 指定")
		os.Exit(1)
	}

	var tmplList []*types.Template
	if !*pluginsOnly {
		var idFilter []string
		if *templateID != "" {
			idFilter = []string{*templateID}
		}
		var sevFilter []string
		if *severity != "" {
			sevFilter = []string{*severity}
		}
		var tagFilter []string
		if *tags != "" {
			tagFilter = strings.Split(*tags, ",")
		}
		var excludeFilter []string
		if *exclude != "" {
			excludeFilter = strings.Split(*exclude, ",")
		}
		if loaded, err := template.LoadDir(*templatesDir); err == nil {
			tmplList = template.ExcludeByID(template.FilterBySeverity(template.FilterByTag(template.FilterByID(loaded, idFilter), tagFilter), sevFilter), excludeFilter)
		}
	}

	// 加载插件（无论是否 plugins-only，先获取全部插件）
	allPlugins := plugin.All()
	// 当指定了 --plugin 或 --id 时，对插件做筛选；否则使用全部插件
	pluginFilterID := *pluginID
	if pluginFilterID == "" && *templateID != "" {
		pluginFilterID = *templateID
	}
	var pluginFilterIDs []string
	if pluginFilterID != "" {
		pluginFilterIDs = []string{pluginFilterID}
	}
	var filterTagsList []string
	if *tags != "" {
		filterTagsList = strings.Split(*tags, ",")
	}
	var filterSevList []string
	if *severity != "" {
		filterSevList = []string{*severity}
	}
	var filterExcludeList []string
	if *exclude != "" {
		filterExcludeList = strings.Split(*exclude, ",")
	}
	pluginList := plugin.Filter(allPlugins, plugin.FilterOptions{
		PluginIDs:  pluginFilterIDs,
		Tags:       filterTagsList,
		Severity:   filterSevList,
		ExcludeIDs: filterExcludeList,
	})
	// 如果是 plugins-only 模式或指定了 --plugin，清空模板列表
	if *pluginsOnly || *pluginID != "" {
		tmplList = nil
	}

	if len(tmplList) == 0 && len(pluginList) == 0 {
		fmt.Fprintln(os.Stderr, "未找到匹配的模板或插件")
		os.Exit(1)
	}

	console := output.NewConsole(verb)

	if verb >= 0 {
		console.PrintDisclaimer()
	}

	// OOB config: 优先级 CLI > config.yaml
	oobCfg := engine.OOBConfig{}
	oobValid := false
	oobNeedsCount := 0 // 需要 OOB 的模板/插件数量
	if *oob || cfg.OOB.Enabled {
		oobCfg.Provider = oobProviderValue
		oobCfg.CeyeToken = ceyeKeyValue
		oobCfg.CeyeDomain = ceyeDomainValue
		oobCfg.AllowExternal = *allowExternal

		// 验证 OOB 配置完整性
		if oobCfg.Provider == "ceye" {
			if oobCfg.CeyeToken != "" && oobCfg.CeyeDomain != "" {
				oobValid = true
			}
		} else if oobCfg.Provider == "dnslog" || oobCfg.Provider == "callbackred" {
			oobValid = true
		}
	}

	// 统计需要 OOB 的模板/插件数量
	if !*pluginsOnly {
		for _, tmpl := range tmplList {
			if engine.TemplateNeedsOOB(tmpl) {
				oobNeedsCount++
			}
		}
	}
	// 检查插件是否需要 OOB
	for _, p := range pluginList {
		if p.NeedsOOB() {
			oobNeedsCount++
		}
	}

	// Build HTTP client
	clientCfg := httpclient.ClientConfig{
		Timeout:        time.Duration(cfg.DefaultTimeout) * time.Second,
		RateLimit:      cfg.RateLimit,
		UserAgent:      cfg.UserAgent,
		MaxRedirects:   cfg.MaxRedirects,
		Proxy:          *proxy,
		Insecure:       !*verifySSL,
		FollowRedirect: *followRedirects,
		MaxBodySize:    cfg.MaxBodySize,
	}
	client := httpclient.New(clientCfg)
	_ = client // client used internally by scanner

	// Create scanner
	scanner := engine.NewScanner(cfg, verb, oobCfg, *proxy, !*verifySSL)
	scanner.SetWordlistDir(*wordlistDir)

	// Inject global headers
	if len(headers) > 0 {
		hmap := parseHeaders(headers)
		scanner.SetGlobalHeaders(hmap)
	}

	// Resume state
	var resumeState *engine.ResumeState
	if *resumeFile != "" {
		resumeState = engine.NewResumeState(*resumeFile)
		scanner.SetResumeState(resumeState)
	}

	// Output writer
	if *outputFile != "" {
		output.WriteFile(nil, *outputFile, *outputFormat)
	} else if *outputDir != "" {
		dir := setupOutputDir(*outputDir)
		output.WriteFile(nil, dir+"/results."+*outputFormat, *outputFormat)
	}

	// Callbacks
	onResult := func(r *types.Result) {
		console.PrintResult(r)
		if *outputFile != "" {
			output.WriteFile([]*types.Result{r}, *outputFile, *outputFormat)
		}
	}
	onProgress := func(completed, total int64, msg string) {
		console.PrintProgress(completed, total, msg)
	}
	onVerbose := func(format string, args ...interface{}) {
		console.PrintVerb(format, args...)
	}
	onDebug := func(format string, args ...interface{}) {
		console.PrintDebug(format, args...)
	}
	onRaw := func(tag, format string, args ...interface{}) {
		console.PrintRaw(tag, 2, format, args...)
	}
	onPacket := func(tag, summary, raw string) {
		console.PrintPacket(tag, 2, summary, raw)
	}
	scanner.SetCallbacks(onResult, onProgress, onVerbose, onDebug, onRaw, onPacket)

	// Logger — 始终初始化 logger，确保插件在 -v/-vv 时能输出日志（即使没有 --log-file）
	// 优先级: CLI flag > config.yaml > 默认值
	actualLogFile := *logFile
	actualLogLevel := *logLevel
	if actualLogFile == "" && cfg.LogFile != "" {
		actualLogFile = cfg.LogFile
	}
	if actualLogLevel == "" && cfg.LogLevel != "" {
		actualLogLevel = cfg.LogLevel
	}
	if actualLogFile != "" {
		logger := output.NewLogger(actualLogFile, actualLogLevel, verb)
		scanner.SetLogger(logger)
	} else if verb >= 0 {
		// 无 log-file 但有 -v/-vv 时，创建无文件输出的 logger，确保插件有日志能力
		logger := output.NewLogger("", actualLogLevel, verb)
		scanner.SetLogger(logger)
	}

	// Post-scan filters
	var filterSev, filterTagList []string
	if *filterSeverity != "" {
		filterSev = strings.Split(*filterSeverity, ",")
	}
	if *filterTags != "" {
		filterTagList = strings.Split(*filterTags, ",")
	}

	// OOB 警告：如果启用了 OOB 但配置不完整，或需要 OOB 但未启用
	if oobNeedsCount > 0 && !oobValid {
		var missing []string
		if !(*oob || cfg.OOB.Enabled) {
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
		} else if !(*oob || cfg.OOB.Enabled) {
			console.PrintOOBWarning(oobNeedsCount, "", nil)
		}
	}

	// Print config panel
	console.PrintScanConfig(output.ScanConfigInfo{
		Targets:      len(targets),
		Templates:    len(tmplList),
		Plugins:      len(pluginList),
		Concurrency:  cfg.Concurrency,
		RateLimit:    cfg.RateLimit,
		Timeout:      cfg.DefaultTimeout,
		OOBEnabled:   *oob || cfg.OOB.Enabled,
		OOBValid:     oobValid,
		OOBDomain:    oobCfg.CeyeDomain,
		OOBProvider:  oobCfg.Provider,
		Proxy:        *proxy,
		OutputFile:   *outputFile,
		OutputFormat: *outputFormat,
	})

	console.PrintScanStart(len(targets), len(tmplList), len(pluginList))

	// Run scan
	results := scanner.Run(context.Background(), tmplList, pluginList, targets)

	// Apply filters
	var filtered []*types.Result
	for _, r := range results {
		if matchSeverityFilter(r.Severity, filterSev) && matchTagsFilter(r.Tags, filterTagList) {
			filtered = append(filtered, r)
		}
	}

	console.PrintScanEnd(int64(len(results)), int64(len(filtered)))
	console.PrintVulnSummary(filtered)

	if *outputFile != "" {
		console.PrintSaved(*outputFile, *outputFormat)
	}
	if resumeState != nil {
		resumeState.Save()
	}
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

