package engine

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gosleek/gosleek/internal/config"
	"github.com/gosleek/gosleek/internal/fingerprint"
	"github.com/gosleek/gosleek/internal/httpclient"
	"github.com/gosleek/gosleek/internal/matcher"
	oobpkg "github.com/gosleek/gosleek/internal/oob"
	"github.com/gosleek/gosleek/internal/placeholder"
	"github.com/gosleek/gosleek/internal/plugin"
	"github.com/gosleek/gosleek/internal/workflow"
	"github.com/gosleek/gosleek/pkg/types"
	"github.com/pterm/pterm"
)

// JobKind distinguishes YAML template jobs from Go plugin jobs.
type JobKind int

const (
	JobKindTemplate JobKind = iota // YAML 模板
	JobKindPlugin                  // Go 插件
)

// Job represents a single (target, template) scan unit.
type Job struct {
	Target   string
	Kind     JobKind
	Template *types.Template // Kind == JobKindTemplate
	Plugin   plugin.Plugin   // Kind == JobKindPlugin
}

// Scanner is the core scanning engine.
//
// OOB handling: the engine no longer performs automatic OOB polling.
// OOB templates must use the workflow form: earlier steps trigger the
// vulnerability (with {{oob}} substituted as the callback domain) and the
// last step performs an HTTP GET against the ceye API with body matchers.
// The engine simply injects three placeholders into every OOB template:
//   {{oob}}         - unique callback subdomain (e.g. gs-a1b2c3d4.foo.ceye.io)
//   {{oob_label}}   - the bare label (e.g. gs-a1b2c3d4) for API filter
//   {{oob_token}}   - provider-specific credential (ceye token / dnslog PHPSESSID / callbackred key)
//   {{oob_domain}}  - provider-specific domain (ceye domain / dnslog base domain / callbackred base)
type Scanner struct {
	client      *httpclient.Client
	fingerprint *fingerprint.Detector
	cfg         *config.GlobalConfig
	verbose     int
	logger      LoggerIface // optional structured logger (pterm-styled)

	// OOB placeholders injected for every template
	oobProvider oobpkg.Provider
	oobAvailable bool
	oobLabel     string
	oobDomain    string

	// Per-template OOB provider cache: templateID → provider
	oobProviderCache sync.Map // map[string]oobpkg.Provider

	// Global CLI options
	globalHeaders   map[string]string // injected into every request
	followRedirects bool              // true = always follow, false = never
	wordlistDir     string            // base dir for wordlist files

	// dedup: "target|templateID" → bool
	dedup sync.Map

	// A3: resume state injected by main.go before Run()
	resumeState *ResumeState

	// stats — [批次A-7 修复点] 使用 int64 配合 atomic 操作,
	// 旧实现的 completed++/matched++ 在多 goroutine 下存在数据竞争。
	totalJobs int64
	completed int64
	matched   int64

	// progress tracking
	progressStart time.Time
	onProgress    func(completed, total int64, msg string)

	// callbacks
	onResult   func(*types.Result)
	onVerbose  func(format string, args ...interface{}) // -v level
	onDebug    func(format string, args ...interface{}) // -vv level (调试 tag)
	onRaw      func(tag, format string, args ...interface{}) // -vv level (匹配 tag)
	onPacket   func(tag string, summary string, raw string)  // -vv level (请求/响应 Burp-style)
}

// NewScanner creates a scanner with the given config.
func NewScanner(cfg *config.GlobalConfig, verbose int, oob OOBConfig, proxy string, insecure bool) *Scanner {
	clientCfg := httpclient.ClientConfig{
		Timeout:        time.Duration(cfg.DefaultTimeout) * time.Second,
		MaxRetries:     cfg.MaxRetries,
		Backoff:        parseDuration(cfg.RetryBackoff),
		RateLimit:      cfg.RateLimit,
		UserAgent:      cfg.UserAgent,
		MaxRedirects:   cfg.MaxRedirects,
		MaxBodySize:    cfg.MaxBodySize,
		Proxy:          proxy,
		Insecure:       insecure,
		FollowRedirect: true, // default: follow redirects up to MaxRedirects
		AllowExternal:  oob.AllowExternal,
	}
	client := httpclient.New(clientCfg)
	fp := fingerprint.New(client)

	return &Scanner{
		client:       client,
		fingerprint:  fp,
		cfg:          cfg,
		verbose:      verbose,
		oobProvider:  oobpkg.NewOobProvider(oob.Provider, oob.CeyeToken),
		oobAvailable: oob.Label != "", // OOB enabled when label is configured (ceye needs token+domain, auto-probe providers are always available)
		oobLabel:     oob.Label,
		oobDomain:    oob.CeyeDomain,
		globalHeaders: make(map[string]string),
	}
}

// SetGlobalHeaders injects headers into every request for the duration of a scan.
// Headers are also propagated to the HTTP client so plugins get them via SendRaw.
func (s *Scanner) SetGlobalHeaders(h map[string]string) {
	s.globalHeaders = h
	s.client.SetGlobalHeaders(h)
}

// SetFollowRedirects controls whether redirects are followed globally.
func (s *Scanner) SetFollowRedirects(follow bool) {
	s.followRedirects = follow
}

// SetWordlistDir sets the base directory for resolving wordlist file paths.
func (s *Scanner) SetWordlistDir(dir string) {
	s.wordlistDir = dir
}

// SetProgressCallback sets the progress reporting function.
func (s *Scanner) SetProgressCallback(fn func(completed, total int64, msg string)) {
	s.onProgress = fn
}

// LoggerIface is a minimal subset of output.Logger, declared here so the
// engine package can accept a logger without importing the output package
// (which imports pterm, and keeps the engine testable with a stub).
type LoggerIface interface {
	DebugKV(msg string, args ...interface{})
	InfoKV(msg string, args ...interface{})
	WarnKV(msg string, args ...interface{})
	Error(msg string, args ...interface{})
}

// SetLogger attaches a structured logger to the scanner.
func (s *Scanner) SetLogger(l LoggerIface) { s.logger = l }

// getOOBProvider returns the OOB provider for a template, respecting per-template overrides.
// Falls back to the global provider if the template doesn't specify one,
// or if the template's provider matches the global provider.
func (s *Scanner) getOOBProvider(tmpl *types.Template) oobpkg.Provider {
	if tmpl != nil && tmpl.OOBProvider != "" {
		// If template specifies the same provider as global, use global (already initialized)
		if s.oobProvider != nil && tmpl.OOBProvider == s.oobProvider.Name() {
			return s.oobProvider
		}
		// Otherwise create/use per-template provider
		if p, ok := s.oobProviderCache.Load(tmpl.ID); ok {
			return p.(oobpkg.Provider)
		}
		p := oobpkg.NewOobProvider(tmpl.OOBProvider, s.cfg.OOB.Ceye.Token)
		s.oobProviderCache.Store(tmpl.ID, p)
		return p
	}
	return s.oobProvider
}

// getOOBConfig returns the OOB config (label/domain/token) for a template.
func (s *Scanner) getOOBConfig(tmpl *types.Template) (label, domain, token string) {
	if tmpl != nil && tmpl.OOBProvider != "" {
		p := s.getOOBProvider(tmpl)
		return p.Label(), p.CallbackURL(), p.Token()
	}
	return s.oobLabel, s.oobDomain, s.cfg.OOB.Ceye.Token
}

// isOOBProviderAvailable checks if an OOB provider has been successfully initialized.
func (s *Scanner) isOOBProviderAvailable(p oobpkg.Provider) bool {
	if p == nil {
		return false
	}
	// For ceye: label must be set
	if p.Name() == "ceye" {
		return p.Label() != ""
	}
	// For dnslog/callbackred: always available (auto-probe)
	return true
}
// main.go calls this before Run().
func (s *Scanner) SetResumeState(rs *ResumeState) { s.resumeState = rs }

// OOBConfig carries the OOB configuration into the scanner.
type OOBConfig struct {
	Provider      string // "ceye" / "dnslog" / "callbackred"
	Label         string // for ceye: gs-xxxxxxxx; for others: auto-generated
	CeyeToken     string // ceye API token (only used for ceye provider)
	CeyeDomain    string // ceye domain (only used for ceye provider)
	AllowExternal bool   // whether to allow Host header redirect to external hosts
}

// SetCallbacks registers result/progress/debug callbacks.
func (s *Scanner) SetCallbacks(
	onResult func(*types.Result),
	onProgress func(int64, int64, string),
	onVerbose func(string, ...interface{}),
	onDebug func(string, ...interface{}),
	onRaw func(tag, format string, args ...interface{}),
	onPacket func(tag string, summary string, raw string),
) {
	s.onResult = onResult
	s.onProgress = onProgress
	s.onVerbose = onVerbose
	s.onDebug = onDebug
	s.onRaw = onRaw
	s.onPacket = onPacket
}

// Run executes the scan with the given templates and plugins against targets.
func (s *Scanner) Run(ctx context.Context, templates []*types.Template, plugins []plugin.Plugin, targets []string) []*types.Result {
	// Initialize OOB provider (Probe for dnslog/callbackred, Setup for ceye)
	if s.oobProvider != nil {
		// Wire shared client and callbacks for request/response logging
		s.oobProvider.SetClient(s.client)
		s.oobProvider.SetVerbose(s.verbose, s.onPacket, s.onRaw)
		s.oobProvider.SetAPIConfig(s.cfg.OOB.Ceye.APIURL, s.cfg.OOB.Ceye.PollInterval, s.cfg.OOB.Ceye.PollTimeout)
		// Call Setup with the configured label/domain (no-op for auto-probe providers)
		s.oobProvider.Setup(s.oobLabel, s.oobDomain)
		if err := s.oobProvider.Probe(ctx); err != nil {
			s.verbosef("OOB provider (%s) probe failed: %v", s.oobProvider.Name(), err)
			s.oobProvider = nil
			s.oobAvailable = false
		} else {
			s.verbosef("OOB provider initialized: %s (label=%s, url=%s)", s.oobProvider.Name(), s.oobProvider.Label(), s.oobProvider.CallbackURL())
		}
	}

	// Initialize per-template OOB providers if needed
	for _, t := range templates {
		if t.OOBProvider != "" && t.OOBProvider != s.oobProvider.Name() {
			p := s.getOOBProvider(t)
			if p != nil {
				p.SetClient(s.client)
				p.SetVerbose(s.verbose, s.onPacket, s.onRaw)
				p.SetAPIConfig(s.cfg.OOB.Ceye.APIURL, s.cfg.OOB.Ceye.PollInterval, s.cfg.OOB.Ceye.PollTimeout)
				p.Setup(s.oobLabel, s.oobDomain)
				if err := p.Probe(ctx); err != nil {
					s.debug("OOB provider %s probe failed for template %s: %v", p.Name(), t.ID, err)
					// Remove failed provider from cache
					s.oobProviderCache.Delete(t.ID)
				}
			}
		}
	}

	// D5: Check for ID collisions between templates and plugins
	seenIDs := make(map[string]string) // id → source
	for _, t := range templates {
		if prev, ok := seenIDs[t.ID]; ok {
			if s.onVerbose != nil {
				s.onVerbose("WARNING: ID collision '%s' between template and %s", t.ID, prev)
			}
		}
		seenIDs[t.ID] = "template"
	}
	for _, p := range plugins {
		meta := p.Meta()
		if prev, ok := seenIDs[meta.ID]; ok {
			if s.onVerbose != nil {
				s.onVerbose("WARNING: ID collision '%s' between plugin and %s", meta.ID, prev)
			}
		}
		seenIDs[meta.ID] = "plugin"
	}

	var allResults []*types.Result
	resultsCh := make(chan *types.Result, 256)

	// Collector goroutine
	var collectorWG sync.WaitGroup
	collectorWG.Add(1)
	go func() {
		defer collectorWG.Done()
		for r := range resultsCh {
			allResults = append(allResults, r)
			if s.onResult != nil {
				s.onResult(r)
			}
		}
	}()

	jobs := make(chan Job, 1024) // bounded queue = backpressure
	total := (len(templates) + len(plugins)) * len(targets)
	s.totalJobs = int64(total)

	concurrency := s.cfg.Concurrency
	if concurrency <= 0 {
		concurrency = 25
	}

	// A3: Periodic resume saver — main thread wires in the resume state
	// and the Run function returns a saverFunc for main to call after scan end.
	resumeState := s.resumeState

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for job := range jobs {
				if ctx.Err() != nil {
					return
				}
				s.runJob(ctx, job, resultsCh)
				done := atomic.AddInt64(&s.completed, 1)
				// A3: periodic save — atomically check throttle and save to avoid TOCTOU race.
				if resumeState != nil && resumeState.TrySave() {
					if s.logger != nil {
						s.logger.InfoKV("resume state saved", "file", resumeState.filePath)
					}
				}
				if s.onProgress != nil {
					var id string
					if job.Kind == JobKindPlugin {
						id = job.Plugin.Meta().ID
					} else {
						id = job.Template.ID
					}
					s.onProgress(done, s.totalJobs,
						fmt.Sprintf("%s vs %s", job.Target, id))
				}
			}
		}(i)
	}

	go func() {
		for _, target := range targets {
			for _, tmpl := range templates {
				select {
				case <-ctx.Done():
					goto done
				case jobs <- Job{Target: target, Kind: JobKindTemplate, Template: tmpl}:
				}
			}
			for _, p := range plugins {
				select {
				case <-ctx.Done():
					goto done
				case jobs <- Job{Target: target, Kind: JobKindPlugin, Plugin: p}:
				}
			}
			if ctx.Err() != nil {
				break
			}
		}
	done:
		close(jobs)
	}()

	wg.Wait()
	close(resultsCh)
	collectorWG.Wait()
	return allResults
}

// runJob executes a single job (YAML template or Go plugin) against a single target.
func (s *Scanner) runJob(ctx context.Context, job Job, results chan<- *types.Result) {
	target := job.Target

	// 统一 ID 用于去重和日志
	var id string
	if job.Kind == JobKindPlugin {
		id = job.Plugin.Meta().ID
	} else {
		id = job.Template.ID
	}

	// 去重: 无论成功失败都标记为已处理
	dedupKey := target + "|" + id
	if _, exists := s.dedup.LoadOrStore(dedupKey, true); exists {
		s.debug("跳过重复: %s vs %s", target, id)
		if s.logger != nil {
			s.logger.InfoKV("skip duplicate (already processed)", "target", target, "template", id)
		}
		return
	}

	if s.logger != nil {
		s.logger.InfoKV("task started", "target", target, "template", id)
	}

	// 指纹预过滤 (YAML 和 Go 插件统一)
	var fps []types.FingerprintRule
	if job.Kind == JobKindPlugin {
		fps = job.Plugin.Fingerprints()
	} else {
		fps = job.Template.Fingerprints
	}
	if len(fps) > 0 {
		fp := s.fingerprint.Detect(ctx, target)
		if !s.fingerprint.Matches(fp, fps) {
			s.debug("跳过指纹不匹配: %s vs %s", target, id)
			if s.logger != nil {
				s.logger.InfoKV("fingerprint mismatch, skip",
					"target", target, "template", id, "server", fp.Server)
			}
			return
		}
		if s.logger != nil {
			s.logger.InfoKV("fingerprint matched", "target", target, "template", id, "server", fp.Server)
		}
	}

	// OOB 预检查 (YAML 模板和需要 OOB 的 Go 插件)
	if job.Kind == JobKindTemplate && TemplateNeedsOOB(job.Template) {
		tmplProvider := s.getOOBProvider(job.Template)
		// 检查模板所需的 provider 是否已初始化
		if tmplProvider == nil || !s.isOOBProviderAvailable(tmplProvider) {
			providerName := tmplProvider.Name()
			s.debug("跳过OOB%s(%s未配置): %s", oobKindName(job), providerName, id)
			if s.logger != nil {
				s.logger.InfoKV("skip OOB template", "provider", providerName, "template", id)
			}
			return
		}
	} else if job.Kind == JobKindPlugin && job.Plugin.NeedsOOB() {
		if !s.oobAvailable || s.oobProvider == nil {
			return
		}
	}

	// 准备 placeholder 引擎
	ti := placeholder.ParseTarget(target)
	var eng *placeholder.Engine
	if job.Kind == JobKindPlugin {
		eng = placeholder.New(ti, nil)
	} else {
		eng = placeholder.New(ti, job.Template.Variables)
	}

	// 注入 OOB 占位符 (使用模板指定的 provider，或全局 provider)
	if s.oobAvailable && s.oobProvider != nil {
		if job.Kind == JobKindTemplate && job.Template != nil && job.Template.OOBProvider != "" {
			// 模板指定了 provider，使用模板的 provider
			tmplProvider := s.getOOBProvider(job.Template)
			if tmplProvider != nil {
				eng.SetOOB(tmplProvider.CallbackURL())
				eng.SetExtracted("oob_label", tmplProvider.Label())
				eng.SetExtracted("oob_token", tmplProvider.Token())
				eng.SetExtracted("oob_domain", tmplProvider.CallbackURL())
			}
		} else {
			// 使用全局 provider
			eng.SetOOB(s.oobProvider.CallbackURL())
			eng.SetExtracted("oob_label", s.oobProvider.Label())
			eng.SetExtracted("oob_token", s.oobProvider.Token())
			eng.SetExtracted("oob_domain", s.oobProvider.CallbackURL())
		}
	}

	// 执行
	var result *types.Result
	if job.Kind == JobKindPlugin {
		result = s.executePlugin(ctx, job.Plugin, target, ti, eng)
	} else if len(job.Template.Workflow) > 0 {
		result = s.executeWorkflow(ctx, job.Template, target, eng)
	} else {
		result = s.executeHTTP(ctx, job.Template, target, eng)
	}

	if result != nil {
		atomic.AddInt64(&s.matched, 1)
		results <- result
		if s.logger != nil {
			s.logger.InfoKV("matched",
				"target", target, "template", id,
				"severity", result.Severity, "evidence", result.Evidence)
		}
	} else {
		if s.logger != nil {
			s.logger.InfoKV("task completed (no match)", "target", target, "template", id)
		}
	}

	// 记录已完成任务，供断点续扫使用（覆盖 YAML 模板和 Go 插件）
	if s.resumeState != nil {
		s.resumeState.MarkDone(target, id)
	}
}

// executePlugin 构造 Context 并调用 Go 插件的 Verify 方法。
func (s *Scanner) executePlugin(ctx context.Context, p plugin.Plugin, target string, ti *placeholder.TargetInfo, eng *placeholder.Engine) *types.Result {
	// [修复] 为插件执行添加超时控制，与 YAML 模板保持一致
	pluginCtx, cancel := context.WithTimeout(ctx, time.Duration(s.cfg.DefaultTimeout)*time.Second)
	defer cancel()

	pctx := &plugin.Context{
		Target:     target,
		TargetInfo: ti,
		Client:     s.client,
		Eng:        eng,
		Vars:       make(map[string]string),
	}

	if s.oobAvailable && s.oobProvider != nil {
		// 直接传递已配置的 oobProvider，确保 OOB API 请求有日志输出
		pctx.Ceye = plugin.NewOOBHandle(s.oobProvider, s.client)
	}
	if s.logger != nil {
		pctx.Log = plugin.NewPluginLogger(p.Meta().ID, s.logger)
	}

	// 注入 Reporter：让 Go 插件能输出与 YAML 工作流一致的 Burp-style 请求/响应包日志
	pctx.Reporter = plugin.NewPluginReporter(
		p.Meta().ID,
		s.verbose,
		s.logger,
		s.onPacket,
		s.onRaw,
	)

	result, err := p.Verify(pluginCtx, pctx)  // 使用带超时的 pluginCtx
	if err != nil {
		s.debug("插件执行错误: %s → %v", p.Meta().ID, err)
		return nil
	}
	return result
}

// executeHTTP runs all HTTP request blocks and evaluates matchers.
func (s *Scanner) executeHTTP(ctx context.Context, tmpl *types.Template, target string, eng *placeholder.Engine) *types.Result {
	var reqResults []bool
	var reqEvidence []string
	allExtracted := make(map[string]string)
	// Track the raw request/response for the first matching request
	var lastRawReq, lastRawResp string

	timeout := s.cfg.DefaultTimeout
	if len(tmpl.HTTP) > 0 {
		for i, req := range tmpl.HTTP {
			select {
			case <-ctx.Done():
				return nil
			default:
			}

			reqTimeout := timeout
			if req.Timeout > 0 {
				reqTimeout = req.Timeout
			}

			if req.RunIf != "" {
				if !evalRunIf(req.RunIf, allExtracted, eng) {
					s.debug("[SKIP]   run-if false: %s req[%d]", tmpl.ID, i)
					continue
				}
			}

			rawReq := eng.ReplaceWithEscape(req.Raw)
			if rawReq == "" {
				if len(req.Path) > 0 {
					method := req.Method
					if method == "" {
						method = "GET"
					}
					// Merge per-request headers with global headers
					mergedHeaders := make(map[string]string, len(req.Headers)+len(s.globalHeaders))
					for k, v := range req.Headers {
						mergedHeaders[k] = v
					}
					for k, v := range s.globalHeaders {
						if _, exists := mergedHeaders[k]; !exists {
							mergedHeaders[k] = v
						}
					}
					// Iterate over all paths in the list
					for _, p := range req.Path {
						pathReq := buildRawFromPathWithBodyType(method, p, mergedHeaders, req.Body, req.BodyType)
						pathReq = eng.ReplaceWithEscape(pathReq)
						if pathReq == "" {
							continue
						}

						// Wordlist injection (multiple wordlists → cartesian product)
						var wordlistCombinations [][]string
						if len(req.Wordlist) > 0 {
							wordlistCombinations = buildWordlistCombinations(s, req.Wordlist)
						}
						if len(wordlistCombinations) > 0 {
							for _, combo := range wordlistCombinations {
								select {
								case <-ctx.Done():
									return nil
								default:
								}
								lineReq := pathReq
								for j, wd := range req.Wordlist {
									phKey := "{{" + wd.Key + "}}"
									if j < len(combo) {
										lineReq = strings.ReplaceAll(lineReq, phKey, combo[j])
									}
								}
								s.sendRequest(ctx, tmpl, i, lineReq, reqTimeout, req.Redirects, allExtracted, eng, &reqResults, &reqEvidence, target, req.Extractors, req.Matchers, !req.Probe, &lastRawReq, &lastRawResp)
							}
							continue
						}

						s.sendRequest(ctx, tmpl, i, pathReq, reqTimeout, req.Redirects, allExtracted, eng, &reqResults, &reqEvidence, target, req.Extractors, req.Matchers, !req.Probe, &lastRawReq, &lastRawResp)
					}
					continue
				}
				if rawReq == "" {
					continue
				}
			} else {
				// For raw requests, placeholder substitution only
				// (global headers already injected in executeHTTP or via client)
				rawReq = eng.ReplaceWithEscape(rawReq)
			}

			// Wordlist injection (multiple wordlists → cartesian product)
			var wordlistCombinations [][]string
			if len(req.Wordlist) > 0 {
				// Load all wordlists and build cartesian product
				wordlistCombinations = buildWordlistCombinations(s, req.Wordlist)
			}
			if len(wordlistCombinations) > 0 {
				for _, combo := range wordlistCombinations {
					select {
					case <-ctx.Done():
						return nil
					default:
					}
					lineReq := rawReq
					for j, wd := range req.Wordlist {
						phKey := "{{" + wd.Key + "}}"
						if j < len(combo) {
							lineReq = strings.ReplaceAll(lineReq, phKey, combo[j])
						}
					}
					// Probe requests with wordlists: extractors still run, but matcher results are ignored
					s.sendRequest(ctx, tmpl, i, lineReq, reqTimeout, req.Redirects, allExtracted, eng, &reqResults, &reqEvidence, target, req.Extractors, req.Matchers, !req.Probe, &lastRawReq, &lastRawResp)
				}
				continue
			}

			// Range injection: iterate over values and replace placeholder
			if req.Range != nil && len(req.Range.Values) > 0 {
				for _, val := range req.Range.Values {
					select {
					case <-ctx.Done():
						return nil
					default:
					}
					rangeReq := strings.ReplaceAll(rawReq, "{{"+req.Range.Key+"}}", val)
					if rangeReq == rawReq {
						// Placeholder not found, send original
						s.sendRequest(ctx, tmpl, i, rawReq, reqTimeout, req.Redirects, allExtracted, eng, &reqResults, &reqEvidence, target, req.Extractors, req.Matchers, !req.Probe, &lastRawReq, &lastRawResp)
						break
					}
					s.sendRequest(ctx, tmpl, i, rangeReq, reqTimeout, req.Redirects, allExtracted, eng, &reqResults, &reqEvidence, target, req.Extractors, req.Matchers, !req.Probe, &lastRawReq, &lastRawResp)
				}
				continue
			}

			// Probe requests with extractors still run, but matcher results are ignored
			s.sendRequest(ctx, tmpl, i, rawReq, reqTimeout, req.Redirects, allExtracted, eng, &reqResults, &reqEvidence, target, req.Extractors, req.Matchers, !req.Probe, &lastRawReq, &lastRawResp)
		}
	}

	// Aggregate only non-probe results
	overallCond := tmpl.MatchersCondition
	if overallCond == "" {
		overallCond = "or"
	}
	overallMatched := aggregateMatches(reqResults, overallCond)
	if !overallMatched {
		return nil
	}

	now := time.Now()
	r := &types.Result{
		TemplateID:  tmpl.ID,
		Name:        tmpl.Name,
		Severity:    tmpl.Severity,
		Description: tmpl.Description,
		Target:      target,
		MatchedAt:   now.Format("2006-01-02 15:04:05"),
		Tags:        tmpl.Tags,
		Reference:   tmpl.Reference,
		Timestamp:   now,
		Evidence:    strings.Join(reqEvidence, "; "),
		Extracted:   allExtracted,
		RawRequest:  lastRawReq,
		RawResponse: lastRawResp,
	}
	return r
}

// sendRequest sends a single HTTP request and processes the response.
// countResult: if false, matcher results are not added to reqResults (used for probe requests).
// rawReqPtr/rawRespPtr: optional pointers to capture the last raw request/response for the matched request.
func (s *Scanner) sendRequest(ctx context.Context, tmpl *types.Template, reqIdx int, rawReq string, reqTimeout int, redirects *bool, allExtracted map[string]string, eng *placeholder.Engine, reqResults *[]bool, evidence *[]string, target string, extractors []types.Extractor, matchers []types.Matcher, countResult bool, rawReqPtr, rawRespPtr *string) {
	s.logRequest(tmpl.ID, reqIdx, rawReq)

	// Inject global headers into raw request text so they appear in -vv output
	// and are sent even when sendRequest calls SendParsed directly.
	rawReq = s.client.InjectGlobalHeaders(rawReq)

	parsed, err := httpclient.ParseRaw(rawReq)
	if err != nil {
		s.verbosef("parse raw: %s req[%d]: %v", tmpl.ID, reqIdx, err)
		if s.logger != nil {
			s.logger.WarnKV("parse raw request failed", "template", tmpl.ID, "req", reqIdx, "error", err.Error())
		}
		*reqResults = append(*reqResults, false)
		return
	}

	reqCtx, cancel := context.WithTimeout(ctx, time.Duration(reqTimeout)*time.Second)
	// A1: honor per-request redirects override via context.
	// Also honor global --follow-redirects flag.
	if s.followRedirects == false {
		// Global: never follow
		if redirects == nil || *redirects {
			falseVal := false
			reqCtx = context.WithValue(reqCtx, httpclient.ContextKeyFollowRedirects{}, falseVal)
		}
	}
	if redirects != nil {
		reqCtx = context.WithValue(reqCtx, httpclient.ContextKeyFollowRedirects{}, *redirects)
	}
	resp, err := s.client.SendParsed(reqCtx, target, parsed)
	cancel()
	if err != nil {
		s.verbosef("send: %s req[%d]: %v", tmpl.ID, reqIdx, err)
		if s.logger != nil {
			s.logger.WarnKV("HTTP request failed", "template", tmpl.ID, "req", reqIdx, "error", err.Error())
		}
		*reqResults = append(*reqResults, false)
		return
	}

	s.logResponse(tmpl.ID, reqIdx, resp.StatusCode, resp.Body, resp.Raw, resp.Time)

	matchCtx := matcher.NewMatchContextWithCookies(
		resp.StatusCode, resp.Body, resp.AllHeaders(), resp.GetHeader("Set-Cookie"), resp.Time,
	)
	// Carry forward extracted variables from previous steps for DSL interpolation
	matchCtx.ExtractedVars = allExtracted
	matchCtx.Debug = func(format string, args ...interface{}) {
		s.debug(format, args...)
	}

	extracted := matcher.Extract(extractors, matchCtx)
	for k, v := range extracted {
		allExtracted[k] = v
		eng.SetExtracted(k, v)
	}
	tmplExtracted := matcher.Extract(tmpl.Extractors, matchCtx)
	for k, v := range tmplExtracted {
		allExtracted[k] = v
		eng.SetExtracted(k, v)
	}

	finalMatchers := matchers
	if len(finalMatchers) == 0 {
		finalMatchers = tmpl.Matchers
	}
	finalMatchers = substituteMatcherPlaceholders(finalMatchers, eng)
	matched, ev := matcher.Evaluate(finalMatchers, "", matchCtx)
	s.logMatcherResult(tmpl.ID, reqIdx, finalMatchers, "", matched, ev)

	// Probe requests: extractors run and info is logged, but matcher results don't count toward final verdict
	if countResult {
		*reqResults = append(*reqResults, matched)
		if matched && ev != "" {
			*evidence = append(*evidence, ev)
			// Capture raw request/response for reporting
			if rawReqPtr != nil {
				*rawReqPtr = rawReq
			}
			if rawRespPtr != nil && resp != nil {
				*rawRespPtr = resp.Raw
			}
		}
	}
	// countResult=false (probe): do NOT collect evidence — probe results must not affect verdict
}

// loadWordlist reads a wordlist file and optionally encodes each line.
func (s *Scanner) loadWordlist(path, encoding string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Apply encoding if specified
		if encoding != "" {
			line = encodeLine(line, encoding)
		}
		lines = append(lines, line)
	}
	return lines, nil
}

// buildWordlistCombinations builds the cartesian product of all wordlist entries.
// Each combination is a []string where index i corresponds to req.Wordlist[i].
func buildWordlistCombinations(s *Scanner, wordlists []types.WordlistConfig) [][]string {
	if len(wordlists) == 0 {
		return nil
	}
	// Load all wordlists first
	allLists := make([][]string, len(wordlists))
	for i, wl := range wordlists {
		lines, err := s.loadWordlist(wl.Path, wl.Encoding)
		if err != nil || len(lines) == 0 {
			s.verbosef("wordlist load failed or empty: %s", wl.Path)
			return nil // abort if any wordlist fails
		}
		allLists[i] = lines
	}
	// Check cartesian product limit before building
	total := 1
	for _, sl := range allLists {
		total *= len(sl)
		if total > s.cfg.MaxCartesianProducts {
			s.verbosef("wordlist cartesian product exceeds limit (%d > %d): %v", total, s.cfg.MaxCartesianProducts, wordlists)
			return nil
		}
	}
	// Build cartesian product
	return cartesianProduct(allLists)
}

// cartesianProduct computes the cartesian product of string slices.
func cartesianProduct(slices [][]string) [][]string {
	if len(slices) == 0 {
		return nil
	}
	// Compute total combinations
	total := 1
	for _, s := range slices {
		total *= len(s)
	}
	if total == 0 {
		return nil
	}
	result := make([][]string, total)
	for i := 0; i < total; i++ {
		comb := make([]string, len(slices))
		m := i
		for j := len(slices) - 1; j >= 0; j-- {
			comb[j] = slices[j][m%len(slices[j])]
			m /= len(slices[j])
		}
		result[i] = comb
	}
	return result
}

// encodeLine applies the specified encoding to a single line.
func encodeLine(line, encoding string) string {
	switch strings.ToLower(encoding) {
	case "url", "urlencode":
		return strings.ReplaceAll(line, "+", "%2B") // avoid double-encoding
	case "base64", "base64_encode":
		return placeholder.Base64Encode(line)
	case "hex", "hex_encode":
		return placeholder.HexEncode(line)
	default:
		return line
	}
}

// injectGlobalHeaders inserts global CLI headers into a raw HTTP request string.
// It inserts missing headers BEFORE the blank line that separates headers from body,
// so that ParseRaw correctly parses them as HTTP headers rather than body content.
// If no \r\n\r\n separator exists, headers are appended at the end of the string.
func injectGlobalHeaders(raw string, headers map[string]string) string {
	if len(headers) == 0 {
		return raw
	}
	// Find the header/body separator: \r\n\r\n (or \n\n as fallback).
	sep := "\r\n\r\n"
	idx := strings.Index(raw, sep)
	if idx < 0 {
		idx = strings.Index(raw, "\n\n")
	}
	if idx >= 0 {
		// Insert BEFORE the blank line so new headers appear in the header block.
		// raw[:idx] ends just before \r\n\r\n, so we add \r\n to close the last header.
		var sb strings.Builder
		sb.WriteString(raw[:idx])
		sb.WriteString("\r\n")
		for k, v := range headers {
			sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
		}
		sb.WriteString(raw[idx:])
		return sb.String()
	}
	// No separator found — append headers at the end.
	// Remove trailing \r\n to avoid creating a false blank line.
	raw = strings.TrimRight(raw, "\r\n")
	return raw + "\r\n" + injectHeadersMap(headers)
}

// injectHeadersMap formats a headers map into HTTP header lines.
func injectHeadersMap(headers map[string]string) string {
	var sb strings.Builder
	for k, v := range headers {
		sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	return sb.String()
}

func (s *Scanner) executeWorkflow(ctx context.Context, tmpl *types.Template, target string, eng *placeholder.Engine) *types.Result {
	wfExec := workflow.New(s.client, s.cfg.DefaultTimeout, s.verbose, s.debug, s.verbosef, s.onRaw, s.onPacket, s.logger, s.globalHeaders, s.cfg.OOB.Provider)
	matched, evidence, extracted := wfExec.Execute(ctx, tmpl.Workflow, target, eng)
	if !matched {
		return nil
	}
	now := time.Now()
	return &types.Result{
		TemplateID:  tmpl.ID,
		Name:        tmpl.Name,
		Severity:    tmpl.Severity,
		Description: tmpl.Description,
		Target:      target,
		MatchedAt:   now.Format("2006-01-02 15:04:05"),
		Tags:        tmpl.Tags,
		Reference:   tmpl.Reference,
		Timestamp:   now,
		Evidence:    strings.Join(evidence, "; "),
		Extracted:   extracted,
	}
}

// GetStats returns (completed, matched, total).
// [批次A-7 修复点] 使用 atomic.Load 读取并发计数器, 替代互斥锁。
func (s *Scanner) GetStats() (completed, matched, total int64) {
	return atomic.LoadInt64(&s.completed),
		atomic.LoadInt64(&s.matched),
		atomic.LoadInt64(&s.totalJobs)
}

// MarkDone pre-marks a (target, templateID) pair as completed.
// [批次A-9 修复点] 用于断点续扫: 从 resume 文件加载已完成的任务,
// 注入 dedup map 使扫描器跳过它们。
func (s *Scanner) MarkDone(target, templateID string) {
	key := target + "|" + templateID
	s.dedup.Store(key, true)
}

// GetCompleted returns all completed (target|templateID) pairs.
// [批次A-9 修复点] 用于保存 resume 状态: 扫描结束后或中断时导出已完成列表。
func (s *Scanner) GetCompleted() []string {
	var pairs []string
	s.dedup.Range(func(key, value interface{}) bool {
		if k, ok := key.(string); ok {
			pairs = append(pairs, k)
		}
		return true
	})
	return pairs
}

// =============================================================================
// Verbose helpers — centralise gating so the engine and workflow agree
// =============================================================================

func (s *Scanner) debug(format string, args ...interface{}) {
	if s.verbose >= 2 && s.onDebug != nil {
		s.onDebug(format, args...)
	}
}

func (s *Scanner) verbosef(format string, args ...interface{}) {
	if s.verbose >= 1 && s.onVerbose != nil {
		s.onVerbose(format, args...)
	}
}

// parseMethodPath extracts the HTTP method and path from a raw request string.
func parseMethodPath(raw string) (method, path string) {
	firstLine := strings.SplitN(raw, "\r\n", 2)[0]
	parts := strings.SplitN(firstLine, " ", 3)
	if len(parts) >= 2 {
		return parts[0], parts[1]
	}
	return "?", "?"
}

// logRequest logs an outgoing HTTP request.
// INFO level (-v): method + path summary via structured logger.
// -vv level: Burp-style packet dump via onPacket callback.
func (s *Scanner) logRequest(tmplID string, i int, raw string) {
	method, path := parseMethodPath(raw)

	// INFO: request summary (visible at -v)
	if s.logger != nil {
		s.logger.InfoKV("HTTP request sent",
			"template", tmplID, "req", i,
			"method", method, "path", path, "bytes", len(raw))
	}

	// -vv: Burp-style packet dump
	if s.verbose >= 2 && s.onPacket != nil {
		summary := fmt.Sprintf("%s req[%d]  %s %s  %d bytes", tmplID, i, method, path, len(raw))
		s.onPacket("请求", summary, raw)
	}
}

// logResponse logs an incoming HTTP response.
// INFO level (-v): status + size + time summary via structured logger.
// -vv level: Burp-style packet dump via onPacket callback.
func (s *Scanner) logResponse(tmplID string, i int, status int, body string, raw string, elapsed time.Duration) {
	// INFO: response summary (visible at -v)
	if s.logger != nil {
		s.logger.InfoKV("HTTP response received",
			"template", tmplID, "req", i,
			"status", status, "time_ms", elapsed.Milliseconds(), "bytes", len(body))
	}

	// -vv: Burp-style packet dump
	if s.verbose >= 2 && s.onPacket != nil {
		summary := fmt.Sprintf("%s req[%d]  status=%d  %s  %d bytes",
			tmplID, i, status, elapsed.Round(time.Millisecond), len(body))
		s.onPacket("响应", summary, raw)
	}
}

// logMatcherResult logs the result of matcher evaluation.
// INFO level (-v): PASS/FAIL result with evidence.
// -vv level: detailed matcher types and condition.
func (s *Scanner) logMatcherResult(tmplID string, i int, ms []types.Matcher, cond string, matched bool, ev string) {
	mTypes := make([]string, 0, len(ms))
	for _, m := range ms {
		mTypes = append(mTypes, m.Type)
	}
	typesStr := strings.Join(mTypes, ",")

	// INFO: match result (visible at -v)
	if s.logger != nil {
		if matched {
			s.logger.InfoKV("matcher PASS",
				"template", tmplID, "req", i,
				"condition", cond, "types", typesStr, "evidence", ev)
		} else {
			s.logger.InfoKV("matcher FAIL",
				"template", tmplID, "req", i,
				"condition", cond, "types", typesStr)
		}
	}

	// -vv: detailed match result with colored PASS/FAIL
	if s.verbose >= 2 && s.onRaw != nil {
		status := pterm.Green("PASS")
		if !matched {
			status = pterm.Red("FAIL")
		}
		s.onRaw("匹配", "%s req[%d]  %s  cond=%s  types=%s  evidence=%q",
			tmplID, i, status, cond, typesStr, ev)
	}
}

// =============================================================================
// helpers
// =============================================================================

// substituteMatcherPlaceholders runs the placeholder engine over the string
// fields of each matcher. YAML-loaded matcher fields bypass the placeholder
// engine — only req.Raw goes through it. This helper closes that gap so
// templates can write things like `words: ["{{oob_label}}"]`.
func substituteMatcherPlaceholders(matchers []types.Matcher, eng *placeholder.Engine) []types.Matcher {
	out := make([]types.Matcher, len(matchers))
	for i, m := range matchers {
		out[i] = m // copy
		out[i].Words = replaceStrSlice(out[i].Words, eng)
		out[i].Regex = replaceStrSlice(out[i].Regex, eng)
		out[i].Header = replaceStrSlice(out[i].Header, eng)
		out[i].Binary = replaceStrSlice(out[i].Binary, eng)
		out[i].JSONPath = eng.ReplaceWithEscape(out[i].JSONPath)
		out[i].JSONField = eng.ReplaceWithEscape(out[i].JSONField)
	}
	return out
}

func replaceStrSlice(in []string, eng *placeholder.Engine) []string {
	if len(in) == 0 {
		return in
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = eng.ReplaceWithEscape(s)
	}
	return out
}

// TemplateNeedsOOB reports whether a template references OOB placeholders.
// Exported so cmd/gosleek can reuse this logic instead of duplicating it.
func TemplateNeedsOOB(tmpl *types.Template) bool {
	if tmpl.OOB != nil {
		return true
	}
	placeholderMarkers := []string{"{{oob}}", "{{interactsh-url}}", "{{oob_label}}", "{{oob_token}}", "{{oob_domain}}"}
	for _, req := range tmpl.HTTP {
		for _, m := range placeholderMarkers {
			if strings.Contains(req.Raw, m) {
				return true
			}
		}
	}
	for _, step := range tmpl.Workflow {
		for _, req := range step.HTTP {
			for _, m := range placeholderMarkers {
				if strings.Contains(req.Raw, m) {
					return true
				}
			}
		}
	}
	return false
}

// oobKindName returns a human-readable kind name for OOB skip messages.
func oobKindName(job Job) string {
	if job.Kind == JobKindPlugin {
		return "插件"
	}
	return "模板"
}

func aggregateMatches(results []bool, cond string) bool {
	if len(results) == 0 {
		return false
	}
	if cond == "and" {
		for _, r := range results {
			if !r {
				return false
			}
		}
		return true
	}
	for _, r := range results {
		if r {
			return true
		}
	}
	return false
}

// evalRunIf evaluates a run-if condition for a request block.
//
// [批次A-6 修复点] 旧实现仅检查替换后的值是否非空, 但当占位符无法解析时
// (例如引用了一个不存在的提取器变量), eng.Replace 会返回字面量 "{{var}}",
// 这是非空字符串, 导致条件错误地为 true。现在增加未解析占位符检测:
// 如果结果中仍包含 "{{...}}" 模式, 说明依赖的变量不存在, 应返回 false。
func evalRunIf(expr string, extracted map[string]string, eng *placeholder.Engine) bool {
	val := eng.Replace(expr)
	if val == "" {
		return false
	}
	// Check for unresolved placeholders using a regex that matches
	// complete {{...}} patterns. This avoids false positives when the
	// user's expression legitimately contains literal "{{" or "}}".
	if unresolvedPlaceholderRe.MatchString(val) {
		return false
	}
	// Literal "false" or "0" → false
	lower := strings.ToLower(strings.TrimSpace(val))
	if lower == "false" || lower == "0" {
		return false
	}
	// If the expression looks like a DSL expression (contains ==, !=, etc.),
	// evaluate it using the DSL engine
	if strings.Contains(val, "==") || strings.Contains(val, "!=") ||
		strings.Contains(val, ">") || strings.Contains(val, "<") ||
		strings.Contains(val, "contains") || strings.Contains(val, "regex") ||
		strings.Contains(val, "!") {
		// Build a match context with extracted variables
		ctx := &matcher.MatchContext{
			StatusCode:    200,
			Body:          "",
			Header:        "",
			ExtractedVars: extracted,
		}
		if result, err := matcher.EvalDSL(val, ctx); err == nil {
			return result
		}
		// If DSL evaluation fails, fall through to default behavior
	}
	return true
}

// unresolvedPlaceholderRe matches a complete {{...}} placeholder.
var unresolvedPlaceholderRe = regexp.MustCompile(`\{\{[^}]+\}\}`)

func buildRawFromPath(method, path string, headers map[string]string, body string) string {
	return buildRawFromPathWithBodyType(method, path, headers, body, "")
}

func buildRawFromPathWithBodyType(method, path string, headers map[string]string, body, bodyType string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", method, path))
	sb.WriteString("Host: {{Hostname}}\r\n")

	// If body-type is specified and body is non-empty, generate appropriate body
	if bodyType != "" && body != "" {
		switch strings.ToLower(bodyType) {
		case "form", "form-urlencoded":
			// Parse body as key=value pairs and set Content-Type
			for k, v := range headers {
				sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
			}
			sb.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
			sb.WriteString("Connection: close\r\n")
			sb.WriteString("\r\n")
			sb.WriteString(body)
			return sb.String()
		case "multipart", "multipart-form-data":
			// Parse body as key=value pairs and generate multipart
			boundary := "----gosleekFormBoundary" + placeholder.RandTextHex(8)
			contentType := "multipart/form-data; boundary=" + boundary
			for k, v := range headers {
				sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
			}
			sb.WriteString("Content-Type: " + contentType + "\r\n")
			sb.WriteString("Connection: close\r\n")
			sb.WriteString("\r\n")
			sb.WriteString(buildMultipartBody(body, boundary))
			return sb.String()
		}
	}

	for k, v := range headers {
		sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	sb.WriteString("Connection: close\r\n")
	sb.WriteString("\r\n")
	if body != "" {
		sb.WriteString(body)
	}
	return sb.String()
}

// buildMultipartBody generates a multipart form body from key=value pairs.
func buildMultipartBody(body, boundary string) string {
	var sb strings.Builder
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, "=")
		if idx < 0 {
			continue
		}
		key := line[:idx]
		value := line[idx+1:]
		sb.WriteString("--" + boundary + "\r\n")
		sb.WriteString(fmt.Sprintf("Content-Disposition: form-data; name=\"%s\"\r\n\r\n", key))
		sb.WriteString(value + "\r\n")
	}
	sb.WriteString("--" + boundary + "--\r\n")
	return sb.String()
}

func parseDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 2 * time.Second
	}
	return d
}
