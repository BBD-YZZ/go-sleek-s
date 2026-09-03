package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"net/url"
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
	"github.com/gosleek/gosleek/internal/ai"
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
	globalHeaders map[string]string // injected into every request
	wordlistDir   string            // base dir for wordlist files

	// WebUI 任务 ID（由 cmd 层在扫描开始前设置）
	taskID string

	// dedup: "target|templateID" → bool (job-level: skip already-processed jobs)
	dedup sync.Map

	// resultDedup: "target|templateID|severity" → bool (result-level: skip duplicate reports)
	// 防止相同模板+目标+严重度被重复报告（断点续扫场景）
	resultDedup sync.Map

	// Cookie jar for session persistence across requests.
	cookieJar http.CookieJar

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
	onWebUIAdd func(*types.Result) // 可选：将结果推送给 Web UI（由 cmd 层注册）
	onVerbose  func(format string, args ...interface{}) // -v level
	onDebug    func(format string, args ...interface{}) // -vv level (调试 tag)
	onRaw      func(tag, format string, args ...interface{}) // -vv level (匹配 tag)
	onPacket   func(tag string, summary string, raw string)  // -vv level (请求/响应 Burp-style)

	// AI 实时分析回调
	aiProvider       ai.Provider // 可选：AI 提供商（nil 表示未启用）
	aiConfidence     float64     // AI 确认的最小置信度阈值
	aiAnalysisChan   chan *types.Result // 异步分析结果通道
	aiWG             sync.WaitGroup // 等待所有 AI 分析 goroutine 完成
	aiDone           chan struct{}  // 信号：所有 AI 分析已完成
	onAIFingerprint  func(*ai.FingerprintResponse, string) // AI 指纹识别回调（可选）

	// dedup stats
	resultDedupCount int64 // 引擎结果去重计数
	jobDedupCount    int64 // 任务去重计数
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
		oobAvailable: oob.Provider != "", // OOB enabled when provider is configured
		oobLabel:     oob.Label,
		oobDomain:    oob.CeyeDomain,
		globalHeaders: make(map[string]string),
		cookieJar:     mustCreateCookieJar(),
	}
}

// SetGlobalHeaders injects headers into every request for the duration of a scan.
// Headers are also propagated to the HTTP client so plugins get them via SendRaw.
func (s *Scanner) SetGlobalHeaders(h map[string]string) {
	s.globalHeaders = h
	s.client.SetGlobalHeaders(h)
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

// OnWebUIAdd sets the optional callback for pushing results to a Web UI server.
func (s *Scanner) OnWebUIAdd(fn func(*types.Result)) {
	s.onWebUIAdd = fn
}

// DedupStats returns (resultDedupCount, jobDedupCount).
// resultDedupCount: 相同目标+模板+严重度去重的结果数。
// jobDedupCount: 相同目标+模板（无论是否匹配）去重的任务数。
func (s *Scanner) DedupStats() (resultDedupCount, jobDedupCount int64) {
	return atomic.LoadInt64(&s.resultDedupCount), atomic.LoadInt64(&s.jobDedupCount)
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

// SetTaskID sets the WebUI task ID for result association.
func (s *Scanner) SetTaskID(id string) { s.taskID = id }

// SetAICallback 设置 AI 实时分析回调。
// provider 为 AI 提供商实例（nil 表示不启用 AI 分析）。
// minConfidence 为 AI 确认的最小置信度阈值（0.0-1.0），低于此值的结果不会推送给 onResult。
// onAIResult 为 AI 分析结果回调（可选）。
// onAIFingerprint 为 AI 指纹识别回调（可选）。
func (s *Scanner) SetAICallback(provider ai.Provider, minConfidence float64,
	onAIResult func(*ai.AnalyzeResponse, *types.Result),
	onAIFingerprint func(*ai.FingerprintResponse, string)) {
	s.aiProvider = provider
	s.aiConfidence = minConfidence
	if onAIResult != nil {
		s.aiAnalysisChan = make(chan *types.Result, 64)
		s.aiDone = make(chan struct{})
		go s.aiAnalysisLoop(onAIResult)
	}
	s.onAIFingerprint = onAIFingerprint
}

// WaitForAI 等待所有 AI 分析完成，最多等待 timeout 秒。
// 应在 Run() 返回后调用，确保 AI 分析结果已输出。
func (s *Scanner) WaitForAI(timeoutSeconds int) {
	if s.aiAnalysisChan == nil {
		return
	}
	close(s.aiAnalysisChan) // 通知 aiAnalysisLoop 没有更多结果了
	if timeoutSeconds <= 0 {
		timeoutSeconds = 30
	}
	done := make(chan struct{})
	go func() {
		s.aiWG.Wait()
		close(done)
	}()
	select {
	case <-done:
		return
	case <-time.After(time.Duration(timeoutSeconds) * time.Second):
		// L2: the wait goroutine above will terminate naturally once the
		// outstanding AI analysis goroutines finish (each has its own ctx
		// timeout), so this is not a permanent leak — but we surface the
		// timeout to the user so they know some AI verdicts may be missing.
		if s.verbose >= 1 {
			fmt.Println("AI 分析超时，跳过等待（部分结果可能缺少 AI 确认）")
		}
	}
}

// aiAnalysisLoop 在独立 goroutine 中执行 AI 异步分析。
func (s *Scanner) aiAnalysisLoop(onAIResult func(*ai.AnalyzeResponse, *types.Result)) {
	for r := range s.aiAnalysisChan {
		s.aiWG.Add(1)
		go func(result *types.Result) {
			defer s.aiWG.Done()
			if s.aiProvider == nil {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.cfg.AI.Timeout)*time.Second)
			defer cancel()

			req := &ai.AnalyzeRequest{
				TemplateID:   result.TemplateID,
				TemplateName: result.Name,
				Severity:     result.Severity,
				Target:       result.Target,
				RawRequest:   result.RawRequest,
				RawResponse:  result.RawResponse,
				Evidence:     result.Evidence,
				Extracted:    result.Extracted,
				Context:      "AI 实时分析",
			}

			resp, err := s.aiProvider.Analyze(ctx, req)
			if err != nil {
				if s.verbose >= 1 && s.onDebug != nil {
					s.onDebug("AI 分析失败: template=%s target=%s err=%v", result.TemplateID, result.Target, err)
				}
				// AI 分析失败时不丢弃结果，仍调用原始 onResult
				if s.onResult != nil {
					s.onResult(result)
				}
				if s.onWebUIAdd != nil {
					s.onWebUIAdd(result)
				}
				return
			}

			if resp == nil {
				if s.onResult != nil {
					s.onResult(result)
				}
				if s.onWebUIAdd != nil {
					s.onWebUIAdd(result)
				}
				return
			}

			confPct := int(resp.Confidence * 100)
			if s.onVerbose != nil {
				s.onVerbose("AI 分析: %s - %s  置信度=%d%%  确认=%v  建议=%d条",
					result.TemplateID, result.Name, confPct, resp.Confident, len(resp.Suggestions))
			}

			// 将 AI 分析结果注入到 result.Extracted 中，供 PrintAIResult 展示
			if result.Extracted == nil {
				result.Extracted = make(map[string]string)
			}
			result.Extracted["ai_evidence"] = resp.Evidence
			result.Extracted["ai_exploit"] = resp.Exploit
			result.Extracted["ai_impact"] = resp.Impact
			result.Extracted["ai_remediation"] = resp.Remediation

			// 如果启用 AI 确认且置信度低于阈值，跳过结果
			if s.aiConfidence > 0 && resp.Confidence < s.aiConfidence {
				if s.verbose >= 1 && s.onDebug != nil {
					s.onDebug("AI 置信度过低，跳过: %s (%.2f < %.2f)", result.TemplateID, resp.Confidence, s.aiConfidence)
				}
				if onAIResult != nil {
					onAIResult(resp, result)
				}
				return
			}

			// AI 确认通过，推送结果
			if s.onResult != nil {
				s.onResult(result)
			}
			if s.onWebUIAdd != nil {
				s.onWebUIAdd(result)
			}
			if onAIResult != nil {
				onAIResult(resp, result)
			}
		}(r)
	}
}

// aiFingerprintTargets 对目标列表进行 AI 指纹识别（扫描开始前）。
// 仅对第一个目标做一次，避免重复请求。
func (s *Scanner) aiFingerprintTargets(ctx context.Context, targets []string) {
	if len(targets) == 0 || s.aiProvider == nil || s.onAIFingerprint == nil {
		return
	}
	// 只对第一个目标做指纹识别（快速获取技术栈信息）
	target := targets[0]
	if s.verbose >= 1 {
		s.verbosef("开始 AI 指纹识别: %s", target)
	}
	// 发送一个简单 GET 请求获取响应
	host := target
	if u, err := url.Parse(target); err == nil {
		host = u.Host
	}
	rawReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	resp, err := s.client.SendRaw(ctx, target, rawReq)
	if err != nil {
		if s.verbose >= 1 {
			s.verbosef("AI 指纹识别失败: %v", err)
		}
		return
	}
	fpReq := &ai.FingerprintRequest{
		Target:      target,
		RawResponse: resp.Raw,
	}
	// 尝试调用指纹识别方法（仅 OpenAIProvider 支持）
	if openaiProvider, ok := s.aiProvider.(*ai.OpenAIProvider); ok {
		fpResp, err := openaiProvider.AnalyzeFingerprint(ctx, fpReq)
		if err != nil {
			if s.verbose >= 1 {
				s.verbosef("AI 指纹分析失败: %v", err)
			}
			return
		}
		if fpResp != nil {
			s.onAIFingerprint(fpResp, target)
		}
	}
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
	// C1 fix: guard against s.oobProvider == nil (probe may have failed above
	// and set it to nil). Only compare names when global provider is non-nil.
	globalProviderName := ""
	if s.oobProvider != nil {
		globalProviderName = s.oobProvider.Name()
	}
	for _, t := range templates {
		if t.OOBProvider != "" && t.OOBProvider != globalProviderName {
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

	// AI 指纹识别（扫描开始前对每个目标做一次快速指纹识别）
	if s.aiProvider != nil && s.onAIFingerprint != nil && len(targets) > 0 {
		s.aiFingerprintTargets(ctx, targets)
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
			if s.aiAnalysisChan != nil {
				// AI 启用时：结果先发给 AI 分析，由 AI goroutine 决定是否输出
				select {
				case s.aiAnalysisChan <- r:
				default:
					// L3 fix: never silently drop results — that would cause
					// under-reporting in the final report. When the AI queue
					// is full, fall back to emitting the result directly so
					// nothing is lost; the AI side simply skips this one.
					if s.verbose >= 1 && s.onDebug != nil {
						s.onDebug("AI 分析队列满，降级直出结果: template=%s", r.TemplateID)
					}
					if s.onResult != nil {
						s.onResult(r)
					}
					if s.onWebUIAdd != nil {
						s.onWebUIAdd(r)
					}
				}
			} else {
				if s.onResult != nil {
					s.onResult(r)
				}
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
	// 使用 ":::" 作为分隔符（URL 中极少出现），避免 "|" 出现在目标 URL 时冲突
	dedupKey := target + ":::" + id
	if _, exists := s.dedup.LoadOrStore(dedupKey, true); exists {
		s.debug("跳过重复: %s vs %s", target, id)
		if s.logger != nil {
			s.logger.InfoKV("skip duplicate (already processed)", "target", target, "template", id)
		}
		atomic.AddInt64(&s.jobDedupCount, 1)
		return
	}

	if s.logger != nil {
		s.logger.InfoKV("task started", "target", target, "template", id)
	}

	// -vv: 记录模板/插件基本信息
	if s.verbose >= 2 && s.onDebug != nil {
		if job.Kind == JobKindPlugin {
			s.onDebug("执行Go插件: %s, 目标=%s", id, target)
		} else {
			s.onDebug("执行YAML模板: %s, 目标=%s, HTTP请求数=%d, workflow步骤数=%d",
				id, target, len(job.Template.HTTP), len(job.Template.Workflow))
		}
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
		if s.verbose >= 2 && s.onDebug != nil {
			s.onDebug("指纹匹配通过: template=%s, server=%s, target=%s", id, fp.Server, target)
		}
	}

	// OOB 预检查 (YAML 模板和需要 OOB 的 Go 插件)
	if job.Kind == JobKindTemplate && TemplateNeedsOOB(job.Template) {
		tmplProvider := s.getOOBProvider(job.Template)
		// 检查模板所需的 provider 是否已初始化
		if tmplProvider == nil || !s.isOOBProviderAvailable(tmplProvider) {
			// N1 fix: tmplProvider 可能为 nil，直接调用 .Name() 会 panic
			var providerName string
			if tmplProvider != nil {
				providerName = tmplProvider.Name()
			} else {
				providerName = "none"
			}
			s.debug("跳过OOB%s(%s未配置): %s", oobKindName(job), providerName, id)
			if s.logger != nil {
				s.logger.InfoKV("skip OOB template", "provider", providerName, "template", id)
			}
			if s.verbose >= 2 && s.onDebug != nil {
				s.onDebug("OOB未配置, 跳过: template=%s, provider=%s", id, providerName)
			}
			return
		}
	} else if job.Kind == JobKindPlugin && job.Plugin.NeedsOOB() {
		if !s.oobAvailable || s.oobProvider == nil {
			if s.verbose >= 2 && s.onDebug != nil {
				s.onDebug("插件需要OOB但未启用, 跳过: plugin=%s", id)
			}
			return
		}
		if s.verbose >= 2 && s.onDebug != nil {
			s.onDebug("OOB可用, 继续插件: plugin=%s, provider=%s", id, s.oobProvider.Name())
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
		// 结果级去重: 相同模板+目标+严重度只报告一次
		resultKey := target + "|" + id + "|" + result.Severity
		if _, loaded := s.resultDedup.LoadOrStore(resultKey, true); loaded {
			if s.logger != nil {
				s.logger.InfoKV("skip duplicate result",
					"target", target, "template", id, "severity", result.Severity)
			}
			if s.verbose >= 2 && s.onDebug != nil {
				s.onDebug("跳过重复结果: %s vs %s (severity=%s)", target, id, result.Severity)
			}
			atomic.AddInt64(&s.resultDedupCount, 1)
		} else {
			atomic.AddInt64(&s.matched, 1)
			results <- result
			if s.logger != nil {
				s.logger.InfoKV("matched",
					"target", target, "template", id,
					"severity", result.Severity, "evidence", result.Evidence)
			}
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
		Log:        &noopPluginLogger{id: p.Meta().ID}, // 始终提供 logger 防止 panic
		CookieJar:  s.cookieJar,
		GlobalCfg:  s.cfg,
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

	// Call PreRun if the plugin implements it (e.g., for login, token extraction).
	if preRunner, ok := p.(interface{ PreRun(context.Context, *plugin.Context) error }); ok {
		if err := preRunner.PreRun(pluginCtx, pctx); err != nil {
			s.debug("插件 PreRun 失败: %s → %v", p.Meta().ID, err)
			return nil
		}
	}

	result, err := p.Verify(pluginCtx, pctx)  // 使用带超时的 pluginCtx

	// Call PostRun if the plugin implements it (e.g., for cleanup, logout).
	// Always called, even if Verify returns an error.
	if postRunner, ok := p.(interface{ PostRun(context.Context, *plugin.Context) }); ok {
		postRunner.PostRun(pluginCtx, pctx)
	}

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
	var lastRedirectChain []types.RedirectInfo

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
				if !matcher.EvalRunIf(req.RunIf, allExtracted, eng) {
					s.debug("[SKIP]   run-if false: %s req[%d]", tmpl.ID, i)
					continue
				}
			}

			// Range injection: iterate over values and replace placeholder FIRST
			// (must be done before placeholder substitution so that {{key}}
			// patterns survive the variable resolution)
			if req.Range != nil && len(req.Range.Values) > 0 {
				for _, val := range req.Range.Values {
					select {
					case <-ctx.Done():
						return nil
					default:
					}
					rangeReq := strings.ReplaceAll(req.Raw, "{{"+req.Range.Key+"}}", val)
					if rangeReq == req.Raw {
						// Placeholder not found, send original with placeholders resolved
						rawReq := eng.ReplaceWithEscape(req.Raw)
						s.sendRequest(ctx, tmpl, i, rawReq, reqTimeout, req.Redirects, allExtracted, eng, &reqResults, &reqEvidence, target, req.Extractors, req.Matchers, !req.Probe, &lastRawReq, &lastRawResp, &lastRedirectChain)
						break
					}
					// Apply Range first, then placeholder substitution
					rawReq := eng.ReplaceWithEscape(rangeReq)
					if rawReq == "" {
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
							lineReq := rawReq
							for j, wd := range req.Wordlist {
								phKey := "{{" + wd.Key + "}}"
								if j < len(combo) {
									lineReq = strings.ReplaceAll(lineReq, phKey, combo[j])
								}
							}
							s.sendRequest(ctx, tmpl, i, lineReq, reqTimeout, req.Redirects, allExtracted, eng, &reqResults, &reqEvidence, target, req.Extractors, req.Matchers, !req.Probe, &lastRawReq, &lastRawResp, &lastRedirectChain)
						}
						continue
					}

					// Probe requests with wordlists: extractors still run, but matcher results are ignored
					s.sendRequest(ctx, tmpl, i, rawReq, reqTimeout, req.Redirects, allExtracted, eng, &reqResults, &reqEvidence, target, req.Extractors, req.Matchers, !req.Probe, &lastRawReq, &lastRawResp, &lastRedirectChain)
				}
				continue
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
						pathReq := httpclient.BuildRawFromPathWithBodyType(method, p, mergedHeaders, req.Body, req.BodyType)
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
								s.sendRequest(ctx, tmpl, i, lineReq, reqTimeout, req.Redirects, allExtracted, eng, &reqResults, &reqEvidence, target, req.Extractors, req.Matchers, !req.Probe, &lastRawReq, &lastRawResp, &lastRedirectChain)
							}
							continue
						}

						s.sendRequest(ctx, tmpl, i, pathReq, reqTimeout, req.Redirects, allExtracted, eng, &reqResults, &reqEvidence, target, req.Extractors, req.Matchers, !req.Probe, &lastRawReq, &lastRawResp, &lastRedirectChain)
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
					s.sendRequest(ctx, tmpl, i, lineReq, reqTimeout, req.Redirects, allExtracted, eng, &reqResults, &reqEvidence, target, req.Extractors, req.Matchers, !req.Probe, &lastRawReq, &lastRawResp, &lastRedirectChain)
				}
				continue
			}
			// Probe requests with extractors still run, but matcher results are ignored
			s.sendRequest(ctx, tmpl, i, rawReq, reqTimeout, req.Redirects, allExtracted, eng, &reqResults, &reqEvidence, target, req.Extractors, req.Matchers, !req.Probe, &lastRawReq, &lastRawResp, &lastRedirectChain)
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
		RedirectChain: lastRedirectChain,
	}
	return r
}

// sendRequest sends a single HTTP request and processes the response.
// countResult: if false, matcher results are not added to reqResults (used for probe requests).
// rawReqPtr/rawRespPtr/rawChainPtr: optional pointers to capture the last raw request/response/redirect-chain for the matched request.
func (s *Scanner) sendRequest(ctx context.Context, tmpl *types.Template, reqIdx int, rawReq string, reqTimeout int, redirects *bool, allExtracted map[string]string, eng *placeholder.Engine, reqResults *[]bool, evidence *[]string, target string, extractors []types.Extractor, matchers []types.Matcher, countResult bool, rawReqPtr, rawRespPtr *string, rawChainPtr *[]types.RedirectInfo) {
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
	// Per-request redirect override via context.
	if redirects != nil {
		reqCtx = context.WithValue(reqCtx, httpclient.ContextKeyFollowRedirects{}, *redirects)
	}
	// Inject shared cookie jar for session persistence across requests.
	reqCtx = httpclient.SetCookieJar(reqCtx, s.cookieJar)
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

	if s.verbose >= 2 && s.onDebug != nil {
		s.onDebug("响应: template=%s req[%d]  status=%d  time=%s  body=%d bytes",
			tmpl.ID, reqIdx, resp.StatusCode, resp.Time.Round(time.Millisecond), len(resp.Body))
		// 重定向链输出
		if len(resp.RedirectChain) > 0 {
			for i, rh := range resp.RedirectChain {
				s.onDebug("  重定向[%d]: %d → %s", i, rh.StatusCode, rh.Location)
			}
		}
		// 记录提取器变量
		if len(extractors) > 0 {
			var keys []string
			for k := range allExtracted {
				keys = append(keys, k)
			}
			s.onDebug("当前提取变量: %s", strings.Join(keys, ", "))
		}
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
		if s.verbose >= 2 && s.onDebug != nil {
			s.onDebug("提取器: template=%s req[%d]  key=%s value=%s", tmpl.ID, reqIdx, k, truncateStr(v, 100))
		}
	}
	tmplExtracted := matcher.Extract(tmpl.Extractors, matchCtx)
	for k, v := range tmplExtracted {
		allExtracted[k] = v
		eng.SetExtracted(k, v)
		if s.verbose >= 2 && s.onDebug != nil {
			s.onDebug("模板提取器: template=%s req[%d]  key=%s value=%s", tmpl.ID, reqIdx, k, truncateStr(v, 100))
		}
	}

	finalMatchers := matchers
	if len(finalMatchers) == 0 {
		finalMatchers = tmpl.Matchers
	}
	finalMatchers = matcher.SubstituterMatcherPlaceholders(finalMatchers, eng)
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
			// Capture redirect chain if present
			if rawChainPtr != nil && resp != nil && len(resp.RedirectChain) > 0 {
				for _, rh := range resp.RedirectChain {
					*rawChainPtr = append(*rawChainPtr, types.RedirectInfo{
						StatusCode: rh.StatusCode,
						Location:   rh.Location,
						Time:       rh.Time.String(),
					})
				}
			}
		}
		if s.verbose >= 2 && s.onDebug != nil {
			s.onDebug("匹配结果: template=%s req[%d]  %s  types=%s  evidence=%q",
				tmpl.ID, reqIdx, statusStr(matched), typesStr(finalMatchers), ev)
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

// MarkResultDone 标记一个结果已报告（target|templateID|severity）。
func (s *Scanner) MarkResultDone(target, templateID, severity string) {
	key := target + "|" + templateID + "|" + severity
	s.resultDedup.Store(key, true)
}

// ResultAlreadyReported 检查该结果是否已被报告过。
func (s *Scanner) ResultAlreadyReported(target, templateID, severity string) bool {
	key := target + "|" + templateID + "|" + severity
	_, exists := s.resultDedup.Load(key)
	return exists
}

// ClearResultDedup 清除结果去重缓存（用于新扫描批次）。
func (s *Scanner) ClearResultDedup() {
	s.resultDedup = sync.Map{}
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

// logRequest logs an outgoing HTTP request.
// INFO level (-v): method + path summary via structured logger.
// -vv level: Burp-style packet dump via onPacket callback.
func (s *Scanner) logRequest(tmplID string, i int, raw string) {
	method, path := httpclient.ParseMethodPath(raw)

	// INFO: request summary (visible at -v)
	if s.logger != nil {
		s.logger.InfoKV("HTTP request sent",
			"template", tmplID, "req", i,
			"method", method, "path", path, "bytes", len(raw))
	}

	// -v+: Burp-style packet dump
	if s.verbose >= 1 && s.onPacket != nil {
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

	// -v+: Burp-style packet dump
	if s.verbose >= 1 && s.onPacket != nil {
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

// truncateStr truncates s to max display width with ellipsis.
func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// statusStr returns "PASS" or "FAIL" for a matcher result.
func statusStr(matched bool) string {
	if matched {
		return "PASS"
	}
	return "FAIL"
}

// typesStr returns a comma-separated list of matcher types.
func typesStr(ms []types.Matcher) string {
	var parts []string
	for _, m := range ms {
		parts = append(parts, m.Type)
	}
	return strings.Join(parts, ",")
}

// noopPluginLogger is a no-op implementation of plugin.Logger.
// Used when no logger is configured to prevent nil pointer panics.
type noopPluginLogger struct {
	id string
}

func (l *noopPluginLogger) Info(msg string, args ...interface{})   {}
func (l *noopPluginLogger) Debug(msg string, args ...interface{})  {}
func (l *noopPluginLogger) Error(msg string, args ...interface{})  {}

// parseDuration parses a duration string, falling back to 2s on error.
func parseDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 2 * time.Second
	}
	return d
}

// mustCreateCookieJar creates an RFC 6265-compliant cookie jar.
// Panics on error — this should never happen with default options.
func mustCreateCookieJar() http.CookieJar {
	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(fmt.Sprintf("failed to create cookie jar: %v", err))
	}
	return jar
}
