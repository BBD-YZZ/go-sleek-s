package distributed

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gosleek/gosleek/internal/config"
	"github.com/gosleek/gosleek/internal/engine"
	"github.com/gosleek/gosleek/internal/plugin"
	"github.com/gosleek/gosleek/internal/template"
	"github.com/gosleek/gosleek/pkg/types"
)

// Worker 是分布式扫描的工作节点。
// 接收 Master 分发的任务，使用本地 engine.Scanner 执行扫描。
// 通过 HTTP 接口暴露 /job 端点供 Master 调用。
type Worker struct {
	ID       string
	Address  string
	cfg      *config.GlobalConfig
	logger   LoggerIface
	nodeInfo *NodeInfo
	stopCh   chan struct{}
	running  atomic.Bool

	// HTTP server
	srv        *http.Server
	httpStopCh chan struct{}
}

// NewWorker 创建一个新的 Worker 节点。
func NewWorker(id, address string, cfg *config.GlobalConfig, logger LoggerIface) *Worker {
	return &Worker{
		ID:         id,
		Address:    address,
		cfg:        cfg,
		logger:     logger,
		nodeInfo:   &NodeInfo{ID: id, Address: address, Role: NodeRoleWorker, Status: "online", Concurrency: cfg.Concurrency, LastSeen: time.Now()},
		stopCh:     make(chan struct{}),
		httpStopCh: make(chan struct{}),
	}
}

// Start 启动 Worker，开启心跳广播和 HTTP 服务。
func (w *Worker) Start() error {
	if w.running.Swap(true) {
		return fmt.Errorf("worker %s already running", w.ID)
	}

	// 启动心跳广播
	go StartHeartbeat(w.nodeInfo, w.stopCh)

	// 启动 HTTP 服务端
	if err := w.startHTTPServer(); err != nil {
		w.running.Store(false)
		return fmt.Errorf("start HTTP server: %w", err)
	}

	if w.logger != nil {
		w.logger.Info("Worker 已启动", "id", w.ID, "address", w.Address)
	}
	return nil
}

// startHTTPServer 启动 HTTP 服务，暴露 /job 和 /info 端点。
func (w *Worker) startHTTPServer() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/job", w.handleJob)
	mux.HandleFunc("/info", w.handleInfo)
	mux.HandleFunc("/health", w.handleHealth)

	addr := w.Address
	// 如果 address 没有端口（如 "192.168.1.1"），加上默认端口
	if !strings.Contains(addr, ":") {
		addr = addr + ":19234"
	}

	w.srv = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// 心跳 UDP 端口由 StartHeartbeat 负责，HTTP server 只负责接收 Master 任务

	if w.logger != nil {
		w.logger.Info("Worker HTTP 监听中", "addr", addr)
	}

	// 异步启动
	go func() {
		if err := w.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			if w.logger != nil {
				w.logger.Error("HTTP 服务异常", "addr", addr, "error", err)
			}
		}
	}()

	return nil
}

// Stop 停止 Worker（HTTP 服务 + 心跳）。
func (w *Worker) Stop() {
	if !w.running.Swap(false) {
		return
	}
	close(w.stopCh)
	close(w.httpStopCh)
	if w.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = w.srv.Shutdown(ctx)
	}
	if w.logger != nil {
		w.logger.Info("Worker 已停止", "id", w.ID)
	}
}

// GetInfo 返回当前节点信息。
func (w *Worker) GetInfo() *NodeInfo {
	w.nodeInfo.LastSeen = time.Now()
	return w.nodeInfo
}

// Addr 返回 Worker 监听地址。
func (w *Worker) Addr() string {
	return w.Address
}

// HandleJob 处理一个扫描任务，返回结果。
func (w *Worker) HandleJob(job *ScanJob) *JobResult {
	if w.logger != nil {
		w.logger.Info("Worker 开始执行任务", "job_id", job.JobID, "targets", len(job.Targets), "templates", len(job.TemplateIDs))
	}

	w.nodeInfo.Status = "busy"
	defer func() { w.nodeInfo.Status = "online" }()

	start := time.Now()

	localCfg := w.cloneConfig()
	if job.Config.Concurrency > 0 {
		localCfg.Concurrency = job.Config.Concurrency
	}
	if job.Config.RateLimit > 0 {
		localCfg.RateLimit = job.Config.RateLimit
	}
	if job.Config.Timeout > 0 {
		localCfg.DefaultTimeout = job.Config.Timeout
	}

	templates, err := w.loadTemplates(job.TemplateIDs)
	if err != nil {
		if w.logger != nil {
			w.logger.Error("加载模板失败", "job_id", job.JobID, "error", err)
		}
		return &JobResult{JobID: job.JobID, Error: err.Error()}
	}

	plugins := w.loadPlugins()

	targets := make([]string, 0, len(job.Targets))
	for _, t := range job.Targets {
		normalized := normalizeTarget(t)
		if normalized != "" {
			targets = append(targets, normalized)
		}
	}

	if len(targets) == 0 {
		return &JobResult{JobID: job.JobID, Error: "no valid targets"}
	}

	scanner := engine.NewScanner(localCfg, 0, engine.OOBConfig{}, job.Config.Proxy, job.Config.Insecure)
	results := scanner.Run(context.Background(), templates, plugins, targets)

	duration := time.Since(start).Milliseconds()
	stats := JobStats{
		TotalJobs:  int64(len(targets)),
		Completed:  int64(len(targets)),
		Matched:    int64(len(results)),
		DurationMs: duration,
	}

	w.nodeInfo.CompletedJobs += int64(len(targets))
	w.nodeInfo.MatchedJobs += int64(len(results))

	if w.logger != nil {
		w.logger.Info("Worker 完成任务", "job_id", job.JobID, "matched", len(results), "duration_ms", duration)
	}

	return &JobResult{JobID: job.JobID, Results: results, Stats: stats}
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP 端点处理
// ─────────────────────────────────────────────────────────────────────────────

// handleJob 处理 POST /job 请求，执行扫描并返回结果。
func (w *Worker) handleJob(wr http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(wr, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var job ScanJob
	if err := json.NewDecoder(r.Body).Decode(&job); err != nil {
		http.Error(wr, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if job.JobID == "" {
		http.Error(wr, "job_id is required", http.StatusBadRequest)
		return
	}

	result := w.HandleJob(&job)

	wr.Header().Set("Content-Type", "application/json; charset=utf-8")
	wr.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(wr).Encode(result)
}

// handleInfo 处理 GET /info 请求，返回节点信息。
func (w *Worker) handleInfo(wr http.ResponseWriter, r *http.Request) {
	info := w.GetInfo()
	wr.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(wr).Encode(info)
}

// handleHealth 处理 GET /health 请求，返回存活状态。
func (w *Worker) handleHealth(wr http.ResponseWriter, r *http.Request) {
	wr.Header().Set("Content-Type", "application/json; charset=utf-8")
	health := map[string]interface{}{
		"status":   "ok",
		"worker_id": w.ID,
		"uptime":   time.Since(w.nodeInfo.LastSeen).String(),
	}
	_ = json.NewEncoder(wr).Encode(health)
}

// ─────────────────────────────────────────────────────────────────────────────
// 私有方法
// ─────────────────────────────────────────────────────────────────────────────

// loadTemplates 加载指定 ID 的模板。
func (w *Worker) loadTemplates(templateIDs []string) ([]*types.Template, error) {
	if len(templateIDs) == 0 {
		return nil, nil
	}
	allTemplates, err := template.LoadDir(w.cfg.TemplateDir)
	if err != nil {
		return nil, fmt.Errorf("load templates: %w", err)
	}
	idSet := make(map[string]bool)
	for _, id := range templateIDs {
		idSet[id] = true
	}
	var result []*types.Template
	for _, tmpl := range allTemplates {
		if idSet[tmpl.ID] {
			result = append(result, tmpl)
		}
	}
	return result, nil
}

// loadPlugins 加载所有已注册的 Go 插件。
func (w *Worker) loadPlugins() []plugin.Plugin {
	return plugin.All()
}

// cloneConfig 浅拷贝配置。
func (w *Worker) cloneConfig() *config.GlobalConfig {
	return &config.GlobalConfig{
		UserAgent:            w.cfg.UserAgent,
		DefaultTimeout:       w.cfg.DefaultTimeout,
		MaxRedirects:         w.cfg.MaxRedirects,
		FollowRedirect:       w.cfg.FollowRedirect,
		MaxBodySize:          w.cfg.MaxBodySize,
		AllowExternal:        w.cfg.AllowExternal,
		Concurrency:          w.cfg.Concurrency,
		RateLimit:            w.cfg.RateLimit,
		MaxRetries:           w.cfg.MaxRetries,
		RetryBackoff:         w.cfg.RetryBackoff,
		MaxCartesianProducts: w.cfg.MaxCartesianProducts,
		TemplateDir:          w.cfg.TemplateDir,
		LogFile:              w.cfg.LogFile,
		LogLevel:             w.cfg.LogLevel,
		OOB:                  w.cfg.OOB,
	}
}

// normalizeTarget 标准化目标 URL。
func normalizeTarget(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	return raw
}
