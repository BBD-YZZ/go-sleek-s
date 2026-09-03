package webui

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gosleek/gosleek/pkg/types"
)

// ---------------------------------------------------------------------------
// 嵌入的模板文件
// ---------------------------------------------------------------------------

//go:embed templates
var templatesFS embed.FS

// ---------------------------------------------------------------------------
// 日志接口：与 engine.LoggerIface 保持一致
// ---------------------------------------------------------------------------

// LoggerIface 是 Web UI 使用的最小日志接口。
type LoggerIface interface {
	DebugKV(msg string, args ...interface{})
	InfoKV(msg string, args ...interface{})
	WarnKV(msg string, args ...interface{})
	Error(msg string, args ...interface{})
}

// ---------------------------------------------------------------------------
// 任务结构
// ---------------------------------------------------------------------------

// Task 表示一个被 Web UI 管理的扫描任务。
type Task struct {
	ID           string              `json:"id"`
	Name         string              `json:"name"`
	Targets      []string            `json:"targets"`
	Templates    []string            `json:"templates"`
	Status       string              `json:"status"` // "running" / "completed" / "stopped"
	StartedAt    time.Time           `json:"started_at"`
	CompletedAt  time.Time           `json:"completed_at"`
	ResultCount  int                 `json:"result_count"`
	Total        int                 `json:"total"`
	Matched      int                 `json:"matched"`
	Results      []*types.Result     `json:"results,omitempty"`
	resultsMu    sync.RWMutex        // 保护 Results 字段
	onResult     func(*types.Result) // 扫描引擎回调
}

// ---------------------------------------------------------------------------
// Server 结构
// ---------------------------------------------------------------------------

// Server 是 Web UI 的核心服务器，负责管理扫描任务和结果展示。
type Server struct {
	mu            sync.RWMutex
	results       []*types.Result
	resultsMu     sync.RWMutex // 单独保护结果切片，避免与 task 互锁
	tasks         map[string]*Task
	taskIDCounter int64
	addr          string
	srv           *http.Server
	logger        LoggerIface
	templates     *template.Template
	onAddResult   func(*types.Result) // 引擎回调，由 cmd 层注册（如 scan 命令）
	dedupCount    int64               // 引擎去重跳过数

	// SSE 订阅管理
	sseMu      sync.Mutex
	sseClients []*sseClient
	resultChan chan *types.Result // 广播新结果给所有 SSE 客户端
	taskChan   chan taskEvent     // 广播任务状态变化
}

// sseClient 表示一个 SSE 长连接客户端
type sseClient struct {
	writer http.ResponseWriter
	flush  http.Flusher
}

// taskEvent 表示任务状态变化事件
type taskEvent struct {
	taskID string
	status string
}

// ---------------------------------------------------------------------------
// 构造函数
// ---------------------------------------------------------------------------

// NewServer 创建一个 Web UI 服务器实例。
func NewServer(addr string, logger LoggerIface) *Server {
	s := &Server{
		addr:       addr,
		logger:     logger,
		tasks:      make(map[string]*Task),
		resultChan: make(chan *types.Result, 256),
		taskChan:   make(chan taskEvent, 64),
	}
	s.loadTemplates()
	s.setupRoutes()
	return s
}

// loadTemplates 加载并编译嵌入的 HTML 模板。
func (s *Server) loadTemplates() {
	s.templates = template.Must(template.New("").Funcs(template.FuncMap{
		// toUpper 将字符串转大写（用于严重度标签显示）
		"toUpper": strings.ToUpper,
		// formatTime 格式化时间
		"formatTime": func(t time.Time) string {
			if t.IsZero() {
				return "-"
			}
			return t.Format("2006-01-02 15:04:05")
		},
		// truncate 截断字符串（模板管道调用时参数顺序：value | truncate n）
		"truncate": func(n int, s string) string {
			if len(s) <= n {
				return s
			}
			return s[:n] + "..."
		},
		// severityColor 根据严重度返回 CSS 颜色
		"severityColor": func(sev string) string {
			switch sev {
			case types.SeverityCritical:
				return "#e74c3c"
			case types.SeverityHigh:
				return "#e67e22"
			case types.SeverityMedium:
				return "#f1c40f"
			case types.SeverityLow:
				return "#3498db"
			case types.SeverityInfo:
				return "#95a5a6"
			default:
				return "#7f8c8d"
			}
		},
	}).ParseFS(templatesFS, "templates/*.html"))
}

// setupRoutes 注册所有 HTTP 路由。
func (s *Server) setupRoutes() {
	mux := http.NewServeMux()

	// ── 页面路由 ─────────────────────────────────────────────────────────
	mux.HandleFunc("/", s.handleIndex)

	// ── SSE 实时推送路由 ─────────────────────────────────────────────────
	mux.HandleFunc("/api/events", s.handleSSE)

	// ── API 路由：任务 ────────────────────────────────────────────────────
	mux.HandleFunc("/api/tasks", s.handleTasks)
	mux.HandleFunc("/api/tasks/", s.handleTaskDetail)

	// ── API 路由：结果 ────────────────────────────────────────────────
	mux.HandleFunc("/api/results", s.handleResults)
	mux.HandleFunc("/api/results/severity", s.handleSeverityStats)
	mux.HandleFunc("/api/results/targets", s.handleTargetStats)
	mux.HandleFunc("/api/results/dedup", s.handleDedupStats)
	mux.HandleFunc("/api/results/dedup/reset", s.handleDedupReset)
	mux.HandleFunc("/api/results/dedup/update", s.handleDedupUpdate)

	s.srv = &http.Server{
		Addr:         s.addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
}

// ---------------------------------------------------------------------------
// 公共方法：任务管理
// ---------------------------------------------------------------------------

// AddTask 创建并启动一个新的扫描任务。
// 返回新创建的 Task（Status 为 "running"），调用方需要通过回调驱动扫描。
func (s *Server) AddTask(name string, targets []string, templates []string) *Task {
	s.mu.Lock()
	s.taskIDCounter++
	id := fmt.Sprintf("task-%d", s.taskIDCounter)
	task := &Task{
		ID:        id,
		Name:      name,
		Targets:   targets,
		Templates: templates,
		Status:    "running",
		StartedAt: time.Now(),
	}
	s.tasks[id] = task
	s.mu.Unlock()

	if s.logger != nil {
		s.logger.InfoKV("创建扫描任务", "id", id, "name", name, "targets", len(targets))
	}
	return task
}

// GetTasks 返回所有任务列表（按创建时间倒序）。
func (s *Server) GetTasks() []*Task {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Task, 0, len(s.tasks))
	for _, t := range s.tasks {
		out = append(out, t)
	}
	// 按 StartedAt 倒序
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// GetTask 根据 ID 获取任务，不存在返回 nil。
func (s *Server) GetTask(id string) *Task {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tasks[id]
}

// CompleteTask 标记任务为已完成（扫描结束后调用）。
func (s *Server) CompleteTask(id string, resultCount, total, matched int) bool {
	s.mu.Lock()
	task, ok := s.tasks[id]
	if !ok {
		s.mu.Unlock()
		return false
	}
	task.Status = "completed"
	task.CompletedAt = time.Now()
	task.ResultCount = resultCount
	task.Total = total
	task.Matched = matched
	s.mu.Unlock()

	// 广播到 SSE 客户端
	s.broadcastTaskEvent(id, "completed")
	return true
}

// StopTask 停止指定任务（标记为 stopped）。
func (s *Server) StopTask(id string) bool {
	s.mu.Lock()
	task, ok := s.tasks[id]
	if !ok {
		s.mu.Unlock()
		return false
	}
	if task.Status != "running" {
		s.mu.Unlock()
		return false
	}
	task.Status = "stopped"
	task.CompletedAt = time.Now()
	s.mu.Unlock()

	// 广播到 SSE 客户端
	s.broadcastTaskEvent(id, "stopped")
	return true
}

// ---------------------------------------------------------------------------
// 公共方法：结果管理
// ---------------------------------------------------------------------------

// OnAddResult sets the callback for engine result delivery (optional).
// When set, results flowing through the engine are automatically recorded in Web UI.
func (s *Server) OnAddResult(fn func(*types.Result)) {
	s.onAddResult = fn
}

// UpdateDedupStats 更新引擎去重统计（由 cmd 层在扫描结束后调用）。
func (s *Server) UpdateDedupStats(resultDedup, jobDedup int64) {
	s.resultsMu.Lock()
	defer s.resultsMu.Unlock()
	s.dedupCount = resultDedup
}

// AddResult 记录一条扫描结果。同时追加到任务和全局结果中。
func (s *Server) AddResult(r *types.Result) {
	s.resultsMu.Lock()
	s.results = append(s.results, r)
	s.resultsMu.Unlock()

	// 引擎回调（由 cmd_scan.go 注册后，scan 结果会自动流入 webui）
	if s.onAddResult != nil {
		s.onAddResult(r)
	}

	// 追加到所有 running 任务中
	s.mu.RLock()
	for _, task := range s.tasks {
		if task.Status == "running" {
			task.resultsMu.Lock()
			task.Results = append(task.Results, r)
			task.resultsMu.Unlock()
			if task.onResult != nil {
				task.onResult(r)
			}
		}
	}
	s.mu.RUnlock()

	// 广播到 SSE 客户端
	select {
	case s.resultChan <- r:
	default:
		// channel 满时丢弃，避免阻塞引擎
	}
}

// GetResults 返回所有结果。
func (s *Server) GetResults() []*types.Result {
	s.resultsMu.RLock()
	defer s.resultsMu.RUnlock()
	out := make([]*types.Result, len(s.results))
	copy(out, s.results)
	return out
}

// ---------------------------------------------------------------------------
// 生命周期
// ---------------------------------------------------------------------------

// Start 启动 HTTP 服务器（在 goroutine 中运行）。
// 先用 dial 探测端口是否已被占用，避免 Windows SO_REUSEADDR 导致的静默重复绑定。
func (s *Server) Start() error {
	// 确保 addr 格式正确（支持 "9090" → ":9090"）
	addr := normalizeListenAddr(s.addr)

	// 探测端口是否已被占用
	if isPortInUse(addr) {
		return fmt.Errorf("webui: 端口已被占用 (%s)", addr)
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("webui: 启动失败 (%s): %w", addr, err)
	}

	// 启动时更新实际监听地址（可能经过 normalize）
	s.addr = addr
	go func() {
		if s.logger != nil {
			s.logger.InfoKV("Web UI 启动", "addr", s.addr)
		}
		if err := s.srv.Serve(ln); err != nil && !strings.Contains(err.Error(), "use of closed") {
			if s.logger != nil {
				s.logger.Error("Web UI 服务异常", "error", err)
			}
		}
	}()
	return nil
}

// isPortInUse 检查指定地址是否已有进程在监听
func isPortInUse(addr string) bool {
	// 支持裸端口（如 "9090"），统一转为 ":9090"
	if !strings.Contains(addr, ":") {
		addr = ":" + addr
	}
	conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		return false // 连接失败，端口可用
	}
	conn.Close()
	return true // 能连上，端口已被占用
}

// normalizeListenAddr 将裸端口（如 "9090"）统一转为带冒号格式（":9090"）。
func normalizeListenAddr(addr string) string {
	if strings.Contains(addr, ":") {
		return addr
	}
	// 验证是否为合法端口号
	_, _, err := net.SplitHostPort(":" + addr)
	if err != nil {
		return addr // 不是合法端口，原样返回（net.Listen 会报标准错误）
	}
	return ":" + addr
}

// Stop 优雅关闭 HTTP 服务器。
func (s *Server) Stop(ctx context.Context) error {
	if s.srv == nil {
		return nil
	}
	if s.logger != nil {
		s.logger.InfoKV("Web UI 正在停止")
	}
	return s.srv.Shutdown(ctx)
}

// Addr 返回服务器监听地址。
func (s *Server) Addr() string {
	return s.addr
}

// ---------------------------------------------------------------------------
// HTTP Handler：页面
// ---------------------------------------------------------------------------

// handleIndex 渲染仪表盘主页。
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	s.resultsMu.RLock()
	allResults := make([]*types.Result, len(s.results))
	copy(allResults, s.results)
	s.resultsMu.RUnlock()

	s.mu.RLock()
	allTasks := make([]*Task, 0, len(s.tasks))
	for _, t := range s.tasks {
		allTasks = append(allTasks, t)
	}
	s.mu.RUnlock()

	total := len(allResults)
	crit := countBySeverity(allResults, types.SeverityCritical)
	high := countBySeverity(allResults, types.SeverityHigh)
	med := countBySeverity(allResults, types.SeverityMedium)
	low := countBySeverity(allResults, types.SeverityLow)
	info := countBySeverity(allResults, types.SeverityInfo)

	// 计算饼图各段的角度（cumulative degrees for conic-gradient）
	var criticalPct, criticalHighPct, mediumPct, lowPct float64
	if total > 0 {
		criticalPct = float64(crit) / float64(total) * 360
		criticalHighPct = float64(crit+high) / float64(total) * 360
		mediumPct = float64(crit+high+med) / float64(total) * 360
		lowPct = float64(crit+high+med+low) / float64(total) * 360
	}

	// 目标统计：按目标 URL 分组计数
	type targetStat struct {
		Target string `json:"target"`
		Count  int    `json:"count"`
		BarPct float64 `json:"bar_pct"`
	}
	targetCounts := make(map[string]int)
	for _, r := range allResults {
		targetCounts[r.Target]++
	}
	maxCount := 0
	for _, c := range targetCounts {
		if c > maxCount {
			maxCount = c
		}
	}
	targetStats := make([]targetStat, 0, len(targetCounts))
	for tgt, cnt := range targetCounts {
		targetStats = append(targetStats, targetStat{
			Target: tgt,
			Count:  cnt,
			BarPct: float64(cnt) / float64(maxCount) * 100,
		})
	}

	data := map[string]interface{}{
		"Tasks":         allTasks,
		"Results":       allResults,
		"Total":         total,
		"DedupCount":    atomic.LoadInt64(&s.dedupCount),
		"Running":       countByStatus(allTasks, "running"),
		"Completed":     countByStatus(allTasks, "completed"),
		"Stopped":       countByStatus(allTasks, "stopped"),
		"Critical":      crit,
		"High":          high,
		"Medium":        med,
		"Low":           low,
		"Info":          info,
		"CriticalPct":   criticalPct,
		"CriticalHighPct": criticalHighPct,
		"MediumPct":     mediumPct,
		"LowPct":        lowPct,
		"TargetStats":   targetStats,
		"ServerAddr":    s.addr,
	}
	buf := new(bytes.Buffer)
	if err := s.templates.ExecuteTemplate(buf, "index.html", data); err != nil {
		http.Error(w, "模板渲染失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := w.Write(buf.Bytes()); err != nil {
		if s.logger != nil {
			s.logger.Error("写入响应失败", "error", err)
		}
	}
}

// ---------------------------------------------------------------------------
// HTTP Handler：API - 任务列表
// ---------------------------------------------------------------------------

// handleTasks 处理 GET /api/tasks 和 POST /api/tasks。
func (s *Server) handleTasks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	switch r.Method {
	case http.MethodGet:
		s.mu.RLock()
		list := make([]*Task, 0, len(s.tasks))
		for _, t := range s.tasks {
			list = append(list, t)
		}
		s.mu.RUnlock()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"total": len(list),
			"tasks": list,
		})

	case http.MethodPost:
		var req struct {
			Name      string   `json:"name"`
			Targets   []string `json:"targets"`
			Templates []string `json:"templates"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "请求体解析失败: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Name == "" {
			http.Error(w, "任务名称不能为空", http.StatusBadRequest)
			return
		}
		task := s.AddTask(req.Name, req.Targets, req.Templates)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(task)

	default:
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
	}
}

// handleTaskDetail 处理 GET/POST /api/tasks/{id}。
func (s *Server) handleTaskDetail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	id := strings.TrimPrefix(r.URL.Path, "/api/tasks/")
	if id == "" {
		http.Error(w, "任务 ID 不能为空", http.StatusBadRequest)
		return
	}

	// 处理 /api/tasks/{id}/stop
	if strings.HasSuffix(id, "/stop") {
		taskID := strings.TrimSuffix(id, "/stop")
		if ok := s.StopTask(taskID); ok {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
		} else {
			http.Error(w, "任务不存在或已停止", http.StatusNotFound)
		}
		return
	}

	// 处理 /api/tasks/{id}/complete（scan 命令扫描结束时调用）
	if strings.HasSuffix(id, "/complete") {
		taskID := strings.TrimSuffix(id, "/complete")
		var req struct {
			ResultCount int `json:"result_count"`
			Total       int `json:"total"`
			Matched     int `json:"matched"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if ok := s.CompleteTask(taskID, req.ResultCount, req.Total, req.Matched); ok {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "completed"})
		} else {
			http.Error(w, "任务不存在", http.StatusNotFound)
		}
		return
	}

	switch r.Method {
	case http.MethodGet:
		task := s.GetTask(id)
		if task == nil {
			http.Error(w, "任务不存在", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(task)

	default:
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// HTTP Handler：API - 结果
// ---------------------------------------------------------------------------

// handleResults 处理 GET /api/results 和 POST /api/results（从 scan 命令接收结果）。
func (s *Server) handleResults(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	switch r.Method {
	case http.MethodGet:
		s.resultsMu.RLock()
		all := make([]*types.Result, len(s.results))
		copy(all, s.results)
		s.resultsMu.RUnlock()

		// 支持查询参数过滤
		severity := r.URL.Query().Get("severity")
		target := r.URL.Query().Get("target")

		filtered := all[:0]
		for _, res := range all {
			if severity != "" && !strings.EqualFold(res.Severity, severity) {
				continue
			}
			if target != "" && !strings.Contains(res.Target, target) {
				continue
			}
			filtered = append(filtered, res)
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"total":    len(filtered),
			"results":  filtered,
			"filtered": len(filtered) < len(all),
		})

	case http.MethodPost:
		// scan 命令推送结果
		var input struct {
			TemplateID  string    `json:"template-id"`
			Name        string    `json:"name"`
			Severity    string    `json:"severity"`
			Target      string    `json:"target"`
			MatchedAt   string    `json:"matched-at"`
			Evidence    string    `json:"evidence,omitempty"`
			Timestamp   string    `json:"timestamp"`
			RawRequest  string    `json:"raw-request,omitempty"`
			RawResponse string    `json:"raw-response,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, "请求体解析失败: "+err.Error(), http.StatusBadRequest)
			return
		}
		ts, _ := time.Parse(time.RFC3339, input.Timestamp)
		if ts.IsZero() {
			ts = time.Now()
		}
		result := &types.Result{
			TemplateID:  input.TemplateID,
			Name:        input.Name,
			Severity:    input.Severity,
			Target:      input.Target,
			MatchedAt:   input.MatchedAt,
			Evidence:    input.Evidence,
			Timestamp:   ts,
			RawRequest:  input.RawRequest,
			RawResponse: input.RawResponse,
		}
		s.AddResult(result)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "id": result.TemplateID})

	default:
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
	}
}

// handleSeverityStats 处理 GET /api/results/severity。
func (s *Server) handleSeverityStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.Method != http.MethodGet {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	s.resultsMu.RLock()
	defer s.resultsMu.RUnlock()

	counts := map[string]int{
		types.SeverityCritical: 0,
		types.SeverityHigh:     0,
		types.SeverityMedium:   0,
		types.SeverityLow:      0,
		types.SeverityInfo:     0,
	}
	for _, res := range s.results {
		counts[res.Severity]++
	}
	_ = json.NewEncoder(w).Encode(counts)
}

// handleTargetStats 处理 GET /api/results/targets。
func (s *Server) handleTargetStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.Method != http.MethodGet {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	s.resultsMu.RLock()
	defer s.resultsMu.RUnlock()

	// 按目标 URL 分组统计
	counts := make(map[string]int)
	for _, res := range s.results {
		counts[res.Target]++
	}

	type targetCount struct {
		Target string `json:"target"`
		Count  int    `json:"count"`
	}
	out := make([]targetCount, 0, len(counts))
	for t, c := range counts {
		out = append(out, targetCount{Target: t, Count: c})
	}
	_ = json.NewEncoder(w).Encode(out)
}

// handleDedupStats 处理 GET /api/results/dedup。
func (s *Server) handleDedupStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.Method != http.MethodGet {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}
	s.resultsMu.RLock()
	defer s.resultsMu.RUnlock()
	_ = json.NewEncoder(w).Encode(map[string]int64{
		"result_dedup": atomic.LoadInt64(&s.dedupCount),
	})
}

// handleDedupReset 处理 DELETE /api/results/dedup/reset。
func (s *Server) handleDedupReset(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.Method != http.MethodDelete {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}
	s.resultsMu.Lock()
	s.dedupCount = 0
	s.resultsMu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "cleared"})
}

// handleDedupUpdate 处理 POST /api/results/dedup/update（scan 命令扫描结束后推送）。
func (s *Server) handleDedupUpdate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.Method != http.MethodPost {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ResultDedup int64 `json:"result_dedup"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "请求体解析失败: "+err.Error(), http.StatusBadRequest)
		return
	}
	s.resultsMu.Lock()
	s.dedupCount = req.ResultDedup
	s.resultsMu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
}

// handleSSE 处理 Server-Sent Events 实时推送连接。
// 客户端订阅后，服务端持续推送新结果和任务状态变更。
func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	client := &sseClient{writer: w, flush: flusher}

	// 注册客户端
	s.sseMu.Lock()
	s.sseClients = append(s.sseClients, client)
	s.sseMu.Unlock()

	// 发送初始握手事件
	fmt.Fprintln(w, "event: connected")
	fmt.Fprintln(w)

	// 当客户端断开时移除
	done := r.Context().Done()
	go func() {
		<-done
		s.sseMu.Lock()
		for i, c := range s.sseClients {
			if c == client {
				s.sseClients = append(s.sseClients[:i], s.sseClients[i+1:]...)
				break
			}
		}
		s.sseMu.Unlock()
	}()

	// 监听结果和任务事件
	for {
		select {
		case <-done:
			return
		case r := <-s.resultChan:
			data, _ := json.Marshal(map[string]interface{}{
				"template_id": r.TemplateID,
				"name":        r.Name,
				"severity":    r.Severity,
				"target":      r.Target,
				"matched_at":  r.MatchedAt,
				"evidence":    r.Evidence,
				"timestamp":   r.Timestamp.Format(time.RFC3339),
			})
			fmt.Fprintf(w, "event: result\ndata: %s\n\n", data)
			flusher.Flush()
		case te := <-s.taskChan:
			data, _ := json.Marshal(map[string]string{
				"task_id": te.taskID,
				"status":  te.status,
			})
			fmt.Fprintf(w, "event: task\ndata: %s\n\n", data)
			flusher.Flush()
		}
	}
}

// broadcastTaskEvent 广播任务状态变化给所有 SSE 客户端。
func (s *Server) broadcastTaskEvent(taskID, status string) {
	select {
	case s.taskChan <- taskEvent{taskID: taskID, status: status}:
	default:
		// channel 满时丢弃，避免阻塞
	}
}

// ---------------------------------------------------------------------------
// 辅助函数
// ---------------------------------------------------------------------------

func countByStatus(tasks []*Task, status string) int {
	n := 0
	for _, t := range tasks {
		if t.Status == status {
			n++
		}
	}
	return n
}

func countBySeverity(results []*types.Result, severity string) int {
	n := 0
	for _, r := range results {
		if r.Severity == severity {
			n++
		}
	}
	return n
}
