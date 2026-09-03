package distributed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/gosleek/gosleek/internal/config"
	"github.com/gosleek/gosleek/internal/engine"
	"github.com/gosleek/gosleek/internal/plugin"
	"github.com/gosleek/gosleek/internal/template"
	"github.com/gosleek/gosleek/pkg/types"
)

// Scheduler 是 Master 节点的任务调度器。
// 负责管理节点池、分发扫描任务、收集结果。
type Scheduler struct {
	pool     *NodePool
	taskQueue chan *ScanJob
	resultCh  chan *JobResult
	logger    LoggerIface
	stopCh    chan struct{}
	once      sync.Once // 防止 Stop 被多次调用导致 panic
	wg        sync.WaitGroup

	// 任务状态跟踪
	pending    sync.Map // jobID -> *pendingTask
	resultMu   sync.Mutex
	allResults []*JobResult
}

// pendingTask 跟踪一个待处理的 ScanJob。
type pendingTask struct {
	job     *ScanJob
	results []*JobResult
	mu      sync.Mutex
	done    chan struct{}
}

// NewScheduler 创建一个新的任务调度器。
func NewScheduler(logger LoggerIface) *Scheduler {
	return &Scheduler{
		pool:      NewNodePool(),
		taskQueue: make(chan *ScanJob, 128),
		resultCh:  make(chan *JobResult, 256),
		logger:    logger,
		stopCh:    make(chan struct{}),
	}
}

// RegisterNode 注册一个节点到节点池。
func (s *Scheduler) RegisterNode(node *NodeInfo) {
	if node.Role == 0 {
		node.Role = NodeRoleWorker // 注册到 Master 的节点默认视为 Worker
	}
	if node.Status == "" {
		node.Status = "online"
	}
	node.LastSeen = time.Now()
	s.pool.Add(node)
	if s.logger != nil {
		s.logger.Info("节点已注册", "id", node.ID, "address", node.Address)
	}
}

// UnregisterNode 注销一个节点。
func (s *Scheduler) UnregisterNode(nodeID string) {
	s.pool.Remove(nodeID)
	if s.logger != nil {
		s.logger.Info("节点已注销", "id", nodeID)
	}
}

// GetNodes 返回所有节点。
func (s *Scheduler) GetNodes() []*NodeInfo {
	return s.pool.GetAll()
}

// GetOnlineNodes 返回在线节点。
func (s *Scheduler) GetOnlineNodes() []*NodeInfo {
	return s.pool.GetOnline()
}

// DispatchJob 分发一个扫描任务到集群。
// 返回一个 channel，调度器会将结果推送至此 channel。
// 调用方应从 channel 读取结果直到 channel 关闭。
func (s *Scheduler) DispatchJob(job *ScanJob) <-chan *JobResult {
	if job == nil {
		return nil
	}

	// 创建 pending task
	done := make(chan struct{})
	pt := &pendingTask{job: job, done: done}
	s.pending.Store(job.JobID, pt)

	// 入队
	select {
	case s.taskQueue <- job:
		// 成功入队
	case <-s.stopCh:
		ch := make(chan *JobResult, 1)
		ch <- &JobResult{
			JobID: job.JobID,
			Error: "scheduler stopped",
		}
		close(done)
		return ch
	}

	// 返回结果 channel
	ch := make(chan *JobResult, 1)
	go func() {
		<-done
		pt.mu.Lock()
		results := pt.results
		pt.mu.Unlock()
		for _, r := range results {
			ch <- r
		}
		close(ch)
	}()

	// 启动结果收集协程
	s.wg.Add(1)
	go s.collectResults(job.JobID, pt, ch)

	return ch
}

// collectResults 收集单个任务的所有 Worker 响应。
func (s *Scheduler) collectResults(jobID string, pt *pendingTask, resultCh chan<- *JobResult) {
	defer s.wg.Done()

	for {
		select {
		case result := <-s.resultCh:
			if result.JobID != jobID {
				continue
			}
			pt.mu.Lock()
			pt.results = append(pt.results, result)
			pt.mu.Unlock()

			// 转发到输出 channel
			select {
			case resultCh <- result:
			default:
			}

			if s.logger != nil {
				s.logger.Info("收到 Worker 结果",
					"job_id", result.JobID,
					"matched", result.Stats.Matched)
			}
		case <-pt.done:
			return
		case <-s.stopCh:
			return
		}
	}
}

// Start 启动调度器的主循环，从 taskQueue 取任务并分发给 Worker。
func (s *Scheduler) Start(cfg *config.GlobalConfig, templates []*types.Template, plugins []plugin.Plugin) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.dispatchLoop(cfg, templates, plugins)
	}()
}

// dispatchLoop 持续从队列取任务并分发给 Worker。
func (s *Scheduler) dispatchLoop(cfg *config.GlobalConfig, templates []*types.Template, plugins []plugin.Plugin) {
	for {
		select {
		case job := <-s.taskQueue:
			s.dispatchToWorkers(job, cfg, templates, plugins)
		case <-s.stopCh:
			return
		}
	}
}

// dispatchToWorkers 将任务分发给所有在线 Worker。
func (s *Scheduler) dispatchToWorkers(job *ScanJob, cfg *config.GlobalConfig,
	templates []*types.Template, plugins []plugin.Plugin) {

	// 无目标则直接返回
	if len(job.Targets) == 0 {
		if pt, ok := s.pending.Load(job.JobID); ok {
			if p, ok := pt.(*pendingTask); ok {
				p.mu.Lock()
				p.results = append(p.results, &JobResult{
					JobID: job.JobID,
					Stats: JobStats{TotalJobs: 0, Completed: 0, Matched: 0},
				})
				p.mu.Unlock()
				close(p.done)
			}
		}
		return
	}

	workers := s.getEligibleWorkers()
	if len(workers) == 0 {
		if s.logger != nil {
			s.logger.Warn("无可用 Worker，任务回退到本地执行", "job_id", job.JobID)
		}
		// 回退：在 Master 本地执行
		s.executeLocally(job, cfg, templates, plugins)
		return
	}

	// 按 Round-Robin 分配目标
	targetsPerWorker := distributeTargets(job.Targets, workers)

	for i, worker := range workers {
		go s.executeOnWorker(job, worker, targetsPerWorker[i], cfg)
	}
}

// getEligibleWorkers 返回状态为 online/busy 的 Worker 列表。
func (s *Scheduler) getEligibleWorkers() []*NodeInfo {
	nodes := s.pool.GetOnline()
	var workers []*NodeInfo
	for _, n := range nodes {
		if n.Role == NodeRoleWorker {
			workers = append(workers, n)
		}
	}
	return workers
}

// distributeTargets 将目标列表按 Round-Robin 分配给 Worker。
func distributeTargets(targets []string, workers []*NodeInfo) [][]string {
	distributed := make([][]string, len(workers))
	for i, t := range targets {
		wIdx := i % len(workers)
		distributed[wIdx] = append(distributed[wIdx], t)
	}
	return distributed
}

// httpClient 是全局 HTTP 客户端，复用连接。
var httpClient = &http.Client{
	Timeout: 5 * time.Minute,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     90 * time.Second,
	},
}

// executeOnWorker 通过 HTTP 将任务发送到远程 Worker 执行。
// 如果远程调用失败，则回退到本地执行。
func (s *Scheduler) executeOnWorker(job *ScanJob, worker *NodeInfo, targets []string, cfg *config.GlobalConfig) {
	if len(targets) == 0 {
		return
	}

	worker.Status = "busy"
	start := time.Now()

	// 构造带 JobConfig 覆盖的远程任务
	localCfg := cloneConfig(cfg)
	if job.Config.Concurrency > 0 {
		localCfg.Concurrency = job.Config.Concurrency
	}
	if job.Config.RateLimit > 0 {
		localCfg.RateLimit = job.Config.RateLimit
	}
	if job.Config.Timeout > 0 {
		localCfg.DefaultTimeout = job.Config.Timeout
	}

	remoteJob := &ScanJob{
		JobID:       job.JobID,
		Targets:     targets,
		TemplateIDs: job.TemplateIDs,
		Config: JobConfig{
			Concurrency: localCfg.Concurrency,
			RateLimit:   localCfg.RateLimit,
			Timeout:     localCfg.DefaultTimeout,
			Proxy:       job.Config.Proxy,
			Insecure:    job.Config.Insecure,
		},
	}

	// 尝试通过 HTTP 发送到远程 Worker
	result := s.sendToWorker(worker.Address, remoteJob)

	duration := time.Since(start).Milliseconds()
	if result == nil {
		// 远程调用失败，回退到本地执行
		if s.logger != nil {
			s.logger.Warn("远程 Worker 不可用，回退本地执行", "worker_id", worker.ID, "address", worker.Address)
		}
		result = s.executeLocallyOnTargets(localCfg, job.JobID, targets)
		duration = time.Since(start).Milliseconds()
	}

	result.Stats.DurationMs = duration

	// 发送结果
	select {
	case s.resultCh <- result:
	default:
		if s.logger != nil {
			s.logger.Warn("结果 channel 满，丢弃结果", "job_id", job.JobID)
		}
	}

	worker.Status = "online"
	worker.CompletedJobs++
	worker.MatchedJobs += int64(len(result.Results))

	if s.logger != nil {
		s.logger.Info("Worker 完成任务",
			"worker_id", worker.ID,
			"job_id", job.JobID,
			"targets", len(targets),
			"matched", len(result.Results),
			"duration_ms", duration)
	}
}

// sendToWorker 通过 HTTP POST 将任务发送到远程 Worker。
func (s *Scheduler) sendToWorker(workerAddr string, job *ScanJob) *JobResult {
	url := fmt.Sprintf("http://%s/job", workerAddr)
	body, err := json.Marshal(job)
	if err != nil {
		return nil
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		if s.logger != nil {
			s.logger.Warn("Worker 返回非 200 状态", "status", resp.StatusCode, "body", string(bodyBytes))
		}
		return nil
	}

	var result JobResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil
	}
	return &result
}

// executeLocallyOnTargets 在本地执行扫描（无 Worker 时的回退）。
func (s *Scheduler) executeLocallyOnTargets(cfg *config.GlobalConfig, jobID string, targets []string) *JobResult {
	start := time.Now()
	scanner := engine.NewScanner(cfg, 0, engine.OOBConfig{}, "", false)
	results := scanner.Run(context.Background(), nil, nil, targets)
	duration := time.Since(start).Milliseconds()
	stats := JobStats{
		TotalJobs:  int64(len(targets)),
		Completed:  int64(len(targets)),
		Matched:    int64(len(results)),
		DurationMs: duration,
	}
	return &JobResult{JobID: jobID, Results: results, Stats: stats}
}

// executeLocally 在 Master 节点本地执行任务。
func (s *Scheduler) executeLocally(job *ScanJob, cfg *config.GlobalConfig,
	templates []*types.Template, plugins []plugin.Plugin) {

	start := time.Now()
	scanner := engine.NewScanner(cfg, 0, engine.OOBConfig{}, "", false)
	results := scanner.Run(context.Background(), templates, plugins, job.Targets)
	duration := time.Since(start).Milliseconds()

	stats := JobStats{
		TotalJobs:  int64(len(job.Targets)),
		Completed:  int64(len(job.Targets)),
		Matched:    int64(len(results)),
		DurationMs: duration,
	}

	result := &JobResult{
		JobID:   job.JobID,
		Results: results,
		Stats:   stats,
	}

	// 通知 pending task
	if pt, ok := s.pending.Load(job.JobID); ok {
		if p, ok := pt.(*pendingTask); ok {
			p.mu.Lock()
			p.results = append(p.results, result)
			p.mu.Unlock()
			close(p.done)
		}
	}

	// 记录结果
	s.resultMu.Lock()
	s.allResults = append(s.allResults, result)
	s.resultMu.Unlock()

	if s.logger != nil {
		s.logger.Info("本地完成任务",
			"job_id", job.JobID,
			"targets", len(job.Targets),
			"matched", len(results))
	}
}

// Stop 停止调度器。只执行一次，重复调用安全。
func (s *Scheduler) Stop() {
	s.once.Do(func() {
		close(s.stopCh)
		s.wg.Wait()
	})
}

// GetResults 返回所有收集到的结果。
func (s *Scheduler) GetResults() []*JobResult {
	s.resultMu.Lock()
	defer s.resultMu.Unlock()
	cp := make([]*JobResult, len(s.allResults))
	copy(cp, s.allResults)
	return cp
}

// LoadTemplates 从模板目录加载模板，并按 TemplateIDs 过滤。
func LoadTemplates(templateDir string, templateIDs []string) ([]*types.Template, error) {
	allTemplates, err := template.LoadDir(templateDir)
	if err != nil {
		return nil, fmt.Errorf("load templates: %w", err)
	}

	if len(templateIDs) == 0 {
		return allTemplates, nil
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

// cloneConfig 浅拷贝 GlobalConfig（字段可直接赋值）。
func cloneConfig(cfg *config.GlobalConfig) *config.GlobalConfig {
	return &config.GlobalConfig{
		UserAgent:            cfg.UserAgent,
		DefaultTimeout:       cfg.DefaultTimeout,
		MaxRedirects:         cfg.MaxRedirects,
		FollowRedirect:       cfg.FollowRedirect,
		MaxBodySize:          cfg.MaxBodySize,
		AllowExternal:        cfg.AllowExternal,
		Concurrency:          cfg.Concurrency,
		RateLimit:            cfg.RateLimit,
		MaxRetries:           cfg.MaxRetries,
		RetryBackoff:         cfg.RetryBackoff,
		MaxCartesianProducts: cfg.MaxCartesianProducts,
		TemplateDir:          cfg.TemplateDir,
		LogFile:              cfg.LogFile,
		LogLevel:             cfg.LogLevel,
		OOB:                  cfg.OOB,
	}
}

