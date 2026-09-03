package distributed

import (
	"testing"
	"time"

	"github.com/gosleek/gosleek/internal/config"
)

// ─────────────────────────────────────────────────────────────────────────────
// NodePool 测试
// ─────────────────────────────────────────────────────────────────────────────

func TestNodePool_AddAndGet(t *testing.T) {
	pool := NewNodePool()
	node := &NodeInfo{
		ID:        "worker-1",
		Address:   "192.168.1.100:8080",
		Role:      NodeRoleWorker,
		Status:    "online",
		Concurrency: 10,
	}

	pool.Add(node)

	got, ok := pool.Get("worker-1")
	if !ok {
		t.Fatal("expected node to exist")
	}
	if got.ID != "worker-1" {
		t.Errorf("expected ID worker-1, got %s", got.ID)
	}
	if got.Address != "192.168.1.100:8080" {
		t.Errorf("expected address 192.168.1.100:8080, got %s", got.Address)
	}
}

func TestNodePool_Remove(t *testing.T) {
	pool := NewNodePool()
	pool.Add(&NodeInfo{ID: "worker-1", Status: "online"})
	pool.Add(&NodeInfo{ID: "worker-2", Status: "online"})

	pool.Remove("worker-1")

	_, ok := pool.Get("worker-1")
	if ok {
		t.Error("expected worker-1 to be removed")
	}

	nodes := pool.GetAll()
	if len(nodes) != 1 {
		t.Errorf("expected 1 node, got %d", len(nodes))
	}
}

func TestNodePool_GetOnline(t *testing.T) {
	pool := NewNodePool()
	pool.Add(&NodeInfo{ID: "w1", Status: "online", Role: NodeRoleWorker})
	pool.Add(&NodeInfo{ID: "w2", Status: "busy", Role: NodeRoleWorker})
	pool.Add(&NodeInfo{ID: "w3", Status: "offline", Role: NodeRoleWorker})

	online := pool.GetOnline()
	if len(online) != 2 {
		t.Errorf("expected 2 online nodes, got %d", len(online))
	}
}

func TestNodePool_ExpireStale(t *testing.T) {
	pool := NewNodePool()
	now := time.Now()
	node := &NodeInfo{ID: "w1", Status: "online", LastSeen: now.Add(-20 * time.Second)}
	// 直接写入 map 避免 Add 覆盖 LastSeen
	pool.Add(node)
	// 由于 Add 会更新 LastSeen 为 now，这里改为直接操作
	// 重新添加一个 LastSeen 为很久以前的节点
	pool.nodes["w1"].LastSeen = now.Add(-20 * time.Second)

	pool.ExpireStale()

	got, _ := pool.Get("w1")
	if got.Status != "offline" {
		t.Errorf("expected offline, got %s", got.Status)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Scheduler 测试
// ─────────────────────────────────────────────────────────────────────────────

func TestScheduler_RegisterAndUnregister(t *testing.T) {
	logger := &testLogger{}
	s := NewScheduler(logger)
	defer s.Stop()

	s.RegisterNode(&NodeInfo{ID: "w1", Address: "127.0.0.1:9001", Role: NodeRoleWorker, Status: "online"})
	s.RegisterNode(&NodeInfo{ID: "w2", Address: "127.0.0.1:9002", Role: NodeRoleWorker, Status: "online"})

	nodes := s.GetNodes()
	if len(nodes) != 2 {
		t.Errorf("expected 2 nodes, got %d", len(nodes))
	}

	s.UnregisterNode("w1")
	nodes = s.GetNodes()
	if len(nodes) != 1 {
		t.Errorf("expected 1 node after unregister, got %d", len(nodes))
	}
}

func TestScheduler_GetOnlineNodes(t *testing.T) {
	logger := &testLogger{}
	s := NewScheduler(logger)
	defer s.Stop()

	s.RegisterNode(&NodeInfo{ID: "w1", Address: "127.0.0.1:9001", Role: NodeRoleWorker, Status: "online"})
	s.RegisterNode(&NodeInfo{ID: "w2", Address: "127.0.0.1:9002", Role: NodeRoleWorker, Status: "offline"})

	online := s.GetOnlineNodes()
	if len(online) != 1 {
		t.Errorf("expected 1 online node, got %d", len(online))
	}
	if online[0].ID != "w1" {
		t.Errorf("expected w1, got %s", online[0].ID)
	}
}

func TestScheduler_DispatchJob(t *testing.T) {
	logger := &testLogger{}
	s := NewScheduler(logger)
	defer s.Stop()

	// 注册一个 Worker
	s.RegisterNode(&NodeInfo{
		ID:          "w1",
		Address:     "127.0.0.1:9001",
		Role:        NodeRoleWorker,
		Status:      "online",
		Concurrency: 5,
	})

	job := &ScanJob{
		JobID:     "test-job-1",
		Targets:   []string{"http://example.com", "http://example.org"},
		TemplateIDs: []string{"tmpl-1"},
		Config: JobConfig{
			Concurrency: 2,
			Timeout:     5,
		},
	}

	ch := s.DispatchJob(job)
	if ch == nil {
		t.Fatal("expected non-nil channel")
	}

	// 启动调度器
	cfg := defaultTestConfig()
	s.Start(cfg, nil, nil)

	// 等待结果
	select {
	case result := <-ch:
		if result.JobID != "test-job-1" {
			t.Errorf("expected job_id test-job-1, got %s", result.JobID)
		}
		if result.Error != "" {
			t.Logf("job error (expected for test): %s", result.Error)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for job result")
	}
}

func TestScheduler_DistributeTargets(t *testing.T) {
	targets := []string{"t1", "t2", "t3", "t4", "t5"}
	workers := []*NodeInfo{
		{ID: "w1"}, {ID: "w2"}, {ID: "w3"},
	}

	distributed := distributeTargets(targets, workers)
	if len(distributed) != 3 {
		t.Fatalf("expected 3 workers, got %d", len(distributed))
	}
	// Round-robin: w1 gets t1,t4; w2 gets t2,t5; w3 gets t3
	if len(distributed[0]) != 2 || distributed[0][0] != "t1" {
		t.Errorf("w1 expected [t1, t4], got %v", distributed[0])
	}
	if len(distributed[1]) != 2 || distributed[1][0] != "t2" {
		t.Errorf("w2 expected [t2, t5], got %v", distributed[1])
	}
	if len(distributed[2]) != 1 || distributed[2][0] != "t3" {
		t.Errorf("w3 expected [t3], got %v", distributed[2])
	}
}

func TestScheduler_EmptyTargets(t *testing.T) {
	logger := &testLogger{}
	s := NewScheduler(logger)
	defer s.Stop()

	// 注册一个 Worker
	s.RegisterNode(&NodeInfo{
		ID:       "w1",
		Address:  "127.0.0.1:9001",
		Role:     NodeRoleWorker,
		Status:   "online",
	})

	job := &ScanJob{
		JobID:       "empty-job",
		Targets:     []string{},
		TemplateIDs: []string{"tmpl-1"},
	}

	ch := s.DispatchJob(job)
	if ch == nil {
		t.Fatal("expected non-nil channel")
	}

	// 启动调度器
	cfg := defaultTestConfig()
	s.Start(cfg, nil, nil)

	// 等待结果（空目标时调度器回退到本地执行，应快速返回）
	select {
	case result := <-ch:
		if result.JobID != "empty-job" {
			t.Errorf("expected job_id empty-job, got %s", result.JobID)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for empty job result")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Worker 测试
// ─────────────────────────────────────────────────────────────────────────────

func TestWorker_NewWorker(t *testing.T) {
	cfg := defaultTestConfig()
	logger := &testLogger{}
	w := NewWorker("test-w1", "127.0.0.1:9001", cfg, logger)

	if w.ID != "test-w1" {
		t.Errorf("expected ID test-w1, got %s", w.ID)
	}
	if w.Address != "127.0.0.1:9001" {
		t.Errorf("expected address 127.0.0.1:9001, got %s", w.Address)
	}
	if w.nodeInfo.Role != NodeRoleWorker {
		t.Error("expected Role Worker")
	}
}

func TestWorker_StartStop(t *testing.T) {
	cfg := defaultTestConfig()
	w := NewWorker("test-w2", "127.0.0.1:9002", cfg, nil)

	if err := w.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	info := w.GetInfo()
	if info.Status != "online" {
		t.Errorf("expected online, got %s", info.Status)
	}

	// 重复启动应失败
	if err := w.Start(); err == nil {
		t.Error("expected error on double Start")
	}

	w.Stop()
}

func TestWorker_HandleJob_NilTemplate(t *testing.T) {
	cfg := defaultTestConfig()
	w := NewWorker("test-w3", "127.0.0.1:9003", cfg, nil)

	job := &ScanJob{
		JobID:       "job-no-tmpl",
		Targets:     []string{"http://example.com"},
		TemplateIDs: []string{}, // 无模板
		Config: JobConfig{
			Timeout: 2,
		},
	}

	result := w.HandleJob(job)
	if result.JobID != "job-no-tmpl" {
		t.Errorf("expected job_id job-no-tmpl, got %s", result.JobID)
	}
	// 无模板时应无结果但也不应 panic
	if len(result.Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(result.Results))
	}
}

func TestWorker_CloneConfig(t *testing.T) {
	cfg := defaultTestConfig()
	w := NewWorker("test-w4", "127.0.0.1:9004", cfg, nil)

	cloned := w.cloneConfig()
	if cloned.Concurrency != cfg.Concurrency {
		t.Error("concurrency not cloned")
	}
	if cloned.DefaultTimeout != cfg.DefaultTimeout {
		t.Error("timeout not cloned")
	}
	// 修改克隆不影响原配置
	cloned.Concurrency = 999
	if cfg.Concurrency == 999 {
		t.Error("clone should be independent")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper 测试
// ─────────────────────────────────────────────────────────────────────────────

func TestNormalizeTarget(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"http://example.com", "http://example.com"},
		{"https://example.com", "https://example.com"},
		{"http://example.com:8080", "http://example.com:8080"},
		{"not-a-url", "http://not-a-url"},
	}

	for _, tt := range tests {
		got := normalizeTarget(tt.input)
		if got != tt.want {
			t.Errorf("normalizeTarget(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestRoleName(t *testing.T) {
	if roleName(NodeRoleMaster) != "master" {
		t.Error("expected master")
	}
	if roleName(NodeRoleWorker) != "worker" {
		t.Error("expected worker")
	}
}

func TestParseInt(t *testing.T) {
	if parseInt("42", 0) != 42 {
		t.Error("expected 42")
	}
	if parseInt("abc", 7) != 7 {
		t.Error("expected default 7")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 辅助类型
// ─────────────────────────────────────────────────────────────────────────────

// testLogger 是一个简单的测试日志实现。
type testLogger struct{}

func (l *testLogger) Debug(msg string, args ...interface{}) {}
func (l *testLogger) Info(msg string, args ...interface{})  {}
func (l *testLogger) Warn(msg string, args ...interface{})  {}
func (l *testLogger) Error(msg string, args ...interface{}) {}

// defaultTestConfig 返回测试用的默认配置。
func defaultTestConfig() *config.GlobalConfig {
	return &config.GlobalConfig{
		UserAgent:      "gosleek-test/1.0",
		DefaultTimeout: 5,
		MaxRedirects:   3,
		FollowRedirect: true,
		Concurrency:    5,
		RateLimit:      50,
		MaxRetries:     1,
		RetryBackoff:   "1s",
		TemplateDir:    "templates",
	}
}
