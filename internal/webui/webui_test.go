package webui

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gosleek/gosleek/pkg/types"
)

// ── 测试用的模拟 logger ──────────────────────────────────────────────────

type stubLogger struct {
	messages []string
}

func (l *stubLogger) DebugKV(msg string, args ...interface{})  { l.messages = append(l.messages, "DEBUG:"+msg) }
func (l *stubLogger) InfoKV(msg string, args ...interface{})   { l.messages = append(l.messages, "INFO:"+msg) }
func (l *stubLogger) WarnKV(msg string, args ...interface{})   { l.messages = append(l.messages, "WARN:"+msg) }
func (l *stubLogger) Error(msg string, args ...interface{})    { l.messages = append(l.messages, "ERROR:"+msg) }

// ── 测试：服务器创建 ─────────────────────────────────────────────────────

func TestNewServer(t *testing.T) {
	logger := &stubLogger{}
	srv := NewServer("127.0.0.1:9999", logger)
	if srv == nil {
		t.Fatal("NewServer 返回 nil")
	}
	if srv.addr != "127.0.0.1:9999" {
		t.Errorf("addr = %q, 期望 127.0.0.1:9999", srv.addr)
	}
	if srv.tasks == nil {
		t.Error("tasks map 应为 nil")
	}
	if srv.logger != logger {
		t.Error("logger 未正确设置")
	}
}

// ── 测试：任务创建与获取 ─────────────────────────────────────────────────

func TestAddTaskAndGetTasks(t *testing.T) {
	srv := NewServer("127.0.0.1:0", nil)

	task1 := srv.AddTask("任务A", []string{"http://example.com"}, []string{"tmpl-1"})
	if task1.ID == "" {
		t.Error("任务 ID 不应为空")
	}
	if task1.Status != "running" {
		t.Errorf("初始状态应为 running，实际: %s", task1.Status)
	}
	if task1.Name != "任务A" {
		t.Errorf("任务名错误: %s", task1.Name)
	}

	task2 := srv.AddTask("任务B", []string{"http://test.com", "http://foo.com"}, []string{"tmpl-2", "tmpl-3"})
	if task2.Name != "任务B" {
		t.Errorf("任务名错误: %s", task2.Name)
	}

	allTasks := srv.GetTasks()
	if len(allTasks) != 2 {
		t.Errorf("任务数 = %d, 期望 2", len(allTasks))
	}

	got := srv.GetTask(task1.ID)
	if got == nil {
		t.Fatal("GetTask 返回 nil")
	}
	if got.Name != "任务A" {
		t.Errorf("GetTask 名称错误: %s", got.Name)
	}

	if srv.GetTask("nonexistent") != nil {
		t.Error("获取不存在任务应返回 nil")
	}
}

// ── 测试：任务停止 ──────────────────────────────────────────────────────

func TestStopTask(t *testing.T) {
	srv := NewServer("127.0.0.1:0", nil)
	task := srv.AddTask("测试任务", []string{"http://example.com"}, []string{"tmpl-1"})

	ok := srv.StopTask(task.ID)
	if !ok {
		t.Error("停止任务应返回 true")
	}
	if task.Status != "stopped" {
		t.Errorf("状态应为 stopped，实际: %s", task.Status)
	}

	ok = srv.StopTask(task.ID)
	if ok {
		t.Error("再次停止应返回 false")
	}

	ok = srv.StopTask("no-such-id")
	if ok {
		t.Error("停止不存在任务应返回 false")
	}
}

// ── 测试：结果记录 ──────────────────────────────────────────────────────

func TestAddResult(t *testing.T) {
	srv := NewServer("127.0.0.1:0", nil)

	r1 := &types.Result{
		TemplateID: "tmpl-1",
		Name:       "测试漏洞1",
		Severity:   types.SeverityHigh,
		Target:     "http://example.com",
		Timestamp:  time.Now(),
	}
	srv.AddResult(r1)

	results := srv.GetResults()
	if len(results) != 1 {
		t.Fatalf("结果数 = %d, 期望 1", len(results))
	}
	if results[0].Name != "测试漏洞1" {
		t.Errorf("结果名称错误: %s", results[0].Name)
	}

	r2 := &types.Result{
		TemplateID: "tmpl-2",
		Name:       "测试漏洞2",
		Severity:   types.SeverityCritical,
		Target:     "http://example.com",
		Timestamp:  time.Now(),
	}
	srv.AddResult(r2)

	results = srv.GetResults()
	if len(results) != 2 {
		t.Errorf("结果数 = %d, 期望 2", len(results))
	}
}

// ── 测试：结果追加到运行中任务 ───────────────────────────────────────────

func TestAddResultToTask(t *testing.T) {
	srv := NewServer("127.0.0.1:0", nil)
	task := srv.AddTask("测试任务", []string{"http://example.com"}, []string{"tmpl-1"})

	r := &types.Result{
		TemplateID: "tmpl-1",
		Name:       "RCE 漏洞",
		Severity:   types.SeverityCritical,
		Target:     "http://example.com",
		MatchedAt:  "body",
		Timestamp:  time.Now(),
		Evidence:   "漏洞证据",
	}
	srv.AddResult(r)

	task.resultsMu.Lock()
	taskResults := task.Results
	task.resultsMu.Unlock()

	if len(taskResults) != 1 {
		t.Fatalf("任务结果数 = %d, 期望 1", len(taskResults))
	}
	if taskResults[0].Name != "RCE 漏洞" {
		t.Errorf("任务结果名称错误: %s", taskResults[0].Name)
	}
}

// ── 测试：HTTP 端点 ────────────────────────────────────────────────────

func TestHTTPHandlers(t *testing.T) {
	srv := NewServer("127.0.0.1:0", nil)

	task := srv.AddTask("测试任务", []string{"http://example.com", "http://test.com"}, []string{"tmpl-1", "tmpl-2"})
	srv.AddResult(&types.Result{
		TemplateID: "tmpl-1", Name: "SQL注入", Severity: types.SeverityCritical,
		Target: "http://example.com", MatchedAt: "body",
		Timestamp: time.Now(), Evidence: "sql error",
	})
	srv.AddResult(&types.Result{
		TemplateID: "tmpl-2", Name: "XSS", Severity: types.SeverityHigh,
		Target: "http://example.com", MatchedAt: "header",
		Timestamp: time.Now(), Evidence: "<script>",
	})
	srv.AddResult(&types.Result{
		TemplateID: "tmpl-1", Name: "信息泄露", Severity: types.SeverityInfo,
		Target: "http://test.com", MatchedAt: "body",
		Timestamp: time.Now(), Evidence: "version info",
	})
	// 不提前停止 task，由"停止任务POST"测试自己验证

	// 另外创建一个已停止的任务，用于测试"已完成任务详情"
	stoppedTask := srv.AddTask("已完成任务", []string{"http://stop.com"}, []string{"tmpl-x"})
	srv.StopTask(stoppedTask.ID)

	ts := httptest.NewServer(srv.srv.Handler)
	defer ts.Close()

	runTest := func(name, method, path, body string, expectedStatus int, check func(*http.Response) error) {
		t.Run(name, func(t *testing.T) {
			var reqBody io.Reader
			if body != "" {
				reqBody = strings.NewReader(body)
			}
			req, err := http.NewRequest(method, ts.URL+path, reqBody)
			if err != nil {
				t.Fatalf("创建请求失败: %v", err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("请求失败: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != expectedStatus {
				t.Errorf("状态码 = %d, 期望 %d", resp.StatusCode, expectedStatus)
			}
			if check != nil {
				if err := check(resp); err != nil {
					t.Errorf("检查失败: %v", err)
				}
			}
		})
	}

	// 主页
	runTest("主页返回200且含标题", "GET", "/", "", http.StatusOK, func(resp *http.Response) error {
		data, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(data), "go-sleek") {
			return fmt.Errorf("主页未包含 go-sleek 标题，响应内容前200字节: %s", string(data[:min(200, len(data))]))
		}
		return nil
	})

	// 任务列表
	runTest("任务列表返回JSON", "GET", "/api/tasks", "", http.StatusOK, func(resp *http.Response) error {
		var body map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return err
		}
		tasks, ok := body["tasks"].([]interface{})
		if !ok {
			return fmt.Errorf("tasks 字段类型错误")
		}
		if len(tasks) != 2 {
			return fmt.Errorf("任务数 = %d, 期望 2", len(tasks))
		}
		return nil
	})

	// 任务详情（已完成任务）
	runTest("任务详情（已停止）", "GET", "/api/tasks/"+stoppedTask.ID, "", http.StatusOK, func(resp *http.Response) error {
		var td map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&td); err != nil {
			return err
		}
		if td["name"] != "已完成任务" {
			return fmt.Errorf("任务名称错误: %v", td["name"])
		}
		if td["status"] != "stopped" {
			return fmt.Errorf("任务状态错误: %v", td["status"])
		}
		return nil
	})

	// 不存在任务
	runTest("不存在任务返回404", "GET", "/api/tasks/nonexistent", "", http.StatusNotFound, nil)

	// 结果列表
	runTest("结果列表", "GET", "/api/results", "", http.StatusOK, func(resp *http.Response) error {
		var body map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return err
		}
		results, ok := body["results"].([]interface{})
		if !ok {
			return fmt.Errorf("results 字段类型错误")
		}
		if len(results) != 3 {
			return fmt.Errorf("结果数 = %d, 期望 3", len(results))
		}
		return nil
	})

	// 按严重度过滤
	runTest("按严重度过滤critical", "GET", "/api/results?severity=critical", "", http.StatusOK, func(resp *http.Response) error {
		var body map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return err
		}
		results := body["results"].([]interface{})
		if len(results) != 1 {
			return fmt.Errorf("过滤后结果数 = %d, 期望 1", len(results))
		}
		return nil
	})

	// 严重度统计
	runTest("严重度统计", "GET", "/api/results/severity", "", http.StatusOK, func(resp *http.Response) error {
		var counts map[string]int
		if err := json.NewDecoder(resp.Body).Decode(&counts); err != nil {
			return err
		}
		if counts[types.SeverityCritical] != 1 {
			return fmt.Errorf("严重数 = %d, 期望 1", counts[types.SeverityCritical])
		}
		if counts[types.SeverityHigh] != 1 {
			return fmt.Errorf("高危数 = %d, 期望 1", counts[types.SeverityHigh])
		}
		if counts[types.SeverityInfo] != 1 {
			return fmt.Errorf("信息数 = %d, 期望 1", counts[types.SeverityInfo])
		}
		return nil
	})

	// 目标统计
	runTest("目标统计", "GET", "/api/results/targets", "", http.StatusOK, func(resp *http.Response) error {
		var targets []map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&targets); err != nil {
			return err
		}
		if len(targets) != 2 {
			return fmt.Errorf("目标数 = %d, 期望 2", len(targets))
		}
		return nil
	})

	// 创建任务 POST
	runTest("创建任务POST", "POST", "/api/tasks",
		`{"name":"新任务","targets":["http://new.com"],"templates":["tmpl-x"]}`,
		http.StatusCreated, func(resp *http.Response) error {
		var task map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&task); err != nil {
			return err
		}
		if task["name"] != "新任务" {
			return fmt.Errorf("任务名错误: %v", task["name"])
		}
		if task["status"] != "running" {
			return fmt.Errorf("状态错误: %v", task["status"])
		}
		return nil
	})

	// 停止任务 POST
	runTest("停止任务POST", "POST", "/api/tasks/"+task.ID+"/stop", "", http.StatusOK, nil)

	// 空任务名
	runTest("空任务名返回400", "POST", "/api/tasks", `{"name":""}`, http.StatusBadRequest, nil)

	// GET 到 stop 路径
	runTest("GET到stop路径返回404", "GET", "/api/tasks/some-id/stop", "", http.StatusNotFound, nil)

	// 去重统计（初始为 0）
	runTest("去重统计返回JSON", "GET", "/api/results/dedup", "", http.StatusOK, func(resp *http.Response) error {
		var body map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return err
		}
		if body["result_dedup"] != float64(0) {
			return fmt.Errorf("去重数 = %v, 期望 0", body["result_dedup"])
		}
		return nil
	})

	// 更新去重统计
	srv.UpdateDedupStats(5, 0)
	runTest("去重统计更新后返回5", "GET", "/api/results/dedup", "", http.StatusOK, func(resp *http.Response) error {
		var body map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return err
		}
		if body["result_dedup"] != float64(5) {
			return fmt.Errorf("去重数 = %v, 期望 5", body["result_dedup"])
		}
		return nil
	})

	// 重置去重统计
	runTest("去重统计重置", "DELETE", "/api/results/dedup/reset", "", http.StatusOK, func(resp *http.Response) error {
		var body map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return err
		}
		if body["status"] != "cleared" {
			return fmt.Errorf("状态错误: %v", body["status"])
		}
		return nil
	})
	runTest("重置后去重为0", "GET", "/api/results/dedup", "", http.StatusOK, func(resp *http.Response) error {
		var body map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return err
		}
		if body["result_dedup"] != float64(0) {
			return fmt.Errorf("去重数 = %v, 期望 0", body["result_dedup"])
		}
		return nil
	})

	// scan 命令推送结果（POST /api/results）
	runTest("POST结果推送到WebUI", "POST", "/api/results",
		`{"template-id":"CVE-2022-22963-go","name":"Spring4Shell","severity":"critical","target":"http://192.168.80.128:8080/","matched-at":"body","timestamp":"2026-09-01T10:00:00Z","evidence":"stack trace visible"}`,
		http.StatusCreated, func(resp *http.Response) error {
		var body map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return err
		}
		if body["status"] != "ok" {
			return fmt.Errorf("status = %v, 期望 ok", body["status"])
		}
		return nil
	})

	// 验证推送结果出现在列表中（之前有3条，POST 后共4条）
	runTest("POST后结果列表含4条", "GET", "/api/results", "", http.StatusOK, func(resp *http.Response) error {
		var body map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return err
		}
		results, ok := body["results"].([]interface{})
		if !ok {
			return fmt.Errorf("results 字段类型错误")
		}
		if len(results) != 4 {
			return fmt.Errorf("结果数 = %d, 期望 4", len(results))
		}
		// 检查最后一条是 POST 推送的
		last := results[3].(map[string]interface{})
		if last["name"] != "Spring4Shell" {
			return fmt.Errorf("名称错误: %v", last["name"])
		}
		if last["severity"] != "critical" {
			return fmt.Errorf("严重度错误: %v", last["severity"])
		}
		return nil
	})
}

// ── 测试：Start/Stop 生命周期 ───────────────────────────────────────────

func TestServerLifecycle(t *testing.T) {
	srv := NewServer("127.0.0.1:0", nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("无法创建监听端口: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	srv.addr = fmt.Sprintf("127.0.0.1:%d", port)

	go func() { _ = srv.srv.Serve(ln) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	}()

	ts := httptest.NewServer(srv.srv.Handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/tasks")
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("状态码 = %d, 期望 200", resp.StatusCode)
	}
}
