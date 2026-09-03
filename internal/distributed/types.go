// Package distributed 提供分布式扫描支持。
//
// 核心设计:
//   - Master 节点通过 Scheduler 管理节点池，将扫描任务分发给 Worker 节点。
//   - Worker 节点本地使用 engine.Scanner 执行扫描，并通过心跳上报状态。
//   - 节点发现通过 UDP 广播实现，适用于同一 LAN 内的节点发现。
package distributed

import (
	"time"

	"github.com/gosleek/gosleek/pkg/types"
)

// NodeRole 区分主节点与工作节点。
type NodeRole int

const (
	NodeRoleMaster NodeRole = iota // Master 节点（任务分发方）
	NodeRoleWorker                 // Worker 节点（执行扫描方）
)

// NodeInfo 表示集群中的一个扫描节点。
type NodeInfo struct {
	ID            string    `json:"id"`
	Address       string    `json:"address"`
	Role          NodeRole  `json:"role"`
	Status        string    `json:"status"`         // "online", "offline", "busy"
	Concurrency   int       `json:"concurrency"`
	LastSeen      time.Time `json:"last_seen"`
	CompletedJobs int64     `json:"completed_jobs"`
	MatchedJobs   int64     `json:"matched_jobs"`
}

// ScanJob 是分发给 Worker 的扫描任务单元。
type ScanJob struct {
	JobID       string            `json:"job_id"`
	Targets     []string          `json:"targets"`
	TemplateIDs []string          `json:"template_ids"`
	Config      JobConfig         `json:"config"`
}

// JobConfig 携带扫描参数。
type JobConfig struct {
	Concurrency int    `json:"concurrency"`
	RateLimit   int    `json:"rate_limit"`
	Timeout     int    `json:"timeout"`
	Proxy       string `json:"proxy,omitempty"`
	Insecure    bool   `json:"insecure"`
}

// JobResult 是 Worker 对 ScanJob 的响应。
type JobResult struct {
	JobID   string            `json:"job_id"`
	Results []*types.Result   `json:"results"`
	Stats   JobStats          `json:"stats"`
	Error   string            `json:"error,omitempty"`
}

// JobStats 记录执行统计信息。
type JobStats struct {
	TotalJobs  int64 `json:"total_jobs"`
	Completed  int64 `json:"completed"`
	Matched    int64 `json:"matched"`
	DurationMs int64 `json:"duration_ms"`
}

// LoggerIface 是分布式包使用的日志接口。
// 各实现方可提供 Debug/Info/Warn/Error 四个级别。
type LoggerIface interface {
	Debug(msg string, args ...interface{})
	Info(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Error(msg string, args ...interface{})
}
