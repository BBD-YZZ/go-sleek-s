# Go-Sleek 分布式扫描指南

> 版本：v1.6.0
> 目标读者：安全工程师、DevOps 工程师
> 前置知识：了解 gosleek 基本扫描流程

---

## 目录

1. [架构概述](#1-架构概述)
2. [快速开始](#2-快速开始)
3. [Worker 节点](#3-worker-节点)
4. [Master 节点](#4-master-节点)
5. [scan 命令集成](#5-scan-命令集成)
6. [编程集成](#6-编程集成)
7. [容错与回退](#7-容错与回退)
8. [性能调优](#8-性能调优)
9. [常见问题](#9-常见问题)

---

## 1. 架构概述

gosleek 分布式扫描采用 **Master-Worker 架构**，通过 CLI 子命令实现：

```
┌──────────────────────────────────────────────────────────────┐
│                      Master 节点                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Scheduler                                            │   │
│  │  ├── 节点池管理 (NodePool)                            │   │
│  │  ├── Round-Robin 目标分发                              │   │
│  │  ├── 心跳监控 (15s 超时淘汰)                           │   │
│  │  ├── HTTP 结果收集                                     │   │
│  │  └── 本地回退 (无 Worker 时自动执行)                   │   │
│  └──────────────────────────────────────────────────────┘   │
│                         │                                    │
│              UDP 广播发现 (端口 19234)                       │
│                         │                                    │
└─────────────────┬───────┼────────────────┬───────────────────┘
                  │       │                │
    ┌─────────────▼──┐ ┌──▼───────┐ ┌─────▼──────┐
    │  Worker-1      │ │ Worker-2 │ │ Worker-3   │
    │  :19234        │ │ :19235   │ │ :19236     │
    │ ┌──────────┐   │ │ ┌──────┐ │ │ ┌──────┐  │
    │ │/job      │   │ │ │/job  │ │ │ │/job  │  │
    │ │/info     │   │ │ │/info │ │ │ │/info │  │
    │ │/health   │   │ │ │/health│ │ │/health│  │
    │ │engine    │   │ │ │engine│ │ │ │engine│  │
    │ └──────────┘   │ │ └──────┘ │ │ └──────┘  │
    └────────────────┘ └──────────┘ └────────────┘
```

**通信机制**：
- **UDP 广播**（端口 19234）：节点自动发现，Worker 每 2 秒发送心跳
- **HTTP/REST**（端口 19234）：Master 通过 POST /job 分发任务，Worker 返回 JobResult
- **轮询拉取**：scan 命令通过 `/api/jobs/poll` 从 Master 拉取任务

**设计原则**：
- Master 和 Worker 使用相同的二进制文件
- Worker 启动时自动广播心跳，Master 启动后自动发现
- 无可用 Worker 时 Master 自动回退到本地执行
- scan 命令支持 `--distributed --master` 通过集群扫描

---

## 2. 快速开始

### 2.1 编译

```bash
go build -o gosleek ./cmd/gosleek/
```

### 2.2 启动 Worker 节点

在多台机器上运行（同一 LAN）：

```bash
# Worker-1: 在 192.168.1.101 上
./gosleek worker --id worker-1 --addr :19234

# Worker-2: 在 192.168.1.102 上
./gosleek worker --id worker-2 --addr :19235
```

### 2.3 启动 Master 节点

```bash
# Master: 在 192.168.1.100 上
./gosleek master --addr :19234
```

Master 启动后会自动监听 UDP 广播，Worker 上线后会自动被发现并注册到节点池。

### 2.4 使用分布式扫描

启动 scan 命令时指定 `--distributed` 和 `--master`：

```bash
./gosleek scan -t http://target1 -t http://target2 \
  --distributed --master 192.168.1.100:19234
```

scan 命令会连接 Master，Master 将任务分发到所有在线 Worker，结果汇总后返回。

---

## 3. Worker 节点

### 3.1 CLI 参数

```bash
gosleek worker [选项]
```

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--id` | Worker 节点 ID（**必填**） | — |
| `--addr` | HTTP 监听地址 | `:19234` |
| `-T, --templates` | 模板目录 | `templates` |
| `--config` | 配置文件路径 | — |
| `-v, --verbose` | 详细输出 | false |
| `-vv` | 极详细输出 | false |

### 3.2 Worker 启动流程

```bash
# 1. 加载 config.yaml（或默认配置）
# 2. 启动心跳广播（UDP 端口 19234）
# 3. 启动 HTTP 服务（监听 --addr）
# 4. 暴露 /job, /info, /health 端点
```

### 3.3 HTTP 端点

Worker 启动后暴露以下 HTTP 端点：

| 端点 | 方法 | 说明 |
|------|------|------|
| `POST /job` | POST | 接收 ScanJob，执行扫描，返回 JobResult |
| `GET /info` | GET | 返回当前节点信息（NodeInfo JSON） |
| `GET /health` | GET | 健康检查（返回 `{"status":"ok"}`） |

**POST /job 请求格式**：
```json
{
  "job_id": "scan-1234567890",
  "targets": ["http://example.com", "http://target2.com"],
  "template_ids": ["CVE-2021-44228-log4j-rce"],
  "config": {
    "concurrency": 25,
    "rate_limit": 150,
    "timeout": 10,
    "proxy": "",
    "insecure": true
  }
}
```

**响应格式**：
```json
{
  "job_id": "scan-1234567890",
  "results": [...],
  "stats": {
    "total_jobs": 2,
    "completed": 2,
    "matched": 1,
    "duration_ms": 3421
  }
}
```

### 3.4 Worker 内部流程

```
HandleJob(job *ScanJob) *JobResult
  │
  ├── 加载模板 (loadTemplates)
  │     └── 从模板目录加载指定 ID 的 YAML 模板
  │
  ├── 加载插件 (loadPlugins)
  │     └── 加载所有已注册的 Go 插件
  │
  ├── 执行扫描 (engine.Scanner.Run)
  │     └── 复用 engine 包的核心扫描逻辑
  │
  └── 返回 JobResult
        ├── Results: []*types.Result  命中结果
        ├── Stats: JobStats           执行统计
        └── Error: string             错误信息（如有）
```

---

## 4. Master 节点

### 4.1 CLI 参数

```bash
gosleek master [选项]
```

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--addr` | 监听地址（心跳 UDP + HTTP API） | `:19234` |
| `-T, --templates` | 模板目录 | `templates` |
| `--config` | 配置文件路径 | — |
| `-v, --verbose` | 详细输出 | false |
| `-vv` | 极详细输出 | false |

### 4.2 Master 启动流程

```bash
# 1. 加载模板和配置
# 2. 启动 Scheduler（后台 goroutine 处理任务分发）
# 3. 启动 UDP 监听（端口 19234）接收 Worker 心跳
# 4. 每 5 秒轮询 UDP 广播发现新节点
# 5. 暴露 HTTP API 供 scan 命令连接
```

### 4.3 HTTP API

| 端点 | 方法 | 说明 |
|------|------|------|
| `POST /api/nodes` | POST | 注册 Worker 节点 |
| `GET /api/nodes` | GET | 列出所有节点 |
| `GET /api/jobs/poll` | GET | Worker 轮询拉取任务 |
| `POST /api/tasks` | POST | 创建扫描任务 |
| `GET /api/tasks` | GET | 列出任务 |
| `GET /api/tasks/{id}` | GET | 任务详情 |
| `POST /api/tasks/{id}/complete` | POST | 任务完成 |

### 4.4 Scheduler 调度流程

```
ScanJob 入队
    │
    ├── 无目标 → 直接返回空结果
    │
    ├── 有 Worker → Round-Robin 分配目标 → HTTP 调用 Worker
    │     └── 每个 Worker 在独立 goroutine 执行
    │
    └── 无可用 Worker → 本地回退执行（executeLocally）
```

---

## 5. scan 命令集成

### 5.1 分布式扫描参数

在 `scan` 命令中添加以下参数：

```bash
./gosleek scan -t http://target \
  --distributed \
  --master 192.168.1.100:19234 \
  --node-id worker-1
```

| 参数 | 说明 |
|------|------|
| `--distributed` | 启用分布式扫描模式 |
| `--master <addr>` | Master 节点地址（如 `192.168.1.100:19234`） |
| `--node-id <id>` | 当前节点 ID（用于 Master 识别） |

### 5.2 工作流程

```
1. scan --distributed 启动时创建本地 Worker
2. 连接 Master，注册到 Master 节点池
3. 通过轮询从 Master 获取待执行任务
4. 本地执行扫描（复用 engine.Scanner）
5. 结果通过 HTTP 回传给 Master
6. Master 汇总所有结果后返回给用户
```

### 5.3 回退行为

如果 Master 连接失败或无可用 Worker：
1. 打印警告信息
2. 自动回退到本地执行（与不带 `--distributed` 相同）
3. 不影响原有扫描功能

---

## 6. 编程集成

### 6.1 创建 Worker

```go
package main

import (
    "log"
    "time"

    "github.com/gosleek/gosleek/internal/config"
    "github.com/gosleek/gosleek/internal/distributed"
)

func main() {
    cfg := config.DefaultConfig()
    cfg.Concurrency = 25
    cfg.RateLimit = 150

    worker := distributed.NewWorker(
        "worker-1",           // 节点 ID
        "192.168.1.101:19234", // 监听地址
        cfg,
        nil,                  // logger（可选）
    )

    if err := worker.Start(); err != nil {
        log.Fatal(err)
    }
    defer worker.Stop()

    log.Println("Worker 已启动，等待 Master 分发任务...")

    // 等待手动停止
    select {}
}
```

### 6.2 创建 Master（Scheduler）

```go
package main

import (
    "log"
    "time"

    "github.com/gosleek/gosleek/internal/config"
    "github.com/gosleek/gosleek/internal/distributed"
    "github.com/gosleek/gosleek/internal/template"
)

func main() {
    cfg := config.DefaultConfig()
    templates, _ := template.LoadDir("templates")

    scheduler := distributed.NewScheduler(nil)

    // 启动调度循环
    scheduler.Start(cfg, templates, nil)

    // 注册 Worker（或通过 UDP 自动发现）
    scheduler.RegisterNode(&distributed.NodeInfo{
        ID:          "worker-1",
        Address:     "192.168.1.101:19234",
        Role:        distributed.NodeRoleWorker,
        Status:      "online",
        Concurrency: 25,
    })

    // 分发任务
    job := &distributed.ScanJob{
        JobID:       "job-001",
        Targets:     []string{"http://example.com", "http://target2.com"},
        TemplateIDs: []string{"CVE-2021-44228-log4j-rce"},
        Config: distributed.JobConfig{
            Concurrency: 25,
            RateLimit:   150,
            Timeout:     10,
        },
    }

    resultCh := scheduler.DispatchJob(job)
    for result := range resultCh {
        log.Printf("Job %s 完成: %d 命中, %dms",
            result.JobID, result.Stats.Matched, result.Stats.DurationMs)
        for _, r := range result.Results {
            log.Printf("  [%s] %s → %s", r.Severity, r.Name, r.Target)
        }
    }

    scheduler.Stop()
}
```

### 6.3 节点发现

```go
// 通过 UDP 广播发现同一 LAN 内的节点
nodes, err := distributed.DiscoverNodes(5 * time.Second)
for _, node := range nodes {
    fmt.Printf("发现节点: %s (role=%s, status=%s)\n",
        node.Address, node.Role, node.Status)
}

// 手动添加节点
node := &distributed.NodeInfo{
    ID:        "worker-1",
    Address:   "192.168.1.101:19234",
    Role:      distributed.NodeRoleWorker,
    Status:    "online",
    Concurrency: 25,
}
pool.Add(node)
```

---

## 7. 容错与回退

### 7.1 Worker 掉线

- Worker 心跳超时（15s）后自动从节点池移除
- 正在执行的任务结果正常回传
- 新任务不再分发到已离线节点

### 7.2 任务失败

```go
type JobResult struct {
    JobID   string            `json:"job_id"`
    Results []*types.Result   `json:"results"`
    Stats   JobStats          `json:"stats"`
    Error   string            `json:"error,omitempty"`
}
```

### 7.3 本地回退

当无可用 Worker 时：
1. Scheduler 检测在线节点数为 0
2. 自动调用 `executeLocally()` 使用本地 engine.Scanner
3. 结果通过相同通道返回，调用方无需感知差异

### 7.4 Master 不可达

scan 命令的 `--distributed` 模式：
1. 尝试连接 Master，失败时打印警告
2. 自动回退到本地执行
3. 不影响原有扫描流程

---

## 8. 性能调优

### 8.1 Worker 并发配置

```yaml
# config.yaml
concurrency: 50   # 默认 25，可根据机器性能调整
rate-limit: 300   # 默认 150
default-timeout: 15
```

### 8.2 节点发现超时

```go
// 调整发现超时（默认 5s）
nodes, err := distributed.DiscoverNodes(10 * time.Second)
```

### 8.3 负载均衡

Round-Robin 策略确保各 Worker 工作量均匀：
- 目标列表按 Worker 索引轮询分配
- 每个 Worker 获得均匀的目标数量
- 无需额外通信开销

---

## 9. 常见问题

### 9.1 Worker 无法被发现

**排查步骤**：
1. 确认所有节点在同一 LAN 段
2. 确认防火墙允许 UDP 端口 19234
3. 确认 Worker 的 `--addr` 参数正确（必须是 Master 可访问的地址）
4. 手动添加节点：`scheduler.RegisterNode(node)`

### 9.2 Master 无法连接到 Worker

**排查步骤**：
1. 确认 Worker 的 HTTP 服务已启动（`GET /health` 返回 200）
2. 确认网络连通性（`curl http://worker-addr:19234/health`）
3. 检查 Worker 日志中的 HTTP 服务启动信息

### 9.3 scan --distributed 回退到本地

**可能原因**：
1. Master 地址不可达（网络不通或 Master 未启动）
2. 无在线 Worker（节点池为空或所有节点离线）
3. 解决方法：检查 Master 运行状态和 Worker 连接情况

### 9.4 端口冲突

```
Error: bind: address already in use
```

**解决**：使用不同端口
```bash
./gosleek worker --id worker-2 --addr :19235
./gosleek master --addr :19236
```

### 9.5 模板目录不一致

Worker 和 Master 应使用相同的模板目录。可通过 `--templates` 参数指定：

```bash
./gosleek worker --id w1 -T /shared/templates
./gosleek master -T /shared/templates
```

---

*本文档基于 gosleek v1.6.0 编写*
