# Go-Sleek Web UI 使用指南

> 版本：v1.0.1
> 目标读者：安全工程师、渗透测试人员
> 前置知识：了解 gosleek 基本扫描流程

---

## 目录

1. [概述](#1-概述)
2. [快速开始](#2-快速开始)
3. [界面功能](#3-界面功能)
4. [编程集成](#4-编程集成)
5. [REST API](#5-rest-api)
6. [安全注意事项](#6-安全注意事项)
7. [常见问题](#7-常见问题)

---

## 1. 概述

gosleek Web UI 是一个内置的 HTTP 服务器，提供可视化的扫描任务管理和结果展示。核心特点：

- **零额外依赖**：使用 Go 标准库 `net/http` + `html/template`，无需任何 Web 框架
- **模板嵌入**：通过 `embed.FS` 将 HTML 模板编译进二进制文件
- **实时刷新**：5 秒自动轮询，鼠标悬停暂停刷新
- **纯 CSS 图表**：使用 `conic-gradient` 实现饼图，无需 JavaScript 库

---

## 2. 快速开始

### 2.1 启动 Web UI

```bash
# 默认监听 127.0.0.1:8080
go run ./cmd/gosleek/ webui

# 指定监听地址
go run ./cmd/gosleek/ webui --addr :9090

# 监听所有接口（局域网内可访问）
go run ./cmd/gosleek/ webui --addr 0.0.0.0:8080
```

### 2.2 访问界面

浏览器打开 `http://127.0.0.1:8080` 即可看到仪表盘。

### 2.3 深色主题

界面采用深色主题设计，长时间使用不易疲劳。所有图表和交互均不依赖 JavaScript 外部库。

---

## 3. 界面功能

### 3.1 统计卡片

仪表盘顶部显示关键统计信息：

| 卡片 | 说明 |
|------|------|
| 目标总数 | 已扫描的唯一目标数 |
| 模板数 | 加载的模板和插件总数 |
| 结果数 | 命中的漏洞总数 |
| Critical | 严重级漏洞数 |
| High | 高级漏洞数 |
| Medium | 中级漏洞数 |

### 3.2 任务列表

- **创建任务**：输入任务名称、目标列表（每行一个）、模板 ID（逗号分隔）
- **查看状态**：running / completed / stopped
- **停止任务**：点击停止按钮中断运行中的任务
- **结果预览**：展开任务查看命中结果

### 3.3 结果表格

- 支持按严重度过滤（API 支持 `?severity=critical` 查询参数）
- 支持按目标过滤（API 支持 `?target=example.com` 查询参数）
- 显示字段：目标 URL、模板 ID、名称、严重度、证据、时间

### 3.4 图表

- **严重度饼图**：CSS `conic-gradient` 实现，无需 Chart.js
- **目标漏洞柱图**：每个目标的命中数量分布

---

## 4. 编程集成

### 4.1 基本用法

```go
package main

import (
    "context"
    "log"
    "time"

    "github.com/gosleek/gosleek/internal/webui"
    "github.com/gosleek/gosleek/pkg/types"
)

// 简单的日志实现（适配 LoggerIface）
type simpleLogger struct{}

func (l *simpleLogger) Debug(msg string, args ...interface{})  {}
func (l *simpleLogger) Info(msg string, args ...interface{})   { log.Printf("[INFO] "+msg, args...) }
func (l *simpleLogger) Warn(msg string, args ...interface{})   { log.Printf("[WARN] "+msg, args...) }
func (l *simpleLogger) Error(msg string, args ...interface{})  { log.Printf("[ERROR] "+msg, args...) }

func main() {
    // 创建 Web UI 服务器
    logger := &simpleLogger{}
    srv := webui.NewServer(":8080", logger)

    // 启动服务器（后台 goroutine）
    if err := srv.Start(); err != nil {
        log.Fatal(err)
    }
    defer srv.Stop(context.Background())

    log.Printf("Web UI 已启动: %s", srv.Addr())

    // 创建扫描任务
    task := srv.AddTask("示例扫描",
        []string{"http://example.com"},
        []string{"CVE-2021-44228-log4j-rce", "sqli-time-based-blind"},
    )

    log.Printf("任务已创建: ID=%s", task.ID)

    // 模拟结果写入（实际使用中来自 engine.Scanner 回调）
    time.Sleep(2 * time.Second)
    srv.AddResult(&types.Result{
        TemplateID: "CVE-2021-44228-log4j-rce",
        Name:       "Log4Shell RCE",
        Severity:   types.SeverityCritical,
        Target:     "http://example.com",
        Evidence:   "响应包含 JNDI 注入标记",
        Timestamp:  time.Now(),
    })

    // 保持运行
    select {}
}
```

### 4.2 与 engine.Scanner 集成

```go
import (
    "github.com/gosleek/gosleek/internal/engine"
    "github.com/gosleek/gosleek/internal/config"
    "github.com/gosleek/gosleek/internal/webui"
)

// 创建 Web UI 服务器
srv := webui.NewServer(":8080", logger)
go srv.Start()

// 创建任务
task := srv.AddTask("扫描任务", targets, templateIDs)

// 创建扫描引擎
cfg := config.DefaultConfig()
scanner := engine.NewScanner(cfg, 1, oobCfg, "", true)

// 回调中写入结果
scanner.SetCallbacks(
    func(r *types.Result) {
        srv.AddResult(r)
    },
    nil, nil, nil, nil, nil,
)

// 运行扫描
results := scanner.Run(ctx, templates, plugins, targets)
```

### 4.3 Task 结构

```go
type Task struct {
    ID            string          `json:"id"`          // 自动生成: "task-1", "task-2", ...
    Name          string          `json:"name"`        // 用户定义
    Targets       []string        `json:"targets"`     // 目标列表
    Templates     []string        `json:"templates"`   // 模板 ID 列表
    Status        string          `json:"status"`      // "running" / "completed" / "stopped"
    StartedAt     time.Time       `json:"started_at"`
    CompletedAt   time.Time       `json:"completed_at"`
    Results       []*types.Result `json:"results,omitempty"`
}
```

---

## 5. REST API

所有 API 返回 JSON 格式。

### 5.1 任务管理

| 方法 | 路径 | 请求体 | 说明 |
|------|------|--------|------|
| GET | `/api/tasks` | - | 列出所有任务 |
| POST | `/api/tasks` | `{"name":"","targets":[],"templates":[]}` | 创建任务 |
| GET | `/api/tasks/{id}` | - | 任务详情（含结果） |
| POST | `/api/tasks/{id}/stop` | - | 停止任务 |

**创建任务示例**：
```bash
curl -X POST http://127.0.0.1:8080/api/tasks \
  -H "Content-Type: application/json" \
  -d '{"name":"my-scan","targets":["http://example.com"],"templates":["CVE-2021-44228"]}'
```

### 5.2 结果查询

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/results` | 所有结果（可加 `?severity=critical` 过滤） |
| POST | `/api/results` | 接收扫描结果推送（scan 命令自动调用） |
| GET | `/api/results/severity` | 按严重度统计 `{"critical":2,"high":5,...}` |
| GET | `/api/results/targets` | 按目标统计 `{"http://example.com":3,...}` |
| GET | `/api/results/dedup` | 去重统计 `{"result_dedup":N}` |
| DELETE | `/api/results/dedup/reset` | 重置去重计数 |

**POST /api/results 请求体**：
```json
{
  "template-id": "CVE-2021-44228",
  "name": "Log4Shell RCE",
  "severity": "critical",
  "target": "http://example.com",
  "matched-at": "body",
  "timestamp": "2026-09-01T10:00:00Z",
  "evidence": "JNDI注入检测成功"
}
```

### 5.3 API 响应格式

**GET /api/tasks 响应**：
```json
[
  {
    "id": "task-1",
    "name": "示例扫描",
    "targets": ["http://example.com"],
    "templates": ["CVE-2021-44228"],
    "status": "completed",
    "started_at": "2026-08-31T10:00:00Z",
    "completed_at": "2026-08-31T10:05:00Z",
    "results": [
      {
        "template-id": "CVE-2021-44228",
        "name": "Log4Shell RCE",
        "severity": "critical",
        "target": "http://example.com",
        "evidence": "JNDI注入检测成功",
        "timestamp": "2026-08-31T10:03:00Z"
      }
    ]
  }
]
```

**GET /api/results/severity 响应**：
```json
{
  "critical": 2,
  "high": 5,
  "medium": 3,
  "low": 1,
  "info": 0
}
```

### 5.4 与扫描命令联动

`gosleek scan` 通过 `--webui-url` 参数将扫描结果实时推送到 Web UI：

```bash
# 终端 1：启动 Web UI
go run ./cmd/gosleek/ webui --addr :9090

# 终端 2：扫描并推送结果到 Web UI
gosleek scan -t http://example.com --webui-url http://localhost:9090
```

联动效果：
- 扫描过程中每条命中的漏洞实时推送到 Web UI 仪表盘
- 扫描结束后自动推送去重统计（跳过重复结果的计数）
- Web UI 页面每 5 秒自动刷新，鼠标悬停暂停刷新

**注意**：Web UI 默认只绑定 `127.0.0.1`，如需从其他机器访问，使用 `--addr 0.0.0.0:9090`。

---

## 6. 安全注意事项

### 6.1 默认只绑定本地

Web UI 默认绑定 `127.0.0.1`，仅本机可访问。如需局域网访问，显式指定 `0.0.0.0`。

### 6.2 无认证机制

当前版本**没有内置认证**。如果在非受信任网络中使用，建议：
- 通过防火墙限制访问
- 使用反向代理添加 Basic Auth
- 仅在内网环境使用

### 6.3 敏感信息保护

结果中的 `RawRequest` 和 `RawResponse` 可能包含敏感信息（如 Cookie、Token）。建议配合 `--redact` 参数使用。

---

## 7. 常见问题

### 7.1 端口被占用

```
Error: listen tcp :8080: bind: Only one usage of each socket address...
```

**解决**：使用其他端口
```bash
go run ./cmd/gosleek/ webui --addr :9090
```

### 7.2 无法在浏览器中查看图表

Web UI 使用纯 CSS `conic-gradient` 绘制图表，无需 JavaScript。如果图表不显示，请检查：
- 浏览器是否较旧（建议 Chrome 90+ / Firefox 90+ / Safari 14+）
- 是否启用了严格的内容安全策略（CSP）

### 7.3 任务创建后状态不更新

确保在扫描回调中调用 `srv.AddResult(r)` 将结果写入任务。仅创建任务不会自动触发扫描。

### 7.4 如何关闭 Web UI

- 使用 `Stop()` 方法：`srv.Stop(context.Background())`
- 或发送 SIGINT/SIGTERM 信号

---

*本文档基于 gosleek v1.0.1 编写*
