# Go 插件开发手册

> 版本：v1.3.1
> 目标读者：Go 开发人员、漏洞研究员
> 前置知识：Go 语言基础、HTTP 协议基础

---

## 目录

1. [插件概述](#1-插件概述)
2. [插件架构](#2-插件架构)
3. [插件接口](#3-插件接口)
4. [开发环境准备](#4-开发环境准备)
5. [第一个插件：Hello World](#5-第一个插件hello-world)
6. [Plugin 接口详解](#6-plugin-接口详解)
7. [Context 上下文详解](#7-context-上下文详解)
8. [OOBHandle 接口详解](#8-oobhandle-接口详解)
9. [PluginLogger 详解](#9-pluginlogger-详解)
10. [PluginReporter 详解](#10-pluginreporter-详解)
11. [Result 结构详解](#11-result-结构详解)
12. [插件注册机制](#12-插件注册机制)
13. [完整插件示例](#13-完整插件示例)
14. [插件与 YAML 模板对比](#14-插件与-yaml-模板对比)
15. [开发步骤指南](#15-开发步骤指南)
16. [调试与测试](#16-调试与测试)
17. [常见问题](#17-常见问题)
18. [最佳实践](#18-最佳实践)

---

## 1. 插件概述

### 1.1 什么是 Go 插件

Go 插件是 gosleek 的另一种漏洞检测单元，与 YAML 模板并列。插件用 Go 语言编写，编译后嵌入二进制文件，提供更高的灵活性和性能。

### 1.2 插件 vs YAML 模板

| 特性 | YAML 模板 | Go 插件 |
|------|-----------|---------|
| 编写语言 | YAML | Go |
| 开发难度 | 低（无需编程） | 中（需要 Go 知识） |
| 灵活性 | 受限 | 完全灵活 |
| 执行性能 | 解释执行 | 编译执行 |
| OOB 支持 | 自动注入占位符 | 通过 OOBHandle 接口 |
| 并发控制 | 有限 | 完全控制 |
| 密码学运算 | 不支持 | 支持（crypto 包） |
| 调试方式 | `-vv` 日志 | `pctx.Log` + IDE 调试 |
| 适用场景 | 简单检测、快速原型 | 复杂逻辑、多步利用 |

### 1.3 何时使用插件

- 需要复杂的条件判断和循环
- 需要并发请求和结果聚合
- 需要密码学运算（HMAC、SHA 等）
- 需要动态生成 payload
- YAML 模板无法满足的检测逻辑

---

## 2. 插件架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        cmd/gosleek                             │
│                     main.go + cmd_*.go                         │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     internal/engine                            │
│                      engine.go                                 │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  executePlugin(ctx, plugin, target, ti, eng)             │  │
│  │                                                          │  │
│  │  1. 构造 plugin.Context                                   │  │
│  │  2. 注入 OOBHandle (如果 NeedsOOB)                        │  │
│  │  3. 注入 Logger / Reporter                                │  │  │
│  │  4. 调用 plugin.Verify(ctx, pctx)                        │  │
│  │  5. 处理返回的 Result                                     │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                         plugins/                               │
│                                                                  │
│  init.go  → 集中导入所有插件包，触发 init() 注册                 │
│  └── cve_2022_22947/    → Spring Cloud Gateway SpEL RCE        │
│  └── cve_2022_22963/    → Spring Cloud Function SpEL OOB       │
│  └── jwt_secret_bruteforce/ → JWT 弱密钥爆破                    │
│  └── api_endpoint_discovery/ → API 端点发现                     │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. 插件接口

每个插件必须实现 `plugin.Plugin` 接口：

```go
type Plugin interface {
    // Meta 返回插件的元信息（ID、名称、严重等级、标签等）
    Meta() types.TemplateMeta

    // Fingerprints 返回指纹预过滤规则（可选，返回 nil 表示不过滤）
    Fingerprints() []types.FingerprintRule

    // Verify 执行漏洞检测
    Verify(ctx context.Context, pctx *plugin.Context) (*types.Result, error)

    // NeedsOOB 是否需要 OOB 验证
    NeedsOOB() bool
}
```

---

## 4. 开发环境准备

### 4.1 项目结构

在 `plugins/` 目录下创建新子包：

```
plugins/
├── init.go                    # 集中导入
├── cve_2022_22947/
│   └── cve_2022_22947.go
├── cve_2022_22963/
│   └── cve_2022_22963.go
├── jwt_secret_bruteforce/
│   └── jwt_secret_bruteforce.go
└── my_plugin/                 # 新插件
    └── my_plugin.go
```

### 4.2 模块路径

```go
package my_plugin

import (
    "context"
    "github.com/gosleek/gosleek/internal/plugin"
    "github.com/gosleek/gosleek/pkg/types"
)
```

### 4.3 编译

```bash
go build -o gosleek ./cmd/gosleek/
```

---

## 5. 第一个插件：Hello World

### 5.1 创建插件目录

```bash
mkdir -p plugins/hello_world
```

### 5.2 编写插件代码

```go
// plugins/hello_world/hello_world.go
package hello_world

import (
    "context"
    "github.com/gosleek/gosleek/internal/plugin"
    "github.com/gosleek/gosleek/pkg/types"
)

// HelloPlugin 实现 Plugin 接口
type HelloPlugin struct{}

// init 注册插件
func init() {
    plugin.Register(&HelloPlugin{})
}

// Meta 返回元信息
func (p *HelloPlugin) Meta() types.TemplateMeta {
    return types.TemplateMeta{
        ID:          "hello-world",
        Name:        "Hello World Test",
        Description: "一个简单的测试插件",
        Severity:    types.SeverityInfo,
        Author:      "your-name",
        Tags:        []string{"test", "hello"},
    }
}

// Fingerprints 不需要指纹过滤
func (p *HelloPlugin) Fingerprints() []types.FingerprintRule {
    return nil
}

// Verify 执行检测
func (p *HelloPlugin) Verify(ctx context.Context, pctx *plugin.Context) (*types.Result, error) {
    // 发送请求
    resp, err := pctx.Client.Get(ctx, pctx.Target)
    if err != nil {
        return nil, err
    }

    // 检查响应
    if resp.StatusCode == 200 {
        return &types.Result{
            TemplateID: p.Meta().ID,
            Name:       p.Meta().Name,
            Severity:   p.Meta().Severity,
            Target:     pctx.Target,
            Evidence:   "Hello World 插件运行成功！",
            RawRequest: "GET / HTTP/1.1",
            RawResponse: resp.Raw,
        }, nil
    }

    return nil, nil
}

// NeedsOOB 不需要 OOB
func (p *HelloPlugin) NeedsOOB() bool {
    return false
}
```

### 5.3 注册插件

编辑 `plugins/init.go`，添加导入：

```go
// plugins/init.go
package plugins

import (
    _ "github.com/gosleek/gosleek/plugins/hello_world"
    // ... 其他导入
)
```

### 5.4 编译并测试

```bash
go build -o gosleek ./cmd/gosleek/
./gosleek list                    # 应能看到 hello-world
./gosleek scan -t http://example.com -id hello-world
```

---

## 6. Plugin 接口详解

### 6.1 Meta()

```go
func (p *MyPlugin) Meta() types.TemplateMeta {
    return types.TemplateMeta{
        ID:          "my-plugin-id",       // 必填：唯一标识
        Name:        "插件名称",             // 必填：显示名称
        Description: "插件描述",             // 可选：详细描述
        Severity:    types.SeverityCritical, // 必填：严重等级
        Author:      "author-name",          // 可选：作者
        Tags:        []string{"tag1", "tag2"}, // 可选：标签
        Reference:   []string{"https://..."}, // 可选：参考链接
    }
}
```

**严重等级常量**：
```go
types.SeverityInfo     // "info"
types.SeverityLow      // "low"
types.SeverityMedium   // "medium"
types.SeverityHigh     // "high"
types.SeverityCritical // "critical"
```

### 6.2 Fingerprints()

```go
func (p *MyPlugin) Fingerprints() []types.FingerprintRule {
    return []types.FingerprintRule{
        {
            Title: "Spring Boot",
        },
        {
            Header: []string{"X-Application-Context"},
        },
    }
}
```

**FingerprintRule 字段**：
```go
type FingerprintRule struct {
    Title  string   // 匹配响应 <title> 标签
    Header []string // 匹配响应头（格式：["Key: value-pattern"]）
}
```

**规则**：返回 nil 表示不做指纹过滤；非空时，目标匹配**任一**规则才执行 Verify。

### 6.3 NeedsOOB()

```go
func (p *MyPlugin) NeedsOOB() bool {
    return false // 或 true
}
```

- `false`：不需要 OOB 验证
- `true`：需要 OOB 验证，若 OOB 未配置则跳过此插件

### 6.4 Verify()

```go
func (p *MyPlugin) Verify(ctx context.Context, pctx *plugin.Context) (*types.Result, error) {
    // 检测逻辑
    // 返回 nil 表示未命中
    // 返回 (*types.Result, nil) 表示命中
    // 返回 (nil, error) 表示执行出错
}
```

---

## 7. Context 上下文详解

### 7.1 Context 结构

```go
type Context struct {
    Target     string              // 目标 URL
    TargetInfo *placeholder.TargetInfo  // 解析后的目标信息
    Client     *httpclient.Client  // HTTP 客户端（含代理/限速/重试）
    Eng        *placeholder.Engine // 占位符引擎
    Ceye       OOBHandle           // OOB 句柄（如果 NeedsOOB 返回 true）
    Log        Logger              // 日志接口
    Reporter   Reporter            // 结构化日志输出
    Vars       map[string]string   // 跨请求共享变量
}
```

### 7.2 TargetInfo 结构

```go
type TargetInfo struct {
    BaseURL   string  // 完整基础 URL: http://example.com:8080
    Hostname  string  // 主机名+端口: example.com:8080
    Host      string  // 主机名: example.com
    Port      string  // 端口: 8080
    Scheme    string  // 协议: http/https
    Path      string  // 路径: /api/v1
}
```

### 7.3 使用 Client 发送请求

`pctx.Client` 是引擎提供的 HTTP 客户端，包含代理、限速、重试、连接池等能力。**不要自行创建 `http.Client`**。

```go
// 发送原始请求（最常用）
resp, err := pctx.Client.SendRaw(ctx, pctx.Target, rawRequest)

// 发送解析后的请求
parsed, err := httpclient.ParseRaw(rawRequest)
resp, err := pctx.Client.SendParsed(ctx, pctx.Target, parsed)
```

**Response 结构**：
```go
type Response struct {
    StatusCode int              // HTTP 状态码
    Headers    map[string][]string  // 响应头（多值）
    Body       string             // 响应正文
    Raw        string             // 完整原始响应（用于复放）
    Time       time.Duration      // 响应时间
}

// 辅助方法
resp.GetHeader("Server")       // 获取单个头值
resp.AllHeaders()              // 获取所有头（字符串格式）
resp.GetCookie("PHPSESSID")    // 获取 Cookie
```

**请求格式要求**：
```
METHOD /path?query=value HTTP/1.1\r\n
Header-Name: Header-Value\r\n
\r\n
[Body content]
```

**注意事项**：
- 必须使用 `\r\n` 换行（不是 `\n`）
- Header 和 Body 之间必须有 `\r\n\r\n` 空行
- Host 头必须与目标一致（除非使用 `--allow-external-hosts`）

### 7.4 使用 Eng 进行占位符替换

`pctx.Eng` 是占位符引擎，支持所有 YAML 模板中的占位符和函数。

```go
// 基本替换
hostname := pctx.Eng.Replace("{{Hostname}}")
port := pctx.Eng.Replace("{{Port}}")
scheme := pctx.Eng.Replace("{{Scheme}}")

// 使用动态函数
randomID := pctx.Eng.Replace("{{rand_text_alpha(8)}}")
hexToken := pctx.Eng.Replace("{{rand_text_hex(16)}}")
base64Payload := pctx.Eng.Replace("{{base64_encode('test')}}")

// JNDI payload 转义
jndiPayload := pctx.Eng.ReplaceWithEscape("$${jndi:ldap://{{oob}}}")
// 结果: ${jndi:ldap://abc123.ceye.io}
```

**支持的占位符**（与 YAML 模板相同）：

| 占位符 | 说明 | 示例 |
|--------|------|------|
| `{{Hostname}}` | 主机名+端口 | `example.com:8080` |
| `{{Port}}` | 端口号 | `8080` |
| `{{Scheme}}` | 协议 | `http` |
| `{{baseURL}}` | 完整基础 URL | `http://example.com:8080` |
| `{{oob}}` | OOB 回连地址 | `abc123.ceye.io` |
| `{{oob_label}}` | OOB 标签 | `abc123` |
| `{{oob_token}}` | OOB 凭据 | API token |

**支持的函数**（与 YAML 模板相同）：

| 函数 | 示例 | 说明 |
|------|------|------|
| `randstr(n?)` | `{{randstr}}` | 随机十六进制 |
| `rand_text_alpha(n?)` | `{{rand_text_alpha(8)}}` | 随机字母 |
| `rand_text_hex(n?)` | `{{rand_text_hex(16)}}` | 随机十六进制 |
| `rand_int(min, max?)` | `{{rand_int(1,100)}}` | 随机整数 |
| `base64_encode(s)` | `{{base64_encode("test")}}` | Base64 编码 |
| `url_encode(s)` | `{{url_encode("a b")}}` | URL 编码 |
| `md5(s)` | `{{md5("test")}}` | MD5 哈希 |
| `uuid()` | `{{uuid}}` | UUID v4 |

### 7.5 使用 Vars 共享变量

```go
// 存储变量
pctx.Vars["token"] = "abc123"

// 读取变量
token := pctx.Vars["token"]
```

---

## 8. OOBHandle 接口详解

### 8.1 OOBHandle 接口

```go
type OOBHandle interface {
    Label() string        // 返回 OOB 标签（如 "gs-a1b2c3d4"）
    URL() string          // 返回完整回连地址（如 "gs-a1b2c3d4.foo.ceye.io"）
    VerifyDNS(ctx) (bool, error)   // 查询 DNS 回连记录
    VerifyHTTP(ctx) (bool, error)  // 查询 HTTP 回连记录
}
```

### 8.2 使用 OOBHandle

OOB（Out-of-Band）验证用于检测无回显漏洞。插件通过 `pctx.Ceye` 访问 OOB 能力。

**支持的 Provider**：ceye、dnslog、callbackred（自动代理到对应 Provider 的 API）。

**前置检查**：
```go
func (p *MyPlugin) Verify(ctx context.Context, pctx *plugin.Context) (*types.Result, error) {
    // 必须检查 Ceye 是否为 nil
    if pctx.Ceye == nil {
        pctx.Log.Info("OOB 未配置，跳过检测")
        return nil, nil
    }

    oobURL := pctx.Ceye.URL()    // 获取完整回连地址
    oobLabel := pctx.Ceye.Label() // 获取唯一标签
```

**渐进式验证模式**（推荐）：
```go
    // 渐进式重试：3s → 5s → 8s，逐步等待 OOB 回调
    for _, delay := range []int{3, 5, 8} {
        select {
        case <-ctx.Done():
            return nil, nil  // 取消或超时
        case <-time.After(time.Duration(delay) * time.Second):
        }

        // 先验证 DNS 回连
        ok, err := pctx.Ceye.VerifyDNS(ctx)
        if err != nil {
            pctx.Log.Debug("DNS 验证错误: %v", err)
            continue
        }
        if ok {
            return p.buildResult(pctx, oobLabel, "dns"), nil
        }

        // 再验证 HTTP 回连
        ok, err = pctx.Ceye.VerifyHTTP(ctx)
        if err != nil {
            pctx.Log.Debug("HTTP 验证错误: %v", err)
            continue
        }
        if ok {
            return p.buildResult(pctx, oobLabel, "http"), nil
        }
    }

    pctx.Log.Info("OOB 验证未命中: %s", oobLabel)
    return nil, nil
}
```

**OOBHandle 方法详解**：

| 方法 | 返回类型 | 说明 |
|------|----------|------|
| `Label()` | `string` | 返回 OOB 标签（如 `"gs-a1b2c3d4"`），用于 API 查询过滤 |
| `URL()` | `string` | 返回完整回连地址（如 `"gs-a1b2c3d4.foo.ceye.io"`），用于构造 payload |
| `VerifyDNS(ctx)` | `(bool, error)` | 查询 DNS 回连记录（自动代理到对应 Provider API） |
| `VerifyHTTP(ctx)` | `(bool, error)` | 查询 HTTP 回连记录（自动代理到对应 Provider API） |

**Provider 行为差异**：

| Provider | VerifyDNS | VerifyHTTP |
|----------|-----------|------------|
| ceye | 查询 `api.ceye.io/v1/records?type=dns` | 查询 `api.ceye.io/v1/records?type=http` |
| dnslog | 查询 `47.244.138.18/getrecords.php` | 同 DNS（dnslog 只记录 DNS） |
| callbackred | 查询 `callback.red` POST key=xxx | 同 DNS（callbackred 合并 DNS/HTTP） |

---

## 9. PluginLogger 详解

### 9.1 Logger 接口

```go
type Logger interface {
    Info(msg string, args ...interface{})
    Debug(msg string, args ...interface{})
    Error(msg string, args ...interface{})
}
```

### 9.2 使用示例

```go
// 信息日志
pctx.Log.Info("目标: %s", pctx.Target)
pctx.Log.Info("检测到 %d 个端点", len(endpoints))

// 调试日志（需 -vv 级别才会输出）
pctx.Log.Debug("请求详情: %v", rawRequest)
pctx.Log.Debug("响应内容: %s", resp.Body)

// 错误日志
pctx.Log.Error("请求失败: %v", err)
pctx.Log.Error("解析 JSON 失败: %v", err)
```

---

## 10. PluginReporter 详解

### 10.1 Reporter 接口

```go
type Reporter interface {
    LogStep(stepName string, stepIndex int)
    LogRequest(stepName string, stepIndex int, reqIndex int, raw string)
    LogResponse(stepName string, stepIndex int, reqIndex int,
        status int, body string, raw string, elapsed time.Duration)
    LogMatch(stepName string, stepIndex int, reqIndex int,
        matched bool, condition string, types []string, evidence string)
}
```

### 10.2 使用示例

```go
func (p *MyPlugin) Verify(ctx context.Context, pctx *plugin.Context) (*types.Result, error) {
    reporter := pctx.Reporter

    // 记录步骤开始
    reporter.LogStep("trigger", 0)

    // 构造并发送请求
    rawReq := "POST /api HTTP/1.1\r\nHost: " + pctx.TargetInfo.Hostname + "\r\n\r\n"
    reporter.LogRequest("trigger", 0, 0, rawReq)

    resp, err := pctx.Client.SendRaw(ctx, pctx.Target, rawReq)
    if err != nil {
        return nil, err
    }

    // 记录响应
    reporter.LogResponse("trigger", 0, 0, resp.StatusCode, resp.Body, resp.Raw, resp.Time)

    // 判断是否命中
    matched := resp.StatusCode == 200 && strings.Contains(resp.Body, "vulnerable")
    evidence := fmt.Sprintf("status=%d, body_len=%d", resp.StatusCode, len(resp.Body))

    // 记录匹配结果
    reporter.LogMatch("trigger", 0, 0, matched, "and", []string{"status", "word"}, evidence)

    if matched {
        return &types.Result{...}, nil
    }
    return nil, nil
}
```

### 10.3 Reporter 输出效果

在 `-vv` 模式下，Reporter 会输出 Burp Suite 风格的日志：

```
[请求] trigger[0] req[0]  POST /actuator/gateway/routes/gs_abcd1234  256 bytes
POST /actuator/gateway/routes/gs_abcd1234 HTTP/1.1
Host: target.com
Content-Type: application/json
...

[响应] trigger[0] req[0]  status=201  45ms  0 bytes
HTTP/1.1 201 Created
...

[匹配] trigger[0] req[0]  PASS  cond=or  types=status  evidence="status: 201"
```

### 10.4 Reporter 与 Logger 的区别

| 特性 | Reporter | Logger |
|------|----------|--------|
| 用途 | 步骤级结构化日志 | 自由文本日志 |
| 输出格式 | Burp Suite 风格 | printf 风格 |
| 可见级别 | `-vv` | 始终可见（Info/Error） |
| 适用场景 | HTTP 请求/响应/匹配 | 调试信息、错误、统计 |

---

## 11. Result 结构详解

### 11.1 Result 字段

```go
type Result struct {
    TemplateID  string            `json:"template-id"`
    Name        string            `json:"name"`
    Severity    string            `json:"severity"`
    Description string            `json:"description,omitempty"`
    Target      string            `json:"target"`
    MatchedAt   string            `json:"matched-at"`
    Tags        []string          `json:"tags,omitempty"`
    Reference   []string          `json:"reference,omitempty"`
    Timestamp   time.Time         `json:"timestamp"`
    Evidence    string            `json:"evidence,omitempty"`
    Extracted   map[string]string `json:"extracted,omitempty"`
    RawRequest  string            `json:"raw-request,omitempty"`
    RawResponse string            `json:"raw-response,omitempty"`
}
```

### 11.2 字段说明

| 字段 | 必填 | 说明 |
|------|------|------|
| `TemplateID` | 是 | 与 `Meta().ID` 一致，用于去重 |
| `Name` | 是 | 漏洞名称 |
| `Severity` | 是 | 严重等级 |
| `Description` | 否 | 漏洞描述 |
| `Target` | 是 | 目标 URL |
| `MatchedAt` | 否 | 命中时间（可留空，引擎自动填充） |
| `Tags` | 否 | 标签列表 |
| `Reference` | 否 | 参考链接 |
| `Evidence` | 否 | 匹配证据，说明为何命中 |
| `Extracted` | 否 | 提取的数据 |
| `RawRequest` | 否 | 原始请求（用于复放） |
| `RawResponse` | 否 | 原始响应（用于复放） |

### 11.3 返回 Result 示例

```go
return &types.Result{
    TemplateID:  p.Meta().ID,
    Name:        p.Meta().Name,
    Severity:    p.Meta().Severity,
    Description: p.Meta().Description,
    Target:      pctx.Target,
    Tags:        p.Meta().Tags,
    Reference:   p.Meta().Reference,
    Evidence:    "SpEL RCE 验证成功，响应中包含 marker: " + marker,
    Extracted: map[string]string{
        "marker":    marker,
        "route_id":  routeID,
    },
    RawRequest:  rawReq,
    RawResponse: resp.Raw,
}, nil
```

### 11.4 返回 nil 的含义

```go
// 未命中漏洞
return nil, nil

// 执行出错（会记录错误日志）
return nil, fmt.Errorf("请求失败: %w", err)
```

**重要**：
- `return nil, nil` → 未命中，不输出结果
- `return nil, err` → 执行出错，会打印错误日志
- `return &Result{}, nil` → 命中漏洞，输出结果
- **永远不要 panic**，错误应通过 return 传递

---

## 12. 插件注册机制

### 12.1 注册方式

每个插件包通过 `init()` 函数调用 `plugin.Register()`：

```go
func init() {
    plugin.Register(&MyPlugin{})
}
```

### 12.2 集中导入

`plugins/init.go` 通过 blank import 触发所有插件的 `init()`：

```go
// plugins/init.go
package plugins

import (
    _ "github.com/gosleek/gosleek/plugins/cve_2022_22947"
    _ "github.com/gosleek/gosleek/plugins/cve_2022_22963"
    _ "github.com/gosleek/gosleek/plugins/jwt_secret_bruteforce"
    _ "github.com/gosleek/gosleek/plugins/api_endpoint_discovery"
    _ "github.com/gosleek/gosleek/plugins/my_plugin"  // 新插件
)
```

### 12.3 编译期注册

插件在编译期注册到全局 registry，运行时无需动态加载。因此：

1. 新增插件后必须重新编译
2. ID 必须全局唯一（重复注册会 panic）

---

## 13. 完整插件示例

### 13.1 示例 1：简单存在性检测

```go
// plugins/simple_check/simple_check.go
package simple_check

import (
    "context"
    "strings"

    "github.com/gosleek/gosleek/internal/plugin"
    "github.com/gosleek/gosleek/pkg/types"
)

type SimpleCheck struct{}

func init() {
    plugin.Register(&SimpleCheck{})
}

func (p *SimpleCheck) Meta() types.TemplateMeta {
    return types.TemplateMeta{
        ID:          "simple-check",
        Name:        "简单存在性检测",
        Description: "检测目标是否返回特定关键词",
        Severity:    types.SeverityInfo,
        Tags:        []string{"test", "check"},
    }
}

func (p *SimpleCheck) Fingerprints() []types.FingerprintRule {
    return nil
}

func (p *SimpleCheck) Verify(ctx context.Context, pctx *plugin.Context) (*types.Result, error) {
    reporter := pctx.Reporter

    // 发送请求
    reporter.LogStep("check", 0)
    rawReq := "GET / HTTP/1.1\r\nHost: " + pctx.TargetInfo.Hostname + "\r\n\r\n"
    reporter.LogRequest("check", 0, 0, rawReq)

    resp, err := pctx.Client.SendRaw(ctx, pctx.Target, rawReq)
    if err != nil {
        reporter.LogResponse("check", 0, 0, 0, "", "", 0)
        pctx.Log.Error("请求失败: %v", err)
        return nil, nil
    }

    reporter.LogResponse("check", 0, 0, resp.StatusCode, resp.Body, resp.Raw, resp.Time)

    // 匹配逻辑
    matched := resp.StatusCode == 200 && strings.Contains(resp.Body, "Welcome")
    evidence := ""
    if matched {
        evidence = fmt.Sprintf("status=%d, body contains 'Welcome'", resp.StatusCode)
    }
    reporter.LogMatch("check", 0, 0, matched, "or", []string{"status", "word"}, evidence)

    if matched {
        return &types.Result{
            TemplateID: p.Meta().ID,
            Name:       p.Meta().Name,
            Severity:   p.Meta().Severity,
            Target:     pctx.Target,
            Evidence:   evidence,
            RawRequest: rawReq,
            RawResponse: resp.Raw,
        }, nil
    }

    return nil, nil
}

func (p *SimpleCheck) NeedsOOB() bool {
    return false
}
```

### 13.2 示例 2：有回显的 RCE 检测

```go
// plugins/rce_check/rce_check.go
package rce_check

import (
    "context"
    "fmt"
    "strings"

    "github.com/gosleek/gosleek/internal/plugin"
    "github.com/gosleek/gosleek/pkg/types"
)

type RCECheck struct{}

func init() {
    plugin.Register(&RCECheck{})
}

func (p *RCECheck) Meta() types.TemplateMeta {
    return types.TemplateMeta{
        ID:          "rce-check",
        Name:        "RCE 回显检测",
        Description: "通过系统命令回显检测远程代码执行",
        Severity:    types.SeverityCritical,
        Tags:        []string{"rce", "check"},
    }
}

func (p *RCECheck) Verify(ctx context.Context, pctx *plugin.Context) (*types.Result, error) {
    reporter := pctx.Reporter

    // 步骤 1: 发送包含 whoami 的 payload
    reporter.LogStep("trigger", 0)
    payload := "'; whoami; #"
    rawReq := fmt.Sprintf("GET /api?q=%s HTTP/1.1\r\nHost: %s\r\n\r\n",
        payload, pctx.TargetInfo.Hostname)
    reporter.LogRequest("trigger", 0, 0, rawReq)

    resp, err := pctx.Client.SendRaw(ctx, pctx.Target, rawReq)
    if err != nil {
        pctx.Log.Error("请求失败: %v", err)
        return nil, nil
    }

    reporter.LogResponse("trigger", 0, 0, resp.StatusCode, resp.Body, resp.Raw, resp.Time)

    // 步骤 2: 检查响应是否包含 "root" 或 "www-data" 或 "nobody"
    markers := []string{"root", "www-data", "nobody"}
    matched := false
    var evidence string
    for _, marker := range markers {
        if strings.Contains(resp.Body, marker) {
            matched = true
            evidence = fmt.Sprintf("响应包含用户标识: %s", marker)
            break
        }
    }

    reporter.LogMatch("trigger", 0, 0, matched, "or", []string{"word"}, evidence)

    if matched {
        return &types.Result{
            TemplateID:  p.Meta().ID,
            Name:        p.Meta().Name,
            Severity:    p.Meta().Severity,
            Target:      pctx.Target,
            Evidence:    evidence,
            RawRequest:  rawReq,
            RawResponse: resp.Raw,
        }, nil
    }

    return nil, nil
}

func (p *RCECheck) NeedsOOB() bool {
    return false
}
```

### 13.3 示例 3：OOB 无回显 RCE

```go
// plugins/oob_rce/oob_rce.go
package oob_rce

import (
    "context"
    "fmt"
    "time"

    "github.com/gosleek/gosleek/internal/plugin"
    "github.com/gosleek/gosleek/pkg/types"
)

type OOBRCE struct{}

func init() {
    plugin.Register(&OOBRCE{})
}

func (p *OOBRCE) Meta() types.TemplateMeta {
    return types.TemplateMeta{
        ID:          "oob-rce-test",
        Name:        "OOB RCE 测试",
        Description: "通过 OOB 验证的无回显 RCE 检测",
        Severity:    types.SeverityCritical,
        Tags:        []string{"rce", "oob", "test"},
    }
}

func (p *OOBRCE) Verify(ctx context.Context, pctx *plugin.Context) (*types.Result, error) {
    // 检查 OOB
    if pctx.Ceye == nil {
        pctx.Log.Info("OOB 未配置，跳过 OOB RCE 检测")
        return nil, nil
    }

    oobURL := pctx.Ceye.URL()
    oobLabel := pctx.Ceye.Label()
    reporter := pctx.Reporter

    // 步骤 1: 触发漏洞
    reporter.LogStep("trigger", 0)
    rawReq := fmt.Sprintf(
        "GET /ping?url=http://%%s HTTP/1.1\r\nHost: %%s\r\n\r\n",
        oobURL, pctx.TargetInfo.Hostname)
    reporter.LogRequest("trigger", 0, 0, rawReq)

    resp, err := pctx.Client.SendRaw(ctx, pctx.Target, rawReq)
    if err != nil {
        pctx.Log.Error("触发请求失败: %v", err)
        return nil, nil
    }

    reporter.LogResponse("trigger", 0, 0, resp.StatusCode, resp.Body, resp.Raw, resp.Time)

    // 步骤 2: 渐进式 OOB 验证
    for _, delay := range []int{3, 5, 8} {
        select {
        case <-ctx.Done():
            return nil, nil
        case <-time.After(time.Duration(delay) * time.Second):
        }

        // 验证 DNS
        ok, err := pctx.Ceye.VerifyDNS(ctx)
        if err != nil {
            pctx.Log.Debug("DNS 验证错误: %v", err)
            continue
        }
        if ok {
            pctx.Log.Info("OOB DNS 回连确认: %s", oobLabel)
            return &types.Result{
                TemplateID: p.Meta().ID,
                Name:       p.Meta().Name,
                Severity:   p.Meta().Severity,
                Target:     pctx.Target,
                Evidence:   fmt.Sprintf("OOB DNS 回连确认: %s", oobLabel),
                Extracted: map[string]string{
                    "oob_label": oobLabel,
                    "oob_type":  "dns",
                },
                RawRequest: rawReq,
            }, nil
        }

        // 验证 HTTP
        ok, err = pctx.Ceye.VerifyHTTP(ctx)
        if err != nil {
            pctx.Log.Debug("HTTP 验证错误: %v", err)
            continue
        }
        if ok {
            pctx.Log.Info("OOB HTTP 回连确认: %s", oobLabel)
            return &types.Result{
                TemplateID: p.Meta().ID,
                Name:       p.Meta().Name,
                Severity:   p.Meta().Severity,
                Target:     pctx.Target,
                Evidence:   fmt.Sprintf("OOB HTTP 回连确认: %s", oobLabel),
                Extracted: map[string]string{
                    "oob_label": oobLabel,
                    "oob_type":  "http",
                },
                RawRequest: rawReq,
            }, nil
        }
    }

    pctx.Log.Info("OOB 验证未命中: %s", oobLabel)
    return nil, nil
}

func (p *OOBRCE) NeedsOOB() bool {
    return true
}

func (p *OOBRCE) Fingerprints() []types.FingerprintRule {
    return nil
}
```

### 13.4 示例 4：字典爆破插件

```go
// plugins/wordlist_check/wordlist_check.go
package wordlist_check

import (
    "bufio"
    "context"
    "fmt"
    "os"
    "strings"

    "github.com/gosleek/gosleek/internal/plugin"
    "github.com/gosleek/gosleek/pkg/types"
)

type WordlistCheck struct{}

func init() {
    plugin.Register(&WordlistCheck{})
}

func (p *WordlistCheck) Meta() types.TemplateMeta {
    return types.TemplateMeta{
        ID:          "wordlist-dir-check",
        Name:        "目录枚举检测",
        Description: "使用字典枚举常见目录",
        Severity:    types.SeverityInfo,
        Tags:        []string{"enumeration", "directory"},
    }
}

func (p *WordlistCheck) Verify(ctx context.Context, pctx *plugin.Context) (*types.Result, error) {
    reporter := pctx.Reporter
    wordlistPath := "wordlists/dirs.txt"

    // 读取字典
    file, err := os.Open(wordlistPath)
    if err != nil {
        pctx.Log.Error("无法打开字典文件: %v", err)
        return nil, nil
    }
    defer file.Close()

    var found []string
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        dir := strings.TrimSpace(scanner.Text())
        if dir == "" || strings.HasPrefix(dir, "#") {
            continue
        }

        path := "/" + strings.TrimPrefix(dir, "/")
        fullURL := pctx.TargetInfo.BaseURL + path

        reporter.LogStep("enumerate", len(found))
        rawReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", path, pctx.TargetInfo.Hostname)
        reporter.LogRequest("enumerate", len(found), 0, rawReq)

        resp, err := pctx.Client.SendRaw(ctx, pctx.Target, rawReq)
        if err != nil {
            pctx.Log.Debug("请求 %s 失败: %v", path, err)
            continue
        }

        reporter.LogResponse("enumerate", len(found), 0, resp.StatusCode, resp.Body, resp.Raw, resp.Time)

        // 200 或 301/302 且不为默认页
        if resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302 {
            if !strings.Contains(resp.Body, "404") && !strings.Contains(resp.Body, "Not Found") {
                found = append(found, path)
                pctx.Log.Info("发现目录: %s (status=%d)", path, resp.StatusCode)
            }
        }
    }

    if len(found) > 0 {
        return &types.Result{
            TemplateID: p.Meta().ID,
            Name:       p.Meta().Name,
            Severity:   p.Meta().Severity,
            Target:     pctx.Target,
            Evidence:   fmt.Sprintf("发现 %d 个可用目录: %s", len(found), strings.Join(found, ", ")),
            Extracted: map[string]string{
                "directories": strings.Join(found, "|"),
            },
        }, nil
    }

    return nil, nil
}

func (p *WordlistCheck) NeedsOOB() bool {
    return false
}

func (p *WordlistCheck) Fingerprints() []types.FingerprintRule {
    return nil
}
```

---

## 14. 插件与 YAML 模板对比

### 14.1 功能对比

| 功能 | YAML 模板 | Go 插件 |
|------|-----------|---------|
| 原始 HTTP 请求 | `raw` 字段 | `Client.SendRaw()` |
| 结构化请求 | `path` + `method` + `headers` + `body` | 手动构造 |
| 占位符替换 | 自动 | `Eng.Replace()` |
| 匹配引擎 | `matchers` 字段 | 手动判断 |
| 提取引擎 | `extractors` 字段 | `Eng.SetExtracted()` |
| 工作流 | `workflow` 字段 | 手动顺序执行 |
| 字典爆破 | `wordlist` 字段 | 手动循环 |
| OOB 验证 | 自动注入 + API 轮询 | `OOBHandle` 接口 |
| DSL 表达式 | `dsl` matcher | 需手动实现 |
| 指纹预过滤 | `fingerprints` 字段 | `Fingerprints()` 方法 |
| 并发控制 | 有限（线程数） | 完全控制 |
| 日志输出 | `-v`/`-vv` | `pctx.Log` + `Reporter` |

### 14.2 选择建议

**使用 YAML 模板**：
- 简单的一次性请求检测
- 标准的漏洞模式匹配
- 快速原型验证
- 无需编程的场景

**使用 Go 插件**：
- 多步骤复杂工作流
- 需要并发和聚合
- 需要密码学运算
- 需要动态 payload 生成
- 复杂的条件判断逻辑

---

## 15. 开发步骤指南

### 15.1 编写流程

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  1. 设计逻辑 │───▶│  2. 创建包   │───▶│  3. 实现接口 │───▶│  4. 测试验证 │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

### 15.2 详细步骤

**Step 1：设计检测逻辑**
1. 确定检测目标和技术细节
2. 设计请求序列和匹配规则
3. 确定是否需要 OOB 验证

**Step 2：创建插件包**
```bash
mkdir -p plugins/my_plugin
```

**Step 3：实现 Plugin 接口**
```go
package my_plugin

import (
    "context"
    "github.com/gosleek/gosleek/internal/plugin"
    "github.com/gosleek/gosleek/pkg/types"
)

type MyPlugin struct{}

func init() {
    plugin.Register(&MyPlugin{})
}

func (p *MyPlugin) Meta() types.TemplateMeta { ... }
func (p *MyPlugin) Fingerprints() []types.FingerprintRule { ... }
func (p *MyPlugin) Verify(ctx context.Context, pctx *plugin.Context) (*types.Result, error) { ... }
func (p *MyPlugin) NeedsOOB() bool { ... }
```

**Step 4：注册插件**
编辑 `plugins/init.go`：
```go
import _ "github.com/gosleek/gosleek/plugins/my_plugin"
```

**Step 5：编译和测试**
```bash
go build -o gosleek ./cmd/gosleek/
./gosleek list                    # 确认插件加载
./gosleek scan -t http://target -id my-plugin-id -vv
```

### 15.3 检查清单

- [ ] 实现了所有 Plugin 接口方法
- [ ] `init()` 中调用了 `plugin.Register()`
- [ ] `init.go` 中导入了新包
- [ ] `Meta().ID` 全局唯一
- [ ] `Severity` 值合法
- [ ] `Verify()` 返回 `nil` 表示未命中
- [ ] 正确处理了 `ctx.Done()`（取消/超时）
- [ ] 使用了 `pctx.Reporter` 记录步骤日志
- [ ] 使用了 `pctx.Log` 记录调试信息

---

## 16. 调试与测试

### 16.1 日志级别

```bash
# 默认级别：仅显示结果
./gosleek scan -t http://target -id my-plugin

# -v 级别：显示步骤日志
./gosleek scan -t http://target -id my-plugin -v

# -vv 级别：显示完整请求/响应包
./gosleek scan -t http://target -id my-plugin -vv
```

### 16.2 使用 Reporter 调试

```go
// 每个关键步骤都记录日志
reporter.LogStep("step-name", stepIndex)
reporter.LogRequest("step-name", stepIndex, reqIndex, rawReq)
reporter.LogResponse("step-name", stepIndex, reqIndex, status, body, raw, elapsed)
reporter.LogMatch("step-name", stepIndex, reqIndex, matched, condition, types, evidence)
```

### 16.3 使用 Log 调试

```go
// 信息级别：始终输出
pctx.Log.Info("检测到 %d 个端点", len(endpoints))

// 调试级别：-vv 时输出
pctx.Log.Debug("请求详情: %v", rawRequest)

// 错误级别：始终输出
pctx.Log.Error("请求失败: %v", err)
```

### 16.4 单元测试

```go
// plugins/my_plugin/my_plugin_test.go
package my_plugin

import (
    "testing"
    "github.com/gosleek/gosleek/pkg/types"
)

func TestMeta(t *testing.T) {
    p := &MyPlugin{}
    meta := p.Meta()
    if meta.ID != "my-plugin-id" {
        t.Errorf("expected ID 'my-plugin-id', got '%s'", meta.ID)
    }
    if meta.Severity != types.SeverityCritical {
        t.Errorf("expected severity 'critical', got '%s'", meta.Severity)
    }
}
```

---

## 17. 常见问题

### 17.1 插件未加载

**症状**：`gosleek list` 看不到新插件

**排查**：
1. 确认 `init()` 中调用了 `plugin.Register()`
2. 确认 `plugins/init.go` 中导入了新包
3. 确认已重新编译

### 17.2 ID 冲突

**症状**：编译时报 `plugin already registered`

**排查**：
1. 检查 `Meta().ID` 是否与其他插件重复
2. 确保 ID 全局唯一

### 17.3 OOB 未生效

**症状**：`pctx.Ceye` 为 nil

**排查**：
1. 确认 `NeedsOOB()` 返回 true
2. 确认命令行或配置文件启用了 OOB
3. 确认 OOB provider 配置正确
4. 确认 `--allow-external-hosts` 已添加（外部 provider）

### 17.4 请求失败

**症状**：`pctx.Client.SendRaw()` 返回错误

**排查**：
1. 检查请求格式是否正确（`METHOD /path HTTP/1.1\r\n`）
2. 检查 Host 头是否正确
3. 检查目标 URL 格式
4. 查看 `-vv` 日志获取详细错误

### 17.5 内存泄漏

**建议**：
1. 确保 `context` 正确传递和取消
2. 避免在循环中创建大量 goroutine
3. 使用 `defer` 关闭文件/连接

---

## 18. 最佳实践

### 18.1 Context 取消处理

所有异步操作必须检查 `ctx.Done()`：

```go
func (p *MyPlugin) Verify(ctx context.Context, pctx *plugin.Context) (*types.Result, error) {
    // 每次长时间操作前检查取消
    select {
    case <-ctx.Done():
        pctx.Log.Debug("上下文已取消")
        return nil, nil
    default:
    }

    // 或使用带超时的 context
    reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
    defer cancel()

    resp, err := pctx.Client.SendRaw(reqCtx, pctx.Target, rawReq)
    // ...
}
```

### 18.2 错误处理规范

```go
// 正确：业务逻辑未命中 → 返回 nil, nil
if resp.StatusCode != 200 {
    return nil, nil
}

// 正确：执行出错 → 返回 nil, error
resp, err := pctx.Client.SendRaw(ctx, pctx.Target, rawReq)
if err != nil {
    pctx.Log.Error("请求失败: %v", err)
    return nil, err
}

// 错误：永远不要 panic
// panic("unexpected error")  // ❌
```

### 18.3 资源清理

```go
func (p *MyPlugin) Verify(ctx context.Context, pctx *plugin.Context) (*types.Result, error) {
    // 使用 defer 确保清理
    created := false
    defer func() {
        if created {
            cleanupRoute(ctx, pctx)
        }
    }()

    // 创建资源
    created = true
    // ...
}
```

### 18.4 并发安全

```go
// 使用 sync.Mutex 保护共享状态
type MyPlugin struct {
    mu    sync.Mutex
    count int
}

// 或使用 channel 聚合结果
results := make(chan *types.Result, 10)
var wg sync.WaitGroup
for _, target := range targets {
    wg.Add(1)
    go func(t string) {
        defer wg.Done()
        // 检测逻辑
    }(target)
}
wg.Wait()
close(results)
```

### 18.5 日志分级

```go
// Info：关键操作步骤
pctx.Log.Info("目标: %s, 路由ID: %s", target, routeID)

// Debug：调试细节（-vv 可见）
pctx.Log.Debug("请求详情: %v", rawReq)
pctx.Log.Debug("响应内容: %s", resp.Body)

// Error：错误信息（始终可见）
pctx.Log.Error("请求失败: %v", err)
```

### 18.6 多步骤工作流模式

```go
type StepResult struct {
    name    string
    matched bool
    data    map[string]string
}

func (p *MyPlugin) Verify(ctx context.Context, pctx *plugin.Context) (*types.Result, error) {
    steps := []func(context.Context, *plugin.Context) (*StepResult, error){
        p.step1Login,
        p.step2ExtractToken,
        p.step3TestBypass,
    }

    var prevData map[string]string
    for i, step := range steps {
        select {
        case <-ctx.Done():
            return nil, nil
        default:
        }

        result, err := step(ctx, pctx)
        if err != nil {
            pctx.Log.Error("步骤 %d 失败: %v", i, err)
            return nil, nil
        }
        if !result.matched {
            pctx.Log.Info("步骤 %d 未命中: %s", i, result.name)
            return nil, nil
        }
        if prevData == nil {
            prevData = result.data
        } else {
            for k, v := range result.data {
                prevData[k] = v
            }
        }
    }

    return p.buildResult(pctx, prevData), nil
}
```

### 18.7 OOB 验证最佳实践

```go
func (p *MyPlugin) Verify(ctx context.Context, pctx *plugin.Context) (*types.Result, error) {
    if pctx.Ceye == nil {
        return nil, nil
    }

    oobURL := pctx.Ceye.URL()
    oobLabel := pctx.Ceye.Label()

    // 步骤 1: 触发
    rawReq := buildTriggerRequest(oobURL, pctx.TargetInfo.Hostname)
    resp, err := pctx.Client.SendRaw(ctx, pctx.Target, rawReq)
    if err != nil {
        return nil, nil
    }
    if resp.StatusCode < 200 || resp.StatusCode >= 400 {
        return nil, nil
    }

    // 步骤 2: 渐进式验证（支持 ceye/dnslog/callbackred）
    delays := []int{3, 5, 8, 15}
    for _, delay := range delays {
        select {
        case <-ctx.Done():
            return nil, nil
        case <-time.After(time.Duration(delay) * time.Second):
        }

        // DNS 验证
        ok, _ := pctx.Ceye.VerifyDNS(ctx)
        if ok {
            return p.buildResult(pctx, oobLabel, "dns"), nil
        }

        // HTTP 验证（dnslog 的 HTTP 验证等价于 DNS）
        ok, _ = pctx.Ceye.VerifyHTTP(ctx)
        if ok {
            return p.buildResult(pctx, oobLabel, "http"), nil
        }
    }

    return nil, nil
}
```

**注意**：Go 插件的 OOBHandle 现在支持 ceye、dnslog、callbackred 三种 Provider。`pctx.Ceye` 会根据全局 OOB 配置自动代理到对应的 Provider API。

---

## 附录 A：插件开发检查清单

### A.1 必备要素

- [ ] `package` 声明
- [ ] `init()` 函数调用 `plugin.Register()`
- [ ] `Meta()` 返回合法元信息
- [ ] `Fingerprints()` 返回 nil 或规则列表
- [ ] `Verify()` 实现检测逻辑
- [ ] `NeedsOOB()` 返回正确值
- [ ] `plugins/init.go` 导入新包
- [ ] 处理 `ctx.Done()` 支持取消
- [ ] 返回 `nil` 表示未命中（不是错误）
- [ ] 错误时使用 `return nil, nil` 而非 panic

### A.2 最佳实践

- [ ] 使用 `reporter.LogStep()` 记录步骤
- [ ] 使用 `pctx.Log.Info()` / `pctx.Log.Debug()` 记录日志
- [ ] 处理 `ctx.Done()` 支持取消
- [ ] 返回 `nil` 表示未命中（不是错误）
- [ ] 错误时使用 `return nil, nil` 而非 panic
- [ ] 使用 `pctx.Client` 而非自行创建 HTTP 客户端
- [ ] OOB 插件使用渐进式重试（3s/5s/8s）
- [ ] 使用 `defer` 确保资源清理
- [ ] 多步骤插件使用函数式拆分
- [ ] 并发插件使用 sync.Mutex 或 channel

---

## 附录 B：插件示例代码模板

```go
package my_plugin

import (
    "context"
    "fmt"

    "github.com/gosleek/gosleek/internal/plugin"
    "github.com/gosleek/gosleek/pkg/types"
)

// MyPlugin 实现 Plugin 接口
type MyPlugin struct{}

// init 注册插件（必须）
func init() {
    plugin.Register(&MyPlugin{})
}

// Meta 返回插件元信息
func (p *MyPlugin) Meta() types.TemplateMeta {
    return types.TemplateMeta{
        ID:          "my-plugin-id",
        Name:        "插件名称",
        Description: "插件描述",
        Severity:    types.SeverityMedium,
        Author:      "author",
        Tags:        []string{"tag1", "tag2"},
        Reference:   []string{"https://..."},
    }
}

// Fingerprints 返回指纹预过滤规则（可选）
func (p *MyPlugin) Fingerprints() []types.FingerprintRule {
    return nil
}

// Verify 执行漏洞检测
func (p *MyPlugin) Verify(ctx context.Context, pctx *plugin.Context) (*types.Result, error) {
    reporter := pctx.Reporter

    // 步骤 1: 发送探测请求
    reporter.LogStep("probe", 0)
    rawReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", pctx.TargetInfo.Hostname)
    reporter.LogRequest("probe", 0, 0, rawReq)

    resp, err := pctx.Client.SendRaw(ctx, pctx.Target, rawReq)
    if err != nil {
        pctx.Log.Error("请求失败: %v", err)
        return nil, nil
    }

    reporter.LogResponse("probe", 0, 0, resp.StatusCode, resp.Body, resp.Raw, resp.Time)

    // 步骤 2: 判断是否命中
    matched := resp.StatusCode == 200
    evidence := fmt.Sprintf("status=%d", resp.StatusCode)
    reporter.LogMatch("probe", 0, 0, matched, "or", []string{"status"}, evidence)

    if matched {
        return &types.Result{
            TemplateID:  p.Meta().ID,
            Name:        p.Meta().Name,
            Severity:    p.Meta().Severity,
            Target:      pctx.Target,
            Evidence:    evidence,
            RawRequest:  rawReq,
            RawResponse: resp.Raw,
        }, nil
    }

    return nil, nil
}

// NeedsOOB 是否需要 OOB 验证
func (p *MyPlugin) NeedsOOB() bool {
    return false
}
```

---

## 附录 C：现有插件参考

| 插件包 | ID | 说明 | 关键技巧 |
|--------|----|------|----------|
| `cve_2022_22947` | CVE-2022-22947-go | Spring Cloud Gateway SpEL RCE | 多步骤工作流、Reporter 使用 |
| `cve_2022_22963` | CVE-2022-22963-go | Spring Cloud Function SpEL OOB | OOBHandle 渐进式验证 |
| `jwt_secret_bruteforce` | jwt-weak-secret-bruteforce | JWT 弱密钥爆破 | 并发 worker pool、密码学 |
| `api_endpoint_discovery` | api-endpoint-discovery | API 端点发现 | Fingerprint 预过滤、批量探测 |

详细代码请参考 `plugins/` 目录下各插件包源码。

---

*文档版本 v1.3.1 — 2026-08-17*
