# gosleek YAML 模板编写手册（进阶篇）

> 版本：v1.5.2
> 最后更新：2026-08-21
> 目标读者：漏洞研究员、安全工程师、渗透测试人员
> 前置知识：了解 HTTP 协议基础、YAML 语法基础；建议先阅读 `gosleek-yaml-template-guide.md`

---

## 目录

1. [执行模型：HTTP 是并行还是顺序？](#1-执行模型http-是并行还是顺序)
2. [Workflow 机制详解](#2-workflow-机制详解)
3. [Probe 字段详解](#3-probe-字段详解)
4. [Run-If 条件执行详解](#4-run-if-条件执行详解)
5. [Range 循环详解](#5-range-循环详解)
6. [变量与占位符系统](#6-变量与占位符系统)
7. [Wordlist 字典爆破](#7-wordlist-字典爆破)
8. [body-type 表单请求体自动构造](#8-body-type表单请求体自动构造)
9. [DSL 表达式完全指南](#9-dsl-表达式完全指南)
10. [匹配器 Matcher 完全指南](#10-matcher-完全指南)
11. [提取器 Extractor 完全指南](#11-extractor-完全指南)
12. [OOB 带外验证](#12-oob-带外验证)
13. [完整模板编写最佳实践](#13-完整模板编写最佳实践)
14. [调试技巧](#14-调试技巧)
15. [常见问题排查](#15-常见问题排查)
16. [高级特性与隐藏功能](#16-高级特性与隐藏功能)
17. [附录：模板结构速查表](#附录模板结构速查表)

## 1. 执行模型：HTTP 是并行还是顺序？

### 1.1 核心结论

**在单个模板内部，HTTP 请求是严格顺序执行的。**

gosleek 的并发模型是**模板级并行、请求级串行**：

```
┌─────────────────────────────────────────────────────────────────┐
│                        并发模型                                 │
│                                                                 │
│  模板 A vs 目标 X  ──┐                                          │
│  模板 B vs 目标 X  ──┤  ← 25 个 worker goroutine 并行处理       │
│  模板 C vs 目标 X  ──┤    （config.yaml: concurrency: 25）      │
│  模板 A vs 目标 Y  ──┤                                          │
│  ...                  │                                          │
│                       │                                          │
│  单个模板内:                                          │
│  HTTP[0] → HTTP[1] → HTTP[2]  （严格顺序）                      │
│                                                                 │
│  同一模板内 range 循环:                                         │
│  req@value1 → req@value2 → req@value3  （严格顺序）             │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 代码证据

在 `internal/engine/engine.go` 的 `executeHTTP` 方法中（第 545 行）：

```go
// executeHTTP 对模板的所有 HTTP 请求块进行顺序执行
func (s *Scanner) executeHTTP(ctx context.Context, tmpl *types.Template, target string, eng *placeholder.Engine) *types.Result {
    for i, req := range tmpl.HTTP {   // ← for 循环，不是 goroutine
        // ... 发送请求
        s.sendRequest(ctx, tmpl, i, rawReq, ...)
    }
}
```

在 `internal/workflow/workflow.go` 的 `Execute` 方法中（第 70 行）：

```go
// Execute 按拓扑排序顺序执行 workflow 步骤
for _, stepName := range order {  // ← for 循环，不是 goroutine
    // ... 执行每个步骤的 HTTP 请求
    e.executeHTTPBlocks(ctx, step.HTTP, target, eng, stepIdx, step.Name)
}
```

**关键事实**：
1. 同一模板的多个 HTTP 请求块（`tmpl.HTTP` 数组）是**按数组顺序依次发送**的
2. 同一请求块内的 `range` 循环也是**依次执行**的
3. 同一请求块内的 `path` 列表也是**依次发送**的
4. 只有**不同模板**（不同 `Job`）之间才会并行

### 1.3 为什么这样设计？

| 原因 | 说明 |
|------|------|
| **变量依赖** | 后续请求可能依赖前一个请求的提取器结果（如 CSRF token、JWT token） |
| **状态一致性** | 会话 Cookie、登录状态需要在请求间保持 |
| **匹配逻辑** | `matchers-condition: and` 需要所有请求都匹配才能判定漏洞存在 |
| **资源控制** | 顺序执行配合全局 `rate-limit`（默认 150 req/s）可精确控制速率 |

### 1.4 并发的实际效果

```
时间轴：
Worker-1: [模板A→目标X] → [模板B→目标X] → [模板C→目标X]
Worker-2: [模板A→目标Y] → [模板B→目标Y] → [模板C→目标Y]
Worker-3: [模板D→目标X] → [模板E→目标X] → [模板F→目标X]
Worker-4: [模板D→目标Y] → [模板E→目标Y] → [模板F→目标Y]
...

模板A内部:
  HTTP[0] → HTTP[1] → HTTP[2]  （同一 worker 上串行）
```

**限流机制**：每个 host 有独立的 token bucket 限流器（`internal/ratelimit/limiter.go`），默认 150 req/s。即使 25 个 worker 同时工作，同一 host 的请求也会被限速。

### 1.5 实际影响

| 场景 | HTTP 模式 | Workflow 模式 |
|------|-----------|---------------|
| 提取 CSRF token 后使用 | 无法实现（无步骤间状态传递） | ✅ 步骤1提取，步骤2使用 |
| 多步认证绕过 | 无法实现 | ✅ 步骤1登录，步骤2验证 |
| 单次请求检测 | ✅ 简单高效 | 可但没必要 |
| OOB 无回显检测 | ❌ 不支持 | ✅ 步骤1触发，步骤2验证回调 |
| 多参数暴力枚举 | ✅ range 循环即可 | 可但没必要 |
| 需要等待回调 | ❌ 不支持 | ✅ delay 字段 |

---

## 2. Workflow 机制详解

### 2.1 什么是 Workflow

Workflow 是多步骤检测模式，每个步骤（`WorkflowStep`）包含一个或多个 HTTP 请求，步骤之间通过 `requires` 建立依赖关系。

```
┌────────────────────────────────────────────────────────────┐
│                    Workflow 执行流程                         │
│                                                            │
│  1. 拓扑排序（Kahn 算法）                                    │
│     step1 (no requires) → step2 (requires: [step1])        │
│                          → step3 (requires: [step1])        │
│                                    → step4 (requires: [step2,step3])
│
│  2. 按排序顺序依次执行每个步骤                                │
│     - 每个步骤执行其 HTTP 请求块                              │
│     - 每个请求块的结果通过 matchers-condition 聚合            │
│     - 提取器结果保存在 engine 中，供后续步骤使用               │
│
│  3. 整体判定：所有步骤的 HTTP 结果按 AND 聚合                  │
│     （任何一个步骤的任意请求匹配 = 该步骤匹配）                │
│     所有步骤都匹配 = 模板命中                                 │
└────────────────────────────────────────────────────────────┘
```

### 2.3 Workflow 完整结构

```yaml
id: my-workflow-template
name: "My Workflow Template"
severity: "high"
tags: [workflow, example]
description: "Workflow 模板示例"

workflow:
  # 步骤 1：无依赖，最先执行
  - name: "step1-name"
    # requires: []          # 无前置依赖
    # delay: 0              # 无延迟
    # provider: ""          # 使用全局 OOB provider
    http:
      - raw: |
          GET /api/login HTTP/1.1
          Host: {{Hostname}}
        matchers:
          - type: status
            status: [200]
        extractors:
          - name: "csrf_token"
            type: "regex"
            part: "body"
            regex: ['name="csrf_token"\s+value="([^"]+)"']
            group: 1

  # 步骤 2：依赖步骤 1
  - name: "step2-name"
    requires: ["step1-name"]
    http:
      - raw: |
          POST /api/action HTTP/1.1
          Host: {{Hostname}}
          X-CSRF-Token: {{csrf_token}}
        matchers:
          - type: status
            status: [200]
          - type: word
            words: ["success"]
            part: "body"
        matchers-condition: "and"

  # 步骤 3：依赖步骤 1，可并行执行（与步骤 2 无依赖关系）
  - name: "step3-name"
    requires: ["step1-name"]
    http:
      - raw: |
          GET /api/profile HTTP/1.1
          Host: {{Hostname}}
        matchers:
          - type: status
            status: [200]
```

### 2.4 requires 依赖关系规则

```yaml
# 正确：无循环依赖
workflow:
  - name: "a"          # 首先执行
  - name: "b"          # 等待 a
    requires: ["a"]
  - name: "c"          # 等待 a 和 b
    requires: ["a", "b"]

# 错误：循环依赖
workflow:
  - name: "a"
    requires: ["b"]    # ← 循环！
  - name: "b"
    requires: ["a"]    # ← 循环！
```

**规则**：
- 无 `requires` 的步骤最先执行（入度为 0）
- 有 `requires` 的步骤等待所有前置步骤完成后执行
- 同一依赖层级的步骤按模板中定义顺序执行（非并行）
- 循环依赖会报错：`circular dependency detected in workflow`

### 2.5 Workflow 与 HTTP 模式对比

| 特性 | HTTP 模式 | Workflow 模式 |
|------|-----------|---------------|
| 请求执行顺序 | 顺序 | 按拓扑排序顺序 |
| 步骤间状态传递 | ❌ | ✅ 提取器变量 |
| 步骤间依赖 | ❌ | ✅ requires |
| 步骤间延迟 | ❌ | ✅ delay |
| 步骤级 OOB provider | ❌ | ✅ provider |
| 复杂度 | 简单 | 复杂 |
| 适用场景 | 单步检测 | 多步检测、OOB |

**选择建议**：
- 如果检测逻辑只需要 1-2 个请求，且不需要步骤间变量传递 → 用 `http`
- 如果需要提取 token 后在后续请求中使用 → 用 `workflow`

---

## 3. Probe 字段详解

`probe` 字段是一个**请求级控制标志**，用于区分"探测请求"和"验证请求"。

```yaml
http:
  - raw: |
      GET /api/login HTTP/1.1
      Host: {{Hostname}}
    probe: true              # ← 探测模式
    extractors:
      - name: "csrf_token"
        type: "regex"
        regex: ['name="csrf"\s+value="([^"]+)"']
    matchers:
      - type: status
        status: [200]
```

### 3.2 Probe 的工作原理

```
┌─────────────────────────────────────────────────────────────────┐
│                     Probe 执行流程                               │
│                                                                 │
│  1. 发送 HTTP 请求                                               │
│  2. 执行 Extractors → 提取变量（正常执行）                        │
│  3. 执行 Matchers → 判断匹配（正常执行）                          │
│  4. 结果标记为 "probe"                                           │
│     - 提取器结果仍然生效，保存到 engine 中                        │
│     - Matcher 结果不计入最终判定                                 │
│     - 不会添加到 reqResults 数组                                 │
│  5. 最终判定：只统计非 probe 请求的 Matcher 结果                   │
│                                                                 │
│  代码位置: engine.go:774                                          │
│  if countResult {                                                │
│      *reqResults = append(*reqResults, matched)  // probe=false  │
│  }                                                               │
│  // countResult=false (probe=true): 不收集 evidence               │
└─────────────────────────────────────────────────────────────────┘
```

### 3.3 Probe 的典型使用场景

#### 场景 1：探测 + 验证分离

```yaml
http:
  # 步骤 1：探测页面是否存在，提取 CSRF token
  - raw: |
      GET /api/settings HTTP/1.1
      Host: {{Hostname}}
    probe: true
    extractors:
      - name: "csrf_token"
        type: "regex"
        regex: ['name="csrf_token"\s+value="([^"]+)"']
    matchers:
      - type: status
        status: [200]

  # 步骤 2：使用提取的 token 发送实际检测请求
  - raw: |
      POST /api/settings HTTP/1.1
      Host: {{Hostname}}
      Content-Type: application/json
      X-CSRF-Token: {{csrf_token}}

      {"setting": "test"}
    matchers:
      - type: status
        status: [200, 201, 204]
```

**原理**：步骤 1 是探针，用于获取 CSRF token 并提取到变量。如果步骤 1 匹配成功，token 被保存。步骤 2 使用 token 发送请求，其匹配结果才决定最终判定。

#### 场景 2：指纹探测 + 漏洞验证

```yaml
http:
  # 探测 WebLogic 管理控制台
  - raw: |
      GET /console/framework/skins/wlsstyles.jsp HTTP/1.1
      Host: {{Hostname}}
    probe: true
    matchers:
      - type: word
        words: ["WebLogic"]
        part: "body"

  # 实际漏洞检测（探针结果不影响判定）
  - raw: |
      POST /console/framework/internal/invoker HTTP/1.1
      Host: {{Hostname}}
      Content-Type: text/plain

      com.sun.rowset.JdbcRowSetImpl
    matchers:
      - type: word
        words: ["javax.naming"]
        part: "body"
    matchers-condition: "and"
```

#### 场景 3：Workflow 中的探针步骤

```yaml
workflow:
  # 步骤 1：探针 - 提取 token，不用于判定
  - name: "probe-token"
    http:
      - raw: |
          GET /api/login HTTP/1.1
          Host: {{Hostname}}
        probe: true
        extractors:
          - name: "jwt_token"
            type: "regex"
            regex: ['"token":\s*"([^"]+)"']
        matchers:
          - type: status
            status: [200]

  # 步骤 2：实际检测 - 使用 token 进行认证绕过测试
  - name: "test-bypass"
    requires: ["probe-token"]
    http:
      - raw: |
          GET /api/admin HTTP/1.1
          Host: {{Hostname}}
          Authorization: Bearer {{jwt_token}}
        matchers:
          - type: status
            status: [200]
          - type: word
            words: ["admin", "dashboard"]
            part: "body"
        matchers-condition: "and"
```

### 3.4 Probe 的注意事项

| 特性 | 说明 |
|------|------|
| 提取器 | ✅ probe=true 时仍然执行，变量可被后续请求使用 |
| Matcher | ✅ probe=true 时仍然执行匹配，但结果不影响最终判定 |
| Evidence | ❌ probe 请求的匹配结果不会出现在最终证据中 |
| 日志 | probe 请求正常记录请求/响应日志 |
| 性能 | 无额外性能开销 |

**常见错误**：
```yaml
# ❌ 错误：probe 请求没有 extractors，后续步骤无法使用变量
- raw: |...
  probe: true
  matchers:
    - type: status
      status: [200]
  # 缺少 extractors！

# ✅ 正确：probe 请求必须有 extractors 才能传递变量
- raw: |...
  probe: true
  extractors:
    - name: "token"
      type: "regex"
      regex: ['"token":"([^"]+)"']
  matchers:
    - type: status
      status: [200]
```

---

## 4. Run-If 条件执行详解

`run-if` 是一个**请求级条件执行标志**，用于根据前置条件决定是否发送该请求。

```yaml
http:
  - raw: |
      POST /api/attack HTTP/1.1
      Host: {{Hostname}}
    run-if: "len(csrf_token) > 0"    # ← 只有 csrf_token 存在时才执行
```

### 4.2 Run-If 的执行时机

```
┌─────────────────────────────────────────────────────────────────┐
│                  Run-If 执行流程                                 │
│                                                                 │
│  在发送请求之前评估条件：                                         │
│                                                                 │
│  1. 检查 run-if 表达式                                          │
│  2. 如果是 DSL 表达式（包含 == != > < && || 等）：                │
│     - 使用 matcher.EvalDSL() 评估                               │
│     - 变量来源：extracted map（前置请求的提取器结果）             │
│  3. 如果是简单字符串：                                           │
│     - 替换占位符（{{var}} → 实际值）                             │
│     - 检查是否非空、非 "false"、非 "0"                           │
│     - 如果结果仍包含 {{...}}，说明依赖变量不存在 → false         │
│  4. 条件为 false → 跳过该请求（continue）                        │
│  5. 条件为 true → 正常发送请求                                    │
│                                                                 │
│  代码位置: engine.go:555-559                                      │
│  if req.RunIf != "" {                                            │
│      if !evalRunIf(req.RunIf, allExtracted, eng) {              │
│          continue  // 跳过此请求                                  │
│      }                                                           │
│  }                                                               │
└─────────────────────────────────────────────────────────────────┘
```

### 4.3 DSL 表达式语法

```yaml
# 基础语法
run-if: "len(token) > 0"
run-if: "status_code == 200"
run-if: "contains(body, 'admin')"
run-if: "!contains(body, 'error')"
run-if: "len(token) > 0 && contains(body, 'success')"
run-if: "len(csrf_token) > 0 || len(auth_token) > 0"

# 支持的变量
run-if: "status_code == 200"     # 当前响应状态码
run-if: "contains(body, 'xss')"  # body = 当前响应体
run-if: "len(token) > 0"         # token = 前置提取器变量
run-if: "content_length > 100"   # 响应体大小
```

**可用的 DSL 变量**：

| 变量名 | 含义 | 来源 |
|--------|------|------|
| `status_code` | 当前响应状态码 | 当前请求响应 |
| `body` | 当前响应体 | 当前请求响应 |
| `header` | 当前响应头 | 当前请求响应 |
| `all` | 响应头 + 响应体 | 当前请求响应 |
| `response_time` | 响应时间（秒） | 当前请求响应 |
| `content_length` | 响应体大小（字节） | 当前请求响应 |
| `any_extractor_name` | 前置提取器变量 | 前置请求的 extractors |

**可用的 DSL 函数**：

| 函数 | 说明 | 示例 |
|------|------|------|
| `contains(var, 'str')` | 子串匹配 | `contains(body, 'admin')` |
| `contains_any(var, 'w1', 'w2')` | 任一子串匹配 | `contains_any(body, 'admin', 'root')` |
| `contains_all(var, 'w1', 'w2')` | 全部子串匹配 | `contains_all(body, 'admin', 'panel')` |
| `equals(var, 'val')` | 精确相等 | `equals(status_code, '200')` |
| `regex(var, 'pattern')` | 正则匹配 | `regex(body, 'CVE-\d+-\d+')` |
| `starts_with(var, 'prefix')` | 前缀匹配 | `starts_with(body, 'HTTP/')` |
| `ends_with(var, 'suffix')` | 后缀匹配 | `ends_with(header, 'PHP/')` |
| `len(var)` | 长度 > 0 | `len(token)` 或 `len(body) > 100` |
| `to_lower_contains(var, 'word')` | 忽略大小写包含 | `to_lower_contains(body, 'admin')` |

### 4.4 Run-If 的典型使用场景

#### 场景 1：仅当提取到变量时才执行后续请求

```yaml
workflow:
  - name: "extract-token"
    http:
      - raw: |
          GET /api/login HTTP/1.1
          Host: {{Hostname}}
        extractors:
          - name: "csrf_token"
            type: "regex"
            regex: ['name="csrf"\s+value="([^"]+)"']
        matchers:
          - type: status
            status: [200]

  - name: "test-with-token"
    requires: ["extract-token"]
    http:
      - raw: |
          POST /api/submit HTTP/1.1
          Host: {{Hostname}}
          X-CSRF-Token: {{csrf_token}}
        run-if: "len(csrf_token) > 0"    # 只有提取到 token 才发送
        matchers:
          - type: status
            status: [200]
```

#### 场景 2：条件跳过整个请求块

```yaml
http:
  - raw: |
      POST /api/admin HTTP/1.1
      Host: {{Hostname}}
    run-if: "len(jwt_token) > 0"    # 没有 JWT token 则跳过
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["admin", "dashboard"]
        part: "body"
    matchers-condition: "and"
```

#### 场景 3：复杂条件判断

```yaml
http:
  - raw: |
      POST /api/exploit HTTP/1.1
      Host: {{Hostname}}
    run-if: "len(token) > 0 && contains(body, 'success')"
    matchers:
      - type: status
        status: [200]
```

### 4.5 Run-If 与 Probe 的区别

| 特性 | Probe | Run-If |
|------|-------|--------|
| 请求是否发送 | ✅ 发送 | ❌ 条件为 false 时不发送 |
| 提取器是否执行 | ✅ 执行 | N/A（请求不发送） |
| Matcher 是否执行 | ✅ 执行（但不计入判定） | N/A（请求不发送） |
| 用途 | 探测 + 提取 | 条件跳过 |
| 典型场景 | 获取 token 后用于后续请求 | 依赖前置变量才执行 |

**组合使用示例**：

```yaml
workflow:
  - name: "probe-login"
    http:
      - raw: |
          GET /api/login HTTP/1.1
          Host: {{Hostname}}
        probe: true                    # 不用于判定
        extractors:
          - name: "csrf_token"
            type: "regex"
            regex: ['name="csrf"\s+value="([^"]+)"']
        matchers:
          - type: status
            status: [200]

  - name: "test-exploit"
    requires: ["probe-login"]
    http:
      - raw: |
          POST /api/submit HTTP/1.1
          Host: {{Hostname}}
          X-CSRF-Token: {{csrf_token}}
        run-if: "len(csrf_token) > 0"  # 条件为 false 时跳过
        matchers:
          - type: status
            status: [200]
          - type: word
            words: ["success"]
            part: "body"
        matchers-condition: "and"
```

---

## 5. Range 循环详解

### 5.1 核心概念

`range` 用于对一个请求模板进行多次迭代，每次替换不同的值。

```yaml
http:
  - raw: |
      GET /search?q={{keyword}} HTTP/1.1
      Host: {{Hostname}}
    range:
      key: "keyword"
      values:
        - "admin"
        - "test"
        - "1' OR '1'='1"
        - "<script>alert(1)</script>"
```

### 5.2 执行流程

```
┌─────────────────────────────────────────────────────────────────┐
│                    Range 执行流程                                │
│                                                                 │
│  原始请求:                                                      │
│  GET /search?q={{keyword}} HTTP/1.1                             │
│  Host: {{Hostname}}                                             │
│                                                                 │
│  迭代 1: keyword = "admin"                                       │
│  → GET /search?q=admin HTTP/1.1                                 │
│  → 发送请求 → 匹配 → 提取                                        │
│                                                                 │
│  迭代 2: keyword = "test"                                        │
│  → GET /search?q=test HTTP/1.1                                  │
│  → 发送请求 → 匹配 → 提取                                        │
│                                                                 │
│  迭代 3: keyword = "1' OR '1'='1"                               │
│  → GET /search?q=1'%20OR%20'1'='1 HTTP/1.1                      │
│  → 发送请求 → 匹配 → 提取                                        │
│                                                                 │
│  结果聚合: 所有迭代的 matcher 结果按 matchers-condition 聚合      │
└─────────────────────────────────────────────────────────────────┘
```

### 5.3 Range 与 Extractors 的配合

```yaml
http:
  - raw: |
      GET /api/users?id={{user_id}} HTTP/1.1
      Host: {{Hostname}}
    range:
      key: "user_id"
      values:
        - "1"
        - "2"
        - "3"
    extractors:
      - name: "user_name"
        type: "json"
        json: ["data.name"]
    matchers:
      - type: dsl
        dsl:
          - "status_code == 200"
          - "len(user_name) > 0"
```

**注意**：每次迭代的提取器结果是独立的，后续迭代可以引用前序迭代提取的变量。

### 5.4 Range 的典型使用场景

#### 场景 1：多参数探测

```yaml
http:
  - raw: |
      GET /api/search?{{param}}={{payload}} HTTP/1.1
      Host: {{Hostname}}
    range:
      key: "param"
      values:
        - "q"
        - "search"
        - "keyword"
        - "query"
        - "name"
        - "username"
        - "email"
        - "comment"
      key: "payload"
      values:
        - "<script>alert(1)</script>"
        - "<img src=x onerror=alert(1)>"
        - "<svg onload=alert(1)>"
```

#### 场景 2：多方法测试

```yaml
http:
  - raw: |
      {{method}} /api/admin HTTP/1.1
      Host: {{Hostname}}
    range:
      key: "method"
      values:
        - "GET"
        - "POST"
        - "PUT"
        - "DELETE"
        - "PATCH"
        - "OPTIONS"
        - "HEAD"
    matchers:
      - type: dsl
        dsl:
          - "status_code != 404"
          - "status_code != 405"
```

#### 场景 3：路径遍历

```yaml
http:
  - raw: |
      GET /api/files?path={{payload}} HTTP/1.1
      Host: {{Hostname}}
    range:
      key: "payload"
      values:
        - "../../etc/passwd"
        - "../../../etc/shadow"
        - "....//....//etc/passwd"
        - "%2e%2e/%2e%2e/etc/passwd"
        - "..%2f..%2fetc%2fpasswd"
```

---

## 6. 变量与占位符系统

### 6.1 内置占位符

| 占位符 | 说明 | 示例 |
|--------|------|------|
| `{{Hostname}}` | 目标主机（含端口） | `192.168.1.1:8080` |
| `{{baseURL}}` | 完整基础 URL | `http://192.168.1.1:8080` |
| `{{Host}}` | 同 Hostname | `192.168.1.1:8080` |
| `{{Port}}` | 端口号 | `8080` |
| `{{Scheme}}` | 协议 | `http` |
| `{{Path}}` | 路径 | `/api/v1` |
| `{{oob}}` | OOB 回连地址 | `gs-a1b2c3d4.ceye.io` |
| `{{oob_label}}` | OOB 唯一标签 | `gs-a1b2c3d4` |
| `{{oob_token}}` | OOB 凭据 | ceye token / dnslog cookie |
| `{{oob_domain}}` | OOB 域名 | `ceye.io` |
| `{{interactsh-url}}` | 同 {{oob}} | - |

### 6.2 用户变量

```yaml
variables:
  admin_path: "/admin"
  route_id: "{{rand_text_alpha(8)}}"
  test_user: "admin"
  test_pass: "admin123"
```

变量可以在请求中通过 `{{变量名}}` 引用。

### 6.3 提取器变量

```yaml
http:
  - raw: |
      POST /api/login HTTP/1.1
      Host: {{Hostname}}
    extractors:
      - name: "jwt_token"
        type: "regex"
        regex: ['"token":\s*"([^"]+)"']
        group: 1
```

提取的变量可通过 `{{jwt_token}}` 在后续请求中引用。

### 6.4 内置函数

| 函数 | 说明 | 示例 |
|------|------|------|
| `rand_int(min, max)` | 随机整数 | `{{rand_int(1, 100)}}` |
| `rand_text_alpha(n)` | 随机字母 | `{{rand_text_alpha(8)}}` |
| `rand_text_hex(n)` | 随机十六进制 | `{{rand_text_hex(16)}}` |
| `rand_text_numeric(n)` | 随机数字 | `{{rand_text_numeric(8)}}` |
| `randstr` | 随机字符串（默认 8 位） | `{{randstr}}` |
| `uuid` | 随机 UUID | `{{uuid}}` |
| `timestamp` | 当前时间戳 | `{{timestamp}}` |
| `date(format)` | 格式化日期 | `{{date("2006-01-02")}}` |
| `md5(str)` | MD5 哈希 | `{{md5("test")}}` |
| `sha1(str)` | SHA1 哈希 | `{{sha1("test")}}` |
| `sha256(str)` | SHA256 哈希 | `{{sha256("test")}}` |
| `base64_encode(str)` | Base64 编码 | `{{base64_encode("test")}}` |
| `base64_decode(str)` | Base64 解码 | `{{base64_decode("dGVzdA==")}}` |
| `url_encode(str)` | URL 编码 | `{{url_encode("a b")}}` |
| `url_decode(str)` | URL 解码 | `{{url_decode("a%20b")}}` |
| `hex_encode(str)` | Hex 编码 | `{{hex_encode("test")}}` |
| `hex_decode(str)` | Hex 解码 | `{{hex_decode("74657374")}}` |
| `to_upper(str)` | 转大写 | `{{to_upper("test")}}` |
| `to_lower(str)` | 转小写 | `{{to_lower("TEST")}}` |
| `trim(str)` | 去空格 | `{{trim(" test ")}}` |
| `reverse(str)` | 反转字符串 | `{{reverse("test")}}` |
| `concat(str1, str2)` | 拼接字符串 | `{{concat("a", "b")}}` |
| `repeat(str, n)` | 重复字符串 | `{{repeat("a", 5)}}` |

### 6.5 变量优先级

## 7. Wordlist 字典爆破

### 7.1 基本用法

```yaml
http:
  - raw: |
      POST /api/login HTTP/1.1
      Host: {{Hostname}}
      Content-Type: application/json

      {"username":"admin","password":"{{password}}"}
    wordlist:
      - key: "password"
        path: "wordlists/passwords.txt"
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["success", "welcome"]
        part: "body"
    matchers-condition: "and"
```

### 7.2 多字典组合（笛卡尔积）

```yaml
http:
  - raw: |
      POST /api/login HTTP/1.1
      Host: {{Hostname}}
      Content-Type: application/json

      {"username":"{{username}}","password":"{{password}}"}
    wordlist:
      - key: "username"
        path: "wordlists/usernames.txt"
      - key: "password"
        path: "wordlists/passwords.txt"
    matchers:
      - type: status
        status: [200]
```

**注意**：笛卡尔积有上限（`max-cartesian-products` 配置，默认 10000），超限会跳过。

### 7.3 编码支持

```yaml
wordlist:
  - key: "payload"
    path: "wordlists/ payloads.txt"
    encoding: "url"       # URL 编码
    # 或 "base64" / "hex"
```

---

## 8. body-type：表单请求体自动构造

使用 `path` + `body-type` 时，引擎会根据 `body-type` 自动构造请求体及 `Content-Type` 头，无需手动编写完整的 HTTP 请求文本。

### 8.1 form（application/x-www-form-urlencoded）

```yaml
http:
  - method: "POST"
    path:
      - "/api/login"
    body-type: "form"
    body: |
      username=admin
      password={{password}}
    wordlist:
      - key: "password"
        path: "wordlists/passwords.txt"
    matchers:
      - type: word
        words: ["success", "welcome"]
        part: "body"
```

`body-type: form` 会将 `body` 字段直接作为 URL 编码的请求体附加，并自动设置 `Content-Type: application/x-www-form-urlencoded`。

### 8.2 multipart（multipart/form-data）

```yaml
http:
  - method: "POST"
    path:
      - "/api/upload"
    body-type: "multipart"
    body: |
      username=admin
      avatar=content_of_avatar_file
      description=A test upload
    matchers:
      - type: status
        status: [200]
```

`body-type: multipart` 会将 `body` 中每行 `key=value` 解析为表单字段，自动生成随机 boundary 和标准的 multipart body。

### 8.3 注意事项

- `body` 中每行必须是 `key=value` 格式，空行和 `#` 开头的注释行会被跳过

---

## 9. DSL 表达式完全指南
### 9.1 基本语法

```
status_code == 200
status_code != 404
len(body) > 100
contains(body, 'admin')
!contains(body, 'error')
status_code == 200 && contains(body, 'admin')
len(token) > 0 || status_code == 403
```

### 9.2 运算符优先级

```
! (取反) > && (与) > \|\| (或)
== != > < > <= >=
```

### 9.3 完整示例

```yaml
matchers:
  - type: dsl
    dsl:
      - "status_code == 200"
      - "contains(body, 'vulnerable')"
      - "!contains(body, 'error')"
matchers-condition: "and"
```

---

## 10. 匹配器 Matcher 完全指南

| 类型 | 用途 | 关键参数 |
|------|------|----------|
| `status` | 状态码匹配 | `status: [200, 500]` |
| `word` | 文本子串匹配 | `words: ["admin"]`, `part: body` |
| `regex` | 正则匹配 | `regex: ["CVE-\\d+-\\d+"]` |
| `header` | 响应头匹配 | `header: ["X-Powered-By: PHP"]` |
| `size` | 响应体大小 | `size: [">1000", "<50000"]` |
| `time` | 响应时间 | `time: ">=5"` |
| `binary` | 二进制匹配 | `binary: ["d0cf11"]` |
| `dsl` | DSL 表达式 | `dsl: ["status_code == 200"]` |
| `json-word` | JSON 字段匹配 | `json-path: data`, `json-field: name` |
| `json-2darray` | JSON 二维数组 | `json-2darray-column: 0` |

### 10.2 通用字段

```yaml
- type: "word"
  part: "body"              # body/header/all
  condition: "or"           # or/and
  negative: false           # 取反
  encoding: ""              # url/base64/hex
  case-insensitive: false   # 大小写不敏感
```

---

## 11. 提取器 Extractor 完全指南
### 11.1 类型总览

| 类型 | 用途 | 关键参数 |
|------|------|----------|
| `regex` | 正则提取 | `regex: [...]`, `group: 1` |
| `word` | 关键词提取 | `words: ["SESSIONID="]` |
| `kval` | 键值提取 | `kval: ["session"]` |
| `json` | JSON 路径提取 | `json: ["data.token"]` |
| `cookie` | Cookie 提取 | `name: "sessionid"` |
| `xpath` | XPath 提取 | `xpath: ['//input/@value']` |
| `css` | CSS 选择器提取 | `css: [".class"]` |

### 11.2 kval 键值提取详解

从响应头或 body 中提取指定键名的值。`kval` 提取器会搜索响应中的所有头信息（包括 `Set-Cookie` 头），找到第一个匹配的键名并返回其值。

```yaml
extractors:
  - name: "x_powered_by"
    type: "kval"
    kval: ["X-Powered-By"]    # 支持多个键名，依次查找

  - name: "server"
    type: "kval"
    kval: ["Server", "X-Server"]
```

**工作原理**：
1. 解析响应头（含 Set-Cookie 头）为键值对 map
2. 遍历 `kval` 列表中的每个键名
3. 找到第一个匹配项（不区分大小写）
4. 返回该键的第一个值

**适用场景**：
- 从响应头中提取特定字段（如 `Server`、`X-Powered-By`）
- 不需要正则表达式的简单提取
- 需要从 Set-Cookie 头中提取 cookie 值但不想使用 `cookie` 类型

### 11.3 cookie Cookie 提取详解

从 `Set-Cookie` 响应头中提取指定 cookie 的值。

```yaml
extractors:
  - name: "sessionid"
    type: "cookie"
    # name 字段即为要提取的 cookie 名称

  - name: "auth_token"
    type: "cookie"
```

**工作原理**：
1. 遍历所有 `Set-Cookie` 响应头
2. 提取 `key=value` 部分（忽略 `; expires`, `; path` 等属性）
3. 不区分大小写匹配 cookie 名称
4. 返回匹配的 cookie 值

**与 kval 的区别**：
- `cookie` 类型专门处理 `Set-Cookie` 头，自动解析 `key=value` 格式
- `kval` 类型会搜索所有响应头，包括 `Set-Cookie`，但需要指定完整的头名称

### 11.4 提取器变量传递

```yaml
workflow:
  - name: "step1"
    http:
      - raw: |...
        extractors:
          - name: "token"
            type: "regex"
            regex: ['"token":\s*"([^"]+)"']
    matchers:
      - type: status
        status: [200]

  - name: "step2"
    requires: ["step1"]
    http:
      - raw: |
          GET /api/protected HTTP/1.1
          Host: {{Hostname}}
          Authorization: Bearer {{token}}    # 引用 step1 提取的变量
        matchers:
          - type: status
            status: [200]
```

---

## 12. OOB 带外验证
### 12.1 支持的 Provider

| Provider | 配置要求 | 特点 |
|----------|----------|------|
| `ceye` | token + domain | 功能最全，支持 DNS/HTTP |
| `dnslog` | 无需配置 | 自动获取子域名 |
| `callbackred` | 无需配置 | 自动获取 key |

### 12.2 OOB 模板结构

```yaml
id: ssrf-oob-detection
name: "SSRF Detection (OOB)"
severity: critical
tags: [ssrf, oob]

workflow:
  - name: trigger
    http:
      - raw: |
          GET /api/fetch?url=http://{{oob}} HTTP/1.1
          Host: {{Hostname}}
        matchers:
          - type: status
            status: [200, 302, 500]

  - name: verify-dns
    requires: [trigger]
    delay: 5
    http:
      - raw: |
          GET /v1/records?token={{oob_token}}&type=dns HTTP/1.1
          Host: api.ceye.io
        matchers:
          - type: status
            status: [200]
          - type: json-word
            json-path: data
            json-field: name
            words: ["{{oob_label}}"]
            condition: or
```

---

## 13. 完整模板编写最佳实践
### 13.1 HTTP 模式模板

```yaml
id: simple-xss-detection
name: "Reflected XSS Detection"
severity: high
tags: [xss, injection]
description: "检测反射型 XSS 漏洞"

variables:
  payload: "<script>alert(1)</script>"

http:
  - raw: |
      GET /search?q={{payload}} HTTP/1.1
      Host: {{Hostname}}
    matchers:
      - type: dsl
        dsl:
          - "contains(body, '<script>alert(1)</script>')"
          - "contains(body, 'onerror=alert(1)')"
      - type: status
        status: [200]
    matchers-condition: "and"
```

### 13.2 Workflow 模式模板

```yaml
id: auth-bypass-workflow
name: "Authentication Bypass Workflow"
severity: critical
tags: [auth, bypass, workflow]
description: "多步骤认证绕过检测"

workflow:
  - name: "extract-token"
    http:
      - raw: |
          GET /api/login HTTP/1.1
          Host: {{Hostname}}
        extractors:
          - name: "csrf_token"
            type: "regex"
            regex: ['name="csrf_token"\s+value="([^"]+)"']
            group: 1
        matchers:
          - type: status
            status: [200]

  - name: "test-bypass"
    requires: ["extract-token"]
    http:
      - raw: |
          POST /api/admin HTTP/1.1
          Host: {{Hostname}}
          X-CSRF-Token: {{csrf_token}}
          Content-Type: application/json

          {"action": "bypass"}
        matchers:
          - type: dsl
            dsl:
              - "status_code == 200"
              - "contains(body, 'admin') || contains(body, 'dashboard')"
          - type: word
            words: ["success", "bypass"]
            part: "body"
        matchers-condition: "and"
```

### 13.3 使用 Probe + Run-If 的模板

```yaml
id: csrf-probe-and-test
name: "CSRF Token Detection and Bypass"
severity: medium
tags: [csrf, auth]

workflow:
  - name: "probe-login-page"
    http:
      - raw: |
          GET /api/login HTTP/1.1
          Host: {{Hostname}}
        probe: true
        extractors:
          - name: "csrf_token"
            type: "regex"
            regex: ['name="csrf_token"\s+value="([^"]+)"']
          - name: "csrf_meta"
            type: "regex"
            regex: ['<meta\s+name="csrf"\s+content="([^"]+)"']
        matchers:
          - type: status
            status: [200]

  - name: "test-without-token"
    requires: ["probe-login-page"]
    http:
      - raw: |
          POST /api/settings HTTP/1.1
          Host: {{Hostname}}
          Content-Type: application/json

          {"setting": "test"}
        run-if: "len(csrf_token) == 0"    # 仅在无 token 时执行
        matchers:
          - type: status
            status: [200, 201, 204]
          - type: word
            words: ["success", "updated"]
            part: "body"
        matchers-condition: "and"
```

---

## 14. 调试技巧
### 14.1 日志级别

```bash
# 默认：仅显示匹配结果
gosleek scan -t http://example.com

# -v：显示进度、跳过原因
gosleek scan -t http://example.com -v

# -vv：显示每个请求/响应详情、matcher 结果
gosleek scan -t http://example.com -vv
```

### 14.2 使用 -vv 查看执行细节

```
[INFO] task started  target=http://example.com  template=simple-xss
[INFO] HTTP request sent  template=simple-xss  req=0  method=GET  path=/search
[INFO] HTTP response received  template=simple-xss  req=0  status=200  time_ms=45  bytes=1234
[INFO] matcher PASS  template=simple-xss  req=0  types=dsl,status  evidence="dsl: matched"
[INFO] matched  target=http://example.com  template=simple-xss  severity=high
```

### 14.3 常见问题排查

| 问题 | 原因 | 解决 |
|------|------|------|
| 请求未发送 | run-if 条件为 false | 检查变量是否正确提取 |
| 提取器未生效 | extractor name 拼写错误 | 使用 -vv 查看详细日志 |
| Workflow 步骤跳过 | requires 引用不存在的步骤 | 检查步骤名称 |
| 匹配器不匹配 | part 字段设置错误 | 检查 part: body/header/all |
| OOB 验证失败 | provider 未配置 | 检查 oob.yaml 配置 |

---

## 15. 常见问题排查
### Q1: HTTP 模式的请求是并行还是顺序执行？

**答**：单个模板内的 HTTP 请求是**严格顺序执行**的。并发发生在不同模板之间（通过 worker goroutine 池）。

### Q2: Workflow 和 HTTP 模式有什么区别？

**答**：
- HTTP 模式：所有请求顺序执行，结果按 `matchers-condition` 聚合
- Workflow 模式：步骤间可通过 `requires` 建立依赖，步骤 1 提取的变量供步骤 2+ 使用

### Q3: Probe 和 Run-If 有什么区别？

**答**：
- **Probe**：请求**会发送**，提取器正常执行，但匹配结果不计入最终判定。适合"先探测再验证"的场景。
- **Run-If**：条件为 false 时请求**不发送**。适合"依赖前置变量才执行"的场景。

### Q4: 如何在 Workflow 中传递变量？

**答**：在步骤 1 中使用 extractors 提取变量，步骤 2 及后续步骤通过 `{{变量名}}` 引用。

### Q5: Range 和 Wordlist 有什么区别？

**答**：
- **Range**：在 YAML 中直接声明一组值，每次迭代替换一个占位符。适合小规模、固定值的场景。
- **Wordlist**：从外部文件读取字典，支持 URL/Base64/Hex 编码。适合大规模爆破场景。
- 两者可以组合使用，但 Range 优先于 Wordlist 执行。

### Q6: 为什么我的提取器变量在后续步骤中为空？

**答**：检查以下事项：
1. 前置步骤的 extractors 是否正确定义
2. regex 是否正确匹配响应内容
3. 使用 `-vv` 查看详细日志

### Q7: 如何调试 DSL 表达式？

**答**：使用 `-vv` 查看详细日志，DSL 表达式会显示匹配/失败状态。

### Q8: StopAtFirstMatch 在 HTTP 模式和 Workflow 模式中有何区别？

**答**：
- **HTTP 模式**：`stop-at-first-match` **完全无效**，所有请求块都会被执行
- **Workflow 模式**：两层作用域——请求级（`HTTPRequest.StopAtFirstMatch`）在步骤内命中后停止后续请求；步骤级（`WorkflowStep.StopAtFirstMatch`）在步骤失败后立即终止整个 Workflow

### Q9: 模板级 Matcher/Extractor 如何使用？

**答**：模板级 `matchers` 和 `extractors` 是所有请求块的默认值。请求级会覆盖模板级，同时保留模板级中未覆盖的部分。适用于多个请求共享相同匹配规则的模板。

### Q10: 支持哪些输出格式？

**答**：支持 6 种输出格式：
- `json`（默认）：结构化 JSON
- `txt`：纯文本
- `sarif`：SARIF 标准格式（适合 CI/CD 集成）
- `html`：HTML 报告（带图表）
- `csv`：CSV 表格
- `markdown`：Markdown 格式

### Q11: 哪些 YAML 字段是死字段（定义了但无效）？

**答**：以下字段在类型定义中存在但引擎不读取：
- `threads`（`HTTPRequest`）：定义了但从未使用，不影响任何行为

其他曾经标注为死字段的项（`rate-limit`、`name`、`internal`）已在 v1.5.1 中实现。`threads` 字段仍存在于类型定义中但引擎不读取。

### Q12: 如何让后续的 DSL matcher 使用前置请求的提取变量？

**答**：在 HTTP 模式中，`allExtracted` map 会跨请求块共享。前置请求的提取器结果会自动传递给后续请求的 DSL matcher 和 `run-if` 表达式。例如：

```yaml
http:
  - raw: |
      GET /api/login HTTP/1.1
      Host: {{Hostname}}
    extractors:
      - name: "csrf_token"
        type: "regex"
        regex: ['name="csrf"\s+value="([^"]+)"']
    matchers:
      - type: status
        status: [200]

  - raw: |
      POST /api/submit HTTP/1.1
      Host: {{Hostname}}
      X-CSRF-Token: {{csrf_token}}
    run-if: "len(csrf_token) > 0"
    matchers:
      - type: dsl
        dsl:
          - "status_code == 200"
          - "contains(body, 'success')"
```

---

## 16. 高级特性与隐藏功能
### 16.1 StopAtFirstMatch：命中即停

**重要区别**：`stop-at-first-match` 在 HTTP 模式和 Workflow 模式中的行为**完全不同**。

#### HTTP 模式：不起作用

在 `internal/engine/engine.go` 的 `executeHTTP` 方法中，**没有**对 `StopAtFirstMatch` 的任何引用。HTTP 模式下所有请求块都会被完整执行，无论是否已经命中。

```yaml
# HTTP 模式下 stop-at-first-match 无效
http:
  - raw: |
      GET /api/endpoint1 HTTP/1.1
      Host: {{Hostname}}
    stop-at-first-match: true    # ← 无效！仍然会发送后续请求
    matchers:
      - type: status
        status: [200]

  - raw: |
      GET /api/endpoint2 HTTP/1.1
      Host: {{Hostname}}
    matchers:
      - type: status
        status: [200]
```

#### Workflow 模式：两层作用域

在 `internal/workflow/workflow.go` 中，`StopAtFirstMatch` 在两个层次生效：

**层次 1：请求级**（`HTTPRequest.StopAtFirstMatch`）

```go
// workflow.go:376
if req.StopAtFirstMatch && matched {
    break  // 跳出当前步骤内的请求循环
}
```

同一个 Workflow 步骤内的多个 HTTP 请求块，第一个命中后停止发送后续请求。

**层次 2：步骤级**（`WorkflowStep.StopAtFirstMatch`）

```go
// workflow.go:161
if !stepMatched {
    allMatched = false
    if step.StopAtFirstMatch {
        break  // 跳出步骤循环，停止执行后续步骤
    }
}
```

某个步骤匹配失败后，如果设置了 `stop-at-first-match: true`，则立即终止整个 Workflow，不再执行后续步骤。

#### 典型使用场景

```yaml
workflow:
  # 步骤 1：快速探测
  - name: "probe"
    http:
      - raw: |
          GET /api/health HTTP/1.1
          Host: {{Hostname}}
        matchers:
          - type: status
            status: [200]

  # 步骤 2：深度检测（仅在步骤 1 成功后执行）
  - name: "deep-test"
    requires: ["probe"]
    stop-at-first-match: true    # 任何请求命中即停止，不再发送后续请求
    http:
      - raw: |
          POST /api/exploit HTTP/1.1
          Host: {{Hostname}}
        matchers:
          - type: word
            words: ["vulnerable"]
            part: "body"

      - raw: |
          POST /api/exploit2 HTTP/1.1
          Host: {{Hostname}}
        matchers:
          - type: word
            words: ["exploit"]
            part: "body"
```

### 16.2 Redirects 重定向控制

> **注意**：YAML 字段名是 `redirects`（全小写），不是 `rRedirects`。

#### 全局配置

```bash
# 默认：跟随重定向（最多 MaxRedirects 次）
gosleek scan -t http://example.com

# 不跟随重定向
gosleek scan -t http://example.com --follow-redirects=false
```

#### 请求级覆盖

```yaml
http:
  - raw: |
      GET /api/login HTTP/1.1
      Host: {{Hostname}}
    redirects: false          # 此请求不跟随重定向
    matchers:
      - type: status
        status: [301, 302]    # 期望收到重定向

  - raw: |
      GET /api/protected HTTP/1.1
      Host: {{Hostname}}
    redirects: true           # 此请求跟随重定向（默认）
    matchers:
      - type: status
        status: [200]
```

**优先级规则**：

```
请求级 redirects > 全局 --follow-redirects flag > 默认行为
```

- `nil`（未设置）：使用全局配置
- `true`：强制跟随重定向
- `false`：强制不跟随重定向

### 16.3 模板级 Matcher/Extractor（全局默认）

当某个请求块没有定义 `matchers` 或 `extractors` 时，引擎会使用模板级的默认值。

```yaml
id: advanced-auth-bypass
name: "Advanced Auth Bypass"
severity: "high"

# 模板级默认 matcher（所有请求块共享）
matchers:
  - type: status
    status: [200]

# 模板级默认 extractor
extractors:
  - name: "global_header"
    type: "regex"
    part: "header"
    regex: ['X-Custom-Header:\s*(\w+)']

http:
  - raw: |
      GET /api/admin HTTP/1.1
      Host: {{Hostname}}
    # 此请求使用模板级 matcher 和 extractor
    # 可以额外添加请求级 matcher，与模板级合并

  - raw: |
      POST /api/login HTTP/1.1
      Host: {{Hostname}}
      Content-Type: application/json

      {"username":"admin","password":"admin"}
    # 请求级 matcher 优先，模板级 matcher 作为补充
    matchers:
      - type: word
        words: ["login success"]
        part: "body"
    matchers-condition: "and"
```

**优先级规则**：

| 字段 | 优先级 | 说明 |
|------|--------|------|
| 请求级 `matchers` | 高 | 覆盖模板级同名 matcher |
| 模板级 `matchers` | 低 | 作为请求级的补充 |
| 请求级 `extractors` | 高 | 覆盖模板级同名 extractor |
| 模板级 `extractors` | 低 | 作为请求级的补充 |
| 请求级 `matchers-condition` | 高 | 覆盖模板级条件 |
| 模板级 `matchers-condition` | 低 | 默认值为 `"or"` |

### 16.4 DSL 中引用前置提取变量

在 HTTP 模式中，`run-if` 和 DSL matcher 都可以引用**之前请求块**提取的变量：

```yaml
http:
  # 第一个请求：提取 CSRF token
  - raw: |
      GET /api/login HTTP/1.1
      Host: {{Hostname}}
    extractors:
      - name: "csrf_token"
        type: "regex"
        regex: ['name="csrf"\s+value="([^"]+)"']
        group: 1
    matchers:
      - type: status
        status: [200]

  # 第二个请求：使用前置提取的变量
  - raw: |
      POST /api/submit HTTP/1.1
      Host: {{Hostname}}
      X-CSRF-Token: {{csrf_token}}
    run-if: "len(csrf_token) > 0"    # ← 引用上一个请求的提取结果
    matchers:
      - type: dsl
        dsl:
          - "status_code == 200"
          - "contains(body, 'success')"
```

**变量传递范围**：
- HTTP 模式：同一模板内所有请求块共享 `allExtracted` map

### 16.5 Workflow 的 matchers-condition 优先级（A2 Fix）

在 Workflow 模式中，当多个 HTTP 请求块存在时，**最后一个**请求块的 `matchers-condition` 决定整个步骤的聚合方式：

```go
// workflow.go:477-489
// A2 fix: prefer the LAST block's MatchersCondition
cond := "or"
for i := len(blocks) - 1; i >= 0; i-- {
    if blocks[i].MatchersCondition != "" {
        cond = blocks[i].MatchersCondition
        break
    }
}
```

**实际影响**：

```yaml
workflow:
  - name: "multi-step"
    http:
      - raw: |
          GET /api/step1 HTTP/1.1
          Host: {{Hostname}}
        matchers:
          - type: status
            status: [200]
        matchers-condition: "or"      # ← 被忽略

      - raw: |
          GET /api/step2 HTTP/1.1
          Host: {{Hostname}}
        matchers:
          - type: status
            status: [200]
          - type: word
            words: ["success"]
            part: "body"
        matchers-condition: "and"     # ← 生效！决定整个步骤的聚合条件
```

### 16.6 RawRequest/RawResponse 记录

当匹配成功时，引擎会自动记录**第一个命中请求**的原始请求和响应数据，可用于后续复放（replay）：

```go
// engine.go:539-695
var lastRawReq, lastRawResp string
// ...
// 匹配成功时：
*rawReqPtr = rawReq
*rawRespPtr = resp.Raw
// ...
return &types.Result{
    RawRequest:  lastRawReq,
    RawResponse: lastRawResp,
    // ...
}
```

结果中的 `RawRequest` 和 `RawResponse` 字段可用于：
- 在 Burp Suite 中复放请求
- 分析原始响应内容
- 生成漏洞报告

### 16.7 输出格式

支持多种输出格式：

```bash
# JSON 格式（默认）
gosleek scan -t http://example.com -o results.json

# SARIF 格式（适合集成到 CI/CD）
gosleek scan -t http://example.com -o results.sarif --format sarif

# HTML 报告（带图表）
gosleek scan -t http://example.com -o report.html --format html

# CSV 格式
gosleek scan -t http://example.com -o results.csv --format csv

# Markdown 格式
gosleek scan -t http://example.com -o report.md --format markdown

# TXT 纯文本
gosleek scan -t http://example.com -o results.txt --format txt
```

### 16.8 脱敏输出（Redact）

`--redact` 标志可遮蔽结果中的敏感信息：

```bash
gosleek scan -t http://example.com --redact -o results.json
```

脱敏规则：
- `extracted` 字段中包含 `secret`、`token`、`key`、`jwt` 的变量值会被遮蔽
- `evidence` 字段超过 40 字符时会被遮蔽

```yaml
# 脱敏前
extracted:
  jwt_token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# 脱敏后
extracted:
  jwt_token: "eyJhbG...J9..."
```

### 16.9 请求级 Rate-Limit（rate-limit）

默认全局限速通过 `config.yaml` 的 `rate-limit` 配置，也可以对**单个请求**设置限速，优先级高于全局配置。

```yaml
http:
  - raw: |
      POST /api/login HTTP/1.1
      Host: {{Hostname}}
      Content-Type: application/json

      {"user": "{{username}}", "pass": "{{password}}"}
    rate-limit: 10   # 此请求限速为 10 req/s，覆盖全局配置
    wordlist:
      - key: "username"
        path: "wordlists/users.txt"
      - key: "password"
        path: "wordlists/passwords.txt"
    matchers:
      - type: status
        status: [200]
```

**说明**：
- `rate-limit` 单位：请求/秒（req/s）
- `rate-limit: 0` 或省略：使用全局配置（默认 150 req/s）
- 通过 HTTP context key 传递，仅影响当前请求
- 适用于慢速接口爆破场景

---

### 16.10 请求级名称（name）

每个 HTTP 请求块可设置 `name` 字段，用于在 `-v` / `-vv` 日志中标识请求。

```yaml
http:
  - name: "extract-csrf-token"
    raw: |
      GET /api/settings HTTP/1.1
      Host: {{Hostname}}
    extractors:
      - name: "csrf_token"
        type: "regex"
        regex: ['name="csrf"\s+value="([^"]+)"']
    matchers:
      - type: status
        status: [200]
    probe: true

  - name: "test-no-token"
    raw: |
      POST /api/settings HTTP/1.1
      Host: {{Hostname}}
      Content-Type: application/json
      {"setting": "test"}
    run-if: "len(csrf_token) == 0"
    matchers:
      - type: status
        status: [200, 201, 204]
```

日志示例（`-vv`）：
```
[请求] csrf-token-missing req[0] name=extract-csrf-token  GET /api/settings  234 bytes
[响应] csrf-token-missing req[0]  status=200  12ms
```

### 16.11 内部提取器（internal）

内部提取器（`internal: true`）正常执行并存储到共享作用域，供后续请求使用，但**不出现在最终报告的 `extracted` 字段中**。

```yaml
http:
  - raw: |
      POST /api/login HTTP/1.1
      Host: {{Hostname}}
      Content-Type: application/json
      {"user": "admin", "pass": "test"}
    extractors:
      - name: "session_id"
        type: "kval"
        kval: ["set-cookie"]
        internal: true    # 不进入最终报告

  - raw: |
      GET /api/admin HTTP/1.1
      Host: {{Hostname}}
      Cookie: session={{session_id}}
    matchers:
      - type: status
        status: [200]
```

| 特性 | `internal: false` | `internal: true` |
|------|-------------------|------------------|
| 正常提取 | ✅ | ✅ |
| 存入共享作用域 | ✅ | ✅ |
| 后续请求可引用 | ✅ | ✅ |
| 出现在 Result.Extracted | ✅ | ❌ |

---

### 16.12 Workflow 步骤引用模板

> **注意**：`WorkflowStep.Template` 字段（类型定义中存在）目前**尚未实现**。Workflow 步骤之间的变量传递通过 `requires` + 提取器实现，而非模板引用。

### 16.13 日志格式优化（step 名称显示）

从 v1.5.1 起，日志输出新增了 step 名称标识，使 workflow 和插件的日志更易读：

**非 workflow 模板（YAML）：**
```
[请求] template-id req[0] name=extract-csrf-token  GET /api/settings  234 bytes
[响应] template-id req[0]  status=200  12ms  144 bytes
```

**Workflow 模板（带 step name）：**
```
[请求] workflow[trigger] step[0] (获取CSRF) req[0]  POST /api/login  318 bytes
[响应] workflow[trigger] step[0] (获取CSRF) req[0]  status=200  10ms  144 bytes
[匹配] workflow[trigger] step[0] (获取CSRF) req[0]  PASS  cond=or  types=status  evidence="status: 200"
[请求] workflow[trigger] step[1] (漏洞探测) req[0]  POST /api/exec  156 bytes
[响应] workflow[trigger] step[1] (漏洞探测) req[0]  status=500  8ms  89 bytes
[匹配] workflow[trigger] step[1] (漏洞探测) req[0]  PASS  cond=or  types=status  evidence="status: 500"
```

**Go 插件：**
```
[请求] CVE-2022-22963-go req[0]  POST /functionRouter  245 bytes
[响应] CVE-2022-22963-go req[0]  status=500  15ms  120 bytes
[匹配] CVE-2022-22963-go req[0]  PASS  cond=or  types=status  evidence="status: 500"
```

**字段说明：**
- `step[0] (获取CSRF)` — 步骤索引和步骤名称（来自 workflow 步骤的 `name` 字段）
- `req[0] name=extract-csrf-token` — 请求索引和请求名称（来自 `HTTPRequest.Name`）
- 非 workflow 模板（YAML 单模板或 Go 插件）无 step 信息，直接显示模板 ID

---

### 16.14 已删除的死字段

| 字段 | 位置 | 原因 |
|------|------|------|
| `threads` | `HTTPRequest` | 字段存在于类型定义中（默认值 0），但引擎不读取此字段，不影响任何行为 |

---

## 17. 附录：模板结构速查表
```yaml
# ============ 元数据 ============
id: "unique-id"
name: "Display Name"
description: |
  Multi-line description.
severity: critical
author: "author-name"
tags: [tag1, tag2]
reference:
  - "https://example.com"

# ============ 分类 ============
classification:
  cvss-score: 9.8
  cve-id: "CVE-2021-XXXX"
  cwe: "CWE-XXXX"

# ============ 预过滤 ============
fingerprints:
  - title: "Server Name"
    body: "Spring Boot"
    header:
      - "Server: Apache-Coyote/1.1"
      - "X-Application-Context"

# ============ 变量 ============
variables:
  my_var: "value"
  rand_var: "{{rand_text_alpha(8)}}"

# ============ OOB 配置 ============
oob-provider: "ceye"
oob:
  provider: "ceye"
  matchers:
    - type: json-word
      words: ["{{oob_label}}"]

# ============ 执行模式（二选一） ============

# HTTP 模式
http:
  - raw: |
      GET /path HTTP/1.1
      Host: {{Hostname}}
    probe: false           # 探测模式
    run-if: "len(token) > 0"  # 条件执行
    range:                 # 循环
      key: "param"
      values: ["a", "b"]
    wordlist:              # 字典爆破
      - key: "word"
        path: "wordlists/words.txt"
    timeout: 10
    redirects: true           # 重定向控制（nil=使用全局）
    rate-limit: 10          # 请求级限速
    name: "my-request"      # 请求命名
    timeout: 10
    matchers-condition: "or"
    matchers: [...]
    extractors: [...]

# Workflow 模式
workflow:
  - name: "step1"
    requires: []           # 无依赖
    delay: 0               # 无延迟
    provider: ""           # 全局 provider
    http: [...]

  - name: "step2"
    requires: ["step1"]    # 依赖 step1
    http: [...]

# ============ 模板级默认值 ============
stop-at-first-match: false
matchers-condition: "or"
matchers: [...]
extractors: [...]
```

---

*本文档基于 gosleek v1.5.2 代码分析编写，涵盖了 HTTP 模式、Workflow 模式、Probe、Run-If、Range、Wordlist、body-type、DSL、Matcher、Extractor、OOB 等核心机制的完整原理和使用方法。*