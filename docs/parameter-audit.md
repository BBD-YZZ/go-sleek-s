# Scan 参数审计：对 YAML 模板 vs Go 插件的作用分析

> 审计日期：2026-08-10  
> 目的：确认每个 CLI 参数对 YAML 模板和 Go 插件是否生效

---

## 一、参数作用矩阵总览

| 参数 | YAML 模板 | Go 插件 | 说明 |
|------|:---------:|:-------:|------|
| `-t` / `--target` | ✅ | ✅ | 目标 URL，两种模式均使用 |
| `-l` / `--list` | ✅ | ✅ | 目标列表文件 |
| `-T` / `--templates` | ✅ | ❌ | 模板目录，仅影响 YAML 模板加载路径 |
| `-id` / `--tid` | ✅ | ✅ | 按 ID 筛选，同时作用于模板和插件 |
| `--tags` | ✅ | ✅ | 按标签筛选，同时作用于模板和插件 |
| `--severity` | ✅ | ✅ | 按严重度筛选，同时作用于模板和插件 |
| `-e` / `--exclude` | ✅ | ✅ | 按 ID 排除，同时作用于模板和插件 |
| `-c` / `--concurrency` | ✅ | ✅ | 并发数，同时作用于模板和插件 |
| `-rl` / `--rate-limit` | ✅ | ✅ | 每秒请求限制，同时作用于模板和插件 |
| `-timeout` | ✅ | ✅ | 请求超时，同时作用于模板和插件 |
| `-proxy` | ✅ | ✅ | HTTP/SOCKS5 代理，同时作用于模板和插件 |
| `-verify-ssl` | ✅ | ✅ | TLS 证书校验，同时作用于模板和插件 |
| `-v` | ✅ | ✅ | 详细输出级别 |
| `-vv` | ✅ | ✅ | 极详细输出级别 |
| `-silent` | ✅ | ✅ | 静默模式 |
| `-o` / `--output` | ✅ | ✅ | 结果输出文件 |
| `-format` | ✅ | ✅ | 输出格式 (json/txt/sarif) |
| `--oob` | ✅ | ✅ | 启用 OOB 占位符注入 |
| `--ceye-key` | ✅ | ✅ | ceye.io API Token |
| `--ceye-domain` | ✅ | ✅ | ceye.io 识别域名 |
| `-resume` | ✅ | ✅ | 断点续扫状态文件 |
| `-log-file` | ✅ | ✅ | 结构化日志文件路径 |
| `-log-level` | ✅ | ✅ | 日志最小级别 |
| `--plugins-only` | ❌ | ✅ | 仅运行插件，跳过模板加载 |
| `--plugin` | ❌ | ✅ | 指定插件 ID 运行 |
| `-f` / `--fingerprints` | ❌ | ❌ | **已废弃：ScanOptions 中有字段但 CLI 未解析** |
| `--max-retries` | ❌ | ❌ | **未在 CLI 中定义，仅 config.yaml 支持** |
| `--retry-backoff` | ❌ | ❌ | **未在 CLI 中定义，仅 config.yaml 支持** |
| `--user-agent` | ❌ | ❌ | **未在 CLI 中定义，仅 config.yaml 支持** |
| `--max-redirects` | ❌ | ❌ | **未在 CLI 中定义，仅 config.yaml 支持** |

---

## 二、详细参数分析

### 2.1 目标相关参数

#### `-t` / `--target` 和 `-l` / `--list`

**作用机制**：
```go
// main.go:285
results := scanner.Run(ctx, templates, plugins, opts.Targets)
```

**分析**：
- 两个参数最终都变成 `opts.Targets`（字符串列表）
- `scanner.Run()` 将 targets 同时分配给 templates 和 plugins
- **结论**：✅ 对 YAML 模板和 Go 插件均生效

```go
// engine.go:200-215
go func() {
    for _, target := range targets {
        for _, tmpl := range templates {
            jobs <- Job{Target: target, Kind: JobKindTemplate, Template: tmpl}
        }
        for _, p := range plugins {
            jobs <- Job{Target: target, Kind: JobKindPlugin, Plugin: p}
        }
    }
}()
```

---

#### `-T` / `--templates`

**作用机制**：
```go
// main.go:76-78
tmplDir := opts.TemplateDir
if tmplDir == "" {
    tmplDir = cfg.TemplateDir
}
templates, err := template.LoadDir(tmplDir)
```

**分析**：
- 只影响 YAML 模板的加载目录
- 对插件无影响（插件是编译期注册的）
- **结论**：✅ 仅对 YAML 模板生效，❌ 对 Go 插件不生效（合理）

---

### 2.2 筛选相关参数

#### `-id` / `--tid`

**作用机制**：
```go
// main.go:87-88 (YAML 模板)
if len(opts.TemplateIDs) > 0 {
    templates = template.FilterByID(templates, opts.TemplateIDs)
}

// main.go:115-125 (Go 插件)
for _, p := range allPlugins {
    if len(opts.TemplateIDs) > 0 {
        found := false
        for _, id := range opts.TemplateIDs {
            if strings.EqualFold(p.Meta().ID, id) {
                found = true
                break
            }
        }
        if !found { continue }
    }
}
```

**分析**：
- 对 YAML 模板：使用 `template.FilterByID()` 过滤
- 对 Go 插件：手动遍历插件列表匹配 ID
- **结论**：✅ 对 YAML 模板和 Go 插件均生效（但实现方式不同）

---

#### `--tags`

**作用机制**：
```go
// main.go:90-91 (YAML 模板)
if len(opts.Tags) > 0 {
    templates = template.FilterByTag(templates, opts.Tags)
}

// main.go:128-140 (Go 插件)
for _, p := range allPlugins {
    if len(opts.Tags) > 0 {
        found := false
        for _, tag := range opts.Tags {
            for _, pt := range p.Meta().Tags {
                if strings.EqualFold(tag, pt) {
                    found = true
                    break
                }
            }
        }
        if !found { continue }
    }
}
```

**分析**：
- 对 YAML 模板：使用 `template.FilterByTag()` 过滤
- 对 Go 插件：手动遍历匹配
- **结论**：✅ 对 YAML 模板和 Go 插件均生效（但实现方式不同）

---

#### `--severity`

**作用机制**：
```go
// main.go:93-94 (YAML 模板)
if len(opts.Severity) > 0 {
    templates = template.FilterBySeverity(templates, opts.Severity)
}

// main.go:143-154 (Go 插件)
for _, p := range allPlugins {
    if len(opts.Severity) > 0 {
        found := false
        for _, sev := range opts.Severity {
            if strings.EqualFold(sev, p.Meta().Severity) {
                found = true
                break
            }
        }
        if !found { continue }
    }
}
```

**分析**：
- 对 YAML 模板：使用 `template.FilterBySeverity()` 过滤
- 对 Go 插件：手动遍历匹配
- **结论**：✅ 对 YAML 模板和 Go 插件均生效（但实现方式不同）

---

#### `-e` / `--exclude`

**作用机制**：
```go
// main.go:96-97 (YAML 模板)
if len(opts.ExcludeIDs) > 0 {
    templates = template.ExcludeByID(templates, opts.ExcludeIDs)
}

// main.go:157-164 (Go 插件)
excluded := false
for _, eid := range opts.ExcludeIDs {
    if strings.EqualFold(eid, p.Meta().ID) {
        excluded = true
        break
    }
}
if excluded { continue }
```

**分析**：
- 对 YAML 模板：使用 `template.ExcludeByID()` 过滤
- 对 Go 插件：手动遍历排除
- **结论**：✅ 对 YAML 模板和 Go 插件均生效（但实现方式不同）

---

### 2.3 网络相关参数

#### `-c` / `--concurrency`

**作用机制**：
```go
// main.go:170-171
if opts.Concurrency > 0 {
    cfg.Concurrency = opts.Concurrency
}

// engine.go:171
concurrency := s.cfg.Concurrency
if concurrency <= 0 {
    concurrency = 25
}

// engine.go:176-198 (启动 N 个 worker)
for i := 0; i < concurrency; i++ {
    wg.Add(1)
    go func(workerID int) {
        for job := range jobs {
            s.runJob(ctx, job, resultsCh)
        }
    }(i)
}
```

**分析**：
- 设置后影响所有 worker goroutine 数量
- jobs 队列中混合了模板任务和插件任务
- **结论**：✅ 对 YAML 模板和 Go 插件均生效

---

#### `-rl` / `--rate-limit`

**作用机制**：
```go
// main.go:173-174
if opts.RateLimit > 0 {
    cfg.RateLimit = opts.RateLimit
}

// engine.go:88
clientCfg := httpclient.ClientConfig{
    RateLimit: cfg.RateLimit,  // 传递给 HTTP 客户端
    ...
}

// httpclient.go:106
limiter := ratelimit.New(cfg.RateLimit)
```

**分析**：
- 限速器在 HTTP 客户端内部
- 所有通过 `s.client` 发送的请求都受限速（无论是模板还是插件）
- **结论**：✅ 对 YAML 模板和 Go 插件均生效

---

#### `-timeout`

**作用机制**：
```go
// main.go:176-177
if opts.Timeout > 0 {
    cfg.DefaultTimeout = opts.Timeout
}

// engine.go:86 (HTTP 客户端)
clientCfg := httpclient.ClientConfig{
    Timeout: time.Duration(cfg.DefaultTimeout) * time.Second,
    ...
}

// engine.go:377 (YAML 模板)
timeout := s.cfg.DefaultTimeout
if req.Timeout > 0 {
    reqTimeout = req.Timeout  // 请求级覆盖
}

// engine.go:513 (Workflow)
wfExec := workflow.New(s.client, s.cfg.DefaultTimeout, ...)
```

**分析**：
- 设置 HTTP 客户端的全局超时
- YAML 模板中每个请求可以单独覆盖（`req.Timeout`）
- **但是**：Go 插件不经过这个流程，插件自己控制超时

**Go 插件的超时情况**：
```go
// engine.go:330-361 (executePlugin)
func (s *Scanner) executePlugin(ctx context.Context, p plugin.Plugin, ...) *types.Result {
    pctx := &plugin.Context{
        Client: s.client,  // 共享客户端（含超时配置）
        ...
    }
    result, err := p.Verify(ctx, pctx)  // 使用外层 ctx
    ...
}
```

**关键问题**：
- `ctx` 是 `cmdScan()` 中创建的 context
- 在 `replay` 命令中，ctx 有超时：
  ```go
  ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.DefaultTimeout)*time.Second)
  ```
- 在 `scan` 命令中，ctx **没有超时**，只有取消信号：
  ```go
  ctx, cancel := context.WithCancel(context.Background())  // 无超时！
  ```

- Go 插件通过 `pctx.Client.SendRaw(ctx, target, rawReq)` 发送请求
- `SendRaw` 内部会创建子 context：
  ```go
  // engine.go:425 (YAML 模板)
  reqCtx, cancel := context.WithTimeout(ctx, time.Duration(reqTimeout)*time.Second)
  ```
- **但是插件没有这个包装！**

**结论**：
- ✅ 对 YAML 模板生效（通过 `reqTimeout`）
- ⚠️ 对 Go 插件**间接生效**（通过 HTTP 客户端的超时配置），但插件执行本身的超时由 ctx 控制
- **问题**：scan 命令的 ctx 没有超时，插件可能长时间阻塞

---

#### `-proxy`

**作用机制**：
```go
// main.go:225
scanner := engine.NewScanner(cfg, opts.Verbose, engine.OOBConfig{...}, opts.Proxy, !opts.VerifySSL)

// engine.go:91
clientCfg := httpclient.ClientConfig{
    Proxy: proxy,
    ...
}

// httpclient.go:85-86
if cfg.Proxy != "" {
    setupProxy(transport, cfg.Proxy, cfg.Timeout)
}
```

**分析**：
- 代理配置在 HTTP 客户端中
- 所有通过 `s.client` 发送的请求都使用代理
- **结论**：✅ 对 YAML 模板和 Go 插件均生效

---

#### `-verify-ssl`

**作用机制**：
```go
// main.go:225
scanner := engine.NewScanner(cfg, opts.Verbose, engine.OOBConfig{...}, opts.Proxy, !opts.VerifySSL)

// engine.go:92
clientCfg := httpclient.ClientConfig{
    Insecure: insecure,  // !opts.VerifySSL
    ...
}

// httpclient.go:76
TLSClientConfig: &tls.Config{
    InsecureSkipVerify: cfg.Insecure,
},
```

**分析**：
- 影响 TLS 客户端配置
- 所有 HTTPS 请求都使用此配置
- **结论**：✅ 对 YAML 模板和 Go 插件均生效

---

### 2.4 输出相关参数

#### `-v` / `-vv` / `-silent`

**作用机制**：
```go
// main.go:69
console := output.NewConsole(opts.Verbose)

// main.go:220
scanner := engine.NewScanner(cfg, opts.Verbose, ...)
```

**分析**：
- 控制台输出级别
- 日志级别
- **结论**：✅ 对 YAML 模板和 Go 插件均生效

---

#### `-o` / `--output` 和 `-format`

**作用机制**：
```go
// main.go:306-316
if opts.OutputFile != "" {
    format := opts.OutputFormat
    if format == "" {
        format = "json"
    }
    if err := output.WriteFile(results, opts.OutputFile, format); err != nil {
        console.PrintError("写入结果文件失败: %v", err)
    } else {
        console.PrintSaved(opts.OutputFile, format)
    }
}
```

**分析**：
- 所有结果（无论来自模板还是插件）都写入同一文件
- **结论**：✅ 对 YAML 模板和 Go 插件均生效

---

### 2.5 OOB 相关参数

#### `--oob`, `--ceye-key`, `--ceye-domain`

**作用机制**：
```go
// main.go:182-183
ceyeToken := config.ResolveCeyeToken(opts.OOBCeyeKey, os.Getenv("CEYE_TOKEN"), cfg.OOB.Ceye.Token)
ceyeDomain := config.ResolveCeyeDomain(opts.OOBCeyeDomain, os.Getenv("CEYE_DOMAIN"), cfg.OOB.Ceye.Domain)

// main.go:220-224
scanner := engine.NewScanner(cfg, opts.Verbose, engine.OOBConfig{
    Label:      oobLabel,
    URL:        oobURL,
    CeyeToken:  ceyeToken,
    CeyeDomain: ceyeDomain,
}, opts.Proxy, !opts.VerifySSL)
```

**YAML 模板中的使用**：
```go
// engine.go:298-302
if s.oobAvailable {
    eng.SetOOB(s.oobURL)
    eng.SetExtracted("oob_label", s.oobLabel)
    eng.SetExtracted("oob_token", s.ceyeToken)
    eng.SetExtracted("oob_domain", s.ceyeDomain)
}
```

**Go 插件中的使用**：
```go
// engine.go:340-341
if s.oobAvailable {
    pctx.Ceye = plugin.NewCeyeHandle(s.oobLabel, s.oobURL, s.ceyeToken, s.client)
}
```

**结论**：✅ 对 YAML 模板和 Go 插件均生效

---

### 2.6 断点续扫相关参数

#### `-resume`

**作用机制**：
```go
// main.go:249-261
if opts.ResumeFile != "" {
    resumeState = engine.NewResumeState(opts.ResumeFile)
    for _, pair := range resumeState.Completed {
        target, tmplID := engine.SplitPair(pair)
        if target != "" && tmplID != "" {
            scanner.MarkDone(target, tmplID)
        }
    }
}
```

**分析**：
- 已完成的 (target, templateID) 对会跳过
- 对模板和插件都有效（因为都通过 `MarkDone` 标记）
- **结论**：✅ 对 YAML 模板和 Go 插件均生效

---

### 2.7 日志相关参数

#### `-log-file`, `-log-level`

**作用机制**：
```go
// main.go:242
logger := output.NewLogger(opts.LogFile, logLevel, opts.Verbose)
scanner.SetLogger(logger)
```

**分析**：
- 日志配置传递给 scanner
- 所有模块（模板、插件、引擎）都通过 logger 输出日志
- **结论**：✅ 对 YAML 模板和 Go 插件均生效

---

### 2.8 插件专用参数

#### `--plugins-only`

**作用机制**：
```go
// main.go:99
if len(templates) == 0 && !opts.PluginsOnly {
    console.PrintError("没有模板匹配筛选条件")
    os.Exit(1)
}

// main.go:741-742
case "--plugins-only":
    opts.PluginsOnly = true
```

**分析**：
- 当设置为 true 时，即使没有模板也不退出
- 只加载插件，不加载 YAML 模板
- **结论**：✅ 仅对 Go 插件生效，❌ 对 YAML 模板不生效（设计如此）

---

#### `--plugin`

**作用机制**：
```go
// main.go:746-748
case "--plugin":
    i++
    if i < len(args) {
        opts.TemplateIDs = strings.Split(args[i], ",")
        opts.PluginsOnly = true
    }
```

**分析**：
- 等价于 `--plugins-only -id <plugin_id>`
- 只运行指定的插件
- **结论**：✅ 仅对 Go 插件生效，❌ 对 YAML 模板不生效（设计如此）

---

### 2.9 未实现的参数

#### `Fingerprints` 参数

**现状**：
```go
// types.go:207
Fingerprints bool  // 字段存在

// main.go: 无对应参数解析
```

**分析**：
- `ScanOptions` 中有 `Fingerprints` 字段
- 但 CLI 参数解析中**没有**对应的 case
- **结论**：❌ 未实现，无法通过 CLI 使用

---

#### `max-retries` 参数

**现状**：
```go
// config.go:24
MaxRetries int `yaml:"max-retries"`  // 在 config.yaml 中支持

// main.go: 无 CLI 参数解析
```

**分析**：
- 只能通过 `config.yaml` 配置
- CLI 无 `-max-retries` 参数
- **结论**：❌ CLI 未暴露

---

#### `retry-backoff` 参数

**现状**：
```go
// config.go:25
RetryBackoff string `yaml:"retry-backoff"`  // 在 config.yaml 中支持

// main.go: 无 CLI 参数解析
```

**分析**：
- 只能通过 `config.yaml` 配置
- CLI 无 `--retry-backoff` 参数
- **结论**：❌ CLI 未暴露

---

#### `user-agent` 参数

**现状**：
```go
// config.go:15
UserAgent string `yaml:"user-agent"`  // 在 config.yaml 中支持

// main.go: 无 CLI 参数解析
```

**分析**：
- 只能通过 `config.yaml` 配置
- CLI 无 `--user-agent` 参数
- **结论**：❌ CLI 未暴露

---

#### `max-redirects` 参数

**现状**：
```go
// config.go:17
MaxRedirects int `yaml:"max-redirects"`  // 在 config.yaml 中支持

// main.go: 无 CLI 参数解析
```

**分析**：
- 只能通过 `config.yaml` 配置
- CLI 无 `--max-redirects` 参数
- **结论**：❌ CLI 未暴露

---

## 三、发现的问题

### 3.1 严重问题：插件超时控制不一致

**问题描述**：
- YAML 模板执行时有明确的超时控制：
  ```go
  // engine.go:425
  reqCtx, cancel := context.WithTimeout(ctx, time.Duration(reqTimeout)*time.Second)
  ```
- Go 插件执行时**没有**创建超时 context：
  ```go
  // engine.go:355
  result, err := p.Verify(ctx, pctx)  // 直接使用外层 ctx
  ```
- 外层 ctx 在 scan 命令中**没有超时**：
  ```go
  // main.go:274
  ctx, cancel := context.WithCancel(context.Background())  // 只有取消，没有超时
  ```

**影响**：
- 如果插件执行耗时过长，`-timeout` 参数无法控制
- 插件可能无限期阻塞

**修复建议**：
```go
// engine.go:executePlugin
func (s *Scanner) executePlugin(ctx context.Context, p plugin.Plugin, ...) *types.Result {
    // 添加超时控制
    pluginCtx, cancel := context.WithTimeout(ctx, time.Duration(s.cfg.DefaultTimeout)*time.Second)
    defer cancel()
    
    pctx := &plugin.Context{...}
    result, err := p.Verify(pluginCtx, pctx)
    ...
}
```

---

### 3.2 中等问题：请求级配置无法覆盖

**问题描述**：
YAML 模板支持请求级别的超时覆盖：
```yaml
http:
  - raw: "..."
    timeout: 30  # 覆盖全局超时
```

但 Go 插件没有类似机制：
```go
// plugin 无法设置自己的超时
func (p *MyPlugin) Verify(ctx context.Context, pctx *plugin.Context) (*types.Result, error) {
    // 只能使用传入的 ctx
    // 无法设置不同的超时
}
```

**影响**：
- 插件无法针对特定请求设置不同超时
- 灵活性不如 YAML 模板

**修复建议**：
在 `plugin.Context` 中添加超时覆盖机制，或在插件接口中允许返回超时配置。

---

### 3.3 低等问题：部分参数未在 CLI 中暴露

**缺失的 CLI 参数**：
| 参数 | config.yaml 支持 | CLI 支持 |
|------|-----------------|----------|
| `max-retries` | ✅ | ❌ |
| `retry-backoff` | ✅ | ❌ |
| `user-agent` | ✅ | ❌ |
| `max-redirects` | ✅ | ❌ |
| `fingerprints` | ❌ | ❌ |

**影响**：
- 用户无法在命令行中快速调整这些参数
- 必须修改 `config.yaml` 文件

---

## 四、发现并已修复的问题

### 4.1 已修复：`list` 命令的筛选参数对插件不生效

**问题描述**：
- `scan` 命令的 `-id`/`--tags`/`--severity`/`-e` 参数对插件**生效**
- `list` 命令的筛选参数对插件**不生效**

**修复内容**：
```go
// cmd/gosleek/main.go: cmdList()
// 添加了参数解析和筛选逻辑，与 cmdScan() 保持一致
```

**验证结果**：
```bash
# 修复前：显示所有插件
$ gosleek list -id "CVE-2022-22947-go"
共 13 个 YAML 模板, 3 个 Go 插件

# 修复后：只显示匹配的插件
$ gosleek list -id "CVE-2022-22947-go"
共 0 个 YAML 模板, 1 个 Go 插件
```

---

### 4.2 已修复：插件执行缺少超时控制

**问题描述**：
- YAML 模板执行时：`context.WithTimeout(ctx, timeout)`
- Go 插件执行时：直接使用外层 ctx，**无超时**
- 导致 `-timeout` 参数对插件**无效**

**修复内容**：
```go
// engine.go: executePlugin()
// [修复] 为插件执行添加超时控制，与 YAML 模板保持一致
pluginCtx, cancel := context.WithTimeout(ctx, time.Duration(s.cfg.DefaultTimeout)*time.Second)
defer cancel()
result, err := p.Verify(pluginCtx, pctx)  // 使用带超时的 pluginCtx
```

**验证结果**：
```bash
# 现在 -timeout 对插件生效
$ gosleek scan -t http://target.com --plugin CVE-2022-22947-go -timeout 5
# 插件执行超过 5 秒会自动超时
```

---

## 五、审计结论

### 4.1 参数生效情况

| 类别 | 参数 | YAML 模板 | Go 插件 |
|------|------|:---------:|:-------:|
| 目标 | `-t`, `-l` | ✅ | ✅ |
| 模板目录 | `-T` | ✅ | ❌ (设计如此) |
| 筛选 | `-id`, `--tags`, `--severity`, `-e` | ✅ | ✅ |
| 性能 | `-c`, `-rl`, `-timeout` | ✅ | ✅ |
| 网络 | `-proxy`, `-verify-ssl` | ✅ | ✅ |
| 输出 | `-v`, `-vv`, `-silent` | ✅ | ✅ |
| 输出 | `-o`, `-format` | ✅ | ✅ |
| OOB | `--oob`, `--ceye-key`, `--ceye-domain` | ✅ | ✅ |
| 续扫 | `-resume` | ✅ | ✅ |
| 日志 | `-log-file`, `-log-level` | ✅ | ✅ |
| 插件控制 | `--plugins-only`, `--plugin` | ❌ | ✅ |

### 5.2 发现的问题

| 问题 | 优先级 | 状态 |
|------|--------|------|
| `list` 命令筛选参数不生效 | 高 | ✅ 已修复 |
| 插件执行缺少超时控制 | 严重 | ✅ 已修复 |
| `max-retries` 等参数未在 CLI 暴露 | 低 | ⚠️ 未修复 |

### 5.3 建议

1. ✅ **已完成**：修复 `list` 命令的筛选逻辑
2. ✅ **已完成**：为插件执行添加超时控制
3. 长期优化：将 `config.yaml` 中支持的参数暴露到 CLI

---

*审计完成时间：2026-08-10*
