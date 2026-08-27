# Go-Sleek-T 架构原理与代码调用关系分析

> 版本：v1.0.1  
> 分析日期：2026-08-10

---

## 一、系统定位与设计哲学

Go-Sleek-T 是一款**模板驱动的漏洞扫描器**，其核心设计理念是：

> **漏洞检测逻辑与扫描引擎分离** — 新增漏洞只需编写 YAML 模板或 Go 插件，无需修改核心代码。

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         设计理念                                        │
│                                                                         │
│   引擎 = 调度 + 并发 + 输出 + 日志    (保持不变)                        │
│   检测 = 模板 + 插件               (按需扩展)                           │
│                                                                         │
│   新增漏洞检测 = 新增 YAML 文件或 Go 插件包                             │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 二、模块分层架构

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           cmd/gosleek (CLI 入口层)                          │
│   main.go                                                                    │
│   ├── 命令路由: scan / list / validate / replay / version / help            │
│   ├── 参数解析: parseScanFlags()                                             │
│   ├── 流程编排: cmdScan() → 加载 → 筛选 → 扫描 → 输出                       │
│   └── 辅助: cmdReplay(), cmdList(), cmdValidate()                           │
└────────────────────────┬─────────────────────────────────────────────────────┘
                         │ 调用
┌────────────────────────▼─────────────────────────────────────────────────────┐
│                        internal/config (配置层)                              │
│   config.go                                                                  │
│   ├── DefaultConfig()   → 提供默认值 (timeout=10, concurrency=25, ...)     │
│   ├── Load()            → 从 config.yaml 加载配置 (覆盖默认值)               │
│   ├── ResolveCeyeToken/Domain → 优先级: flag > env > config                │
│   └── 数据结构: GlobalConfig, OOBConfigYAML, CeyeConfig                      │
└────────────────────────┬─────────────────────────────────────────────────────┘
                         │ 传入
┌────────────────────────▼─────────────────────────────────────────────────────┐
│                    internal/engine (核心引擎层) ★ 核心调度中枢                │
│   engine.go                                                                  │
│   ├── Scanner struct     → 所有扫描状态的持有者                              │
│   ├── Run()              → 并发调度入口                                                                       │
│   ├── runJob()           → 单任务执行 (去重 → 指纹 → 执行)                    │
│   ├── executeHTTP()      → YAML 单模板模式执行                               │
│   ├── executeWorkflow()  → YAML 多步工作流执行                               │
│   └── executePlugin()    → Go 插件执行                                       │
│                                                                              │
│   resume.go                                                                    │
│   ├── ResumeState      → 断点续扫状态 (已完成 target|templateID 对)          │
│   └── MarkDone/GetCompleted/SplitPair          → 续扫辅助方法                │
└────────────────────────┬─────────────────────────────────────────────────────┘
                         │ 调用
         ┌───────────────┼───────────────┬───────────────┬───────────────┐
         │               │               │               │               │
  ┌──────▼──────┐  ┌─────▼──────┐  ┌────▼───────┐  ┌────▼───────┐  ┌────▼───────┐
  │ httpclient  │  │   matcher  │  │ placeholder │  │  workflow  │  │ fingerprint│
  │  HTTP发送层 │  │  匹配引擎  │  │  变量替换   │  │ 多步工作流 │  │  指纹探测  │
  └──────┬──────┘  └─────┬──────┘  └────┬───────┘  └────┬───────┘  └────┬───────┘
         │               │               │               │               │
  ┌──────▼───────────────────────────────────────────────────────────────────┐
  │                      internal/ratelimit (限速层)                         │
  │   limiter.go → per-host Token Bucket 限速器                              │
  └──────────────────────────────────────────────────────────────────────────┘
  ┌──────────────────────────────────────────────────────────────────────────┐
  │                      internal/plugin (插件系统)                          │
  │   plugin.go   → Plugin 接口 / Context / Logger / OOBHandle             │
  │   registry.go → 全局插件注册表 (sync.RWMutex)                           │
  │   helpers.go  → CeyeHandle / PluginLogger / PluginReporter              │
  └──────────────────────────────────────────────────────────────────────────┘
         │               │               │               │
         └───────────────┴───────────────┴───────────────┘
                         │
┌────────────────────────▼─────────────────────────────────────────────────────┐
│                      internal/output (输出层)                                │
│   console.go  → Console 结构化输出 (3级 verbose: -v/-vv/-silent)            │
│   logger.go   → Logger slog 结构化日志 (console + JSON file)                │
│   file.go     → WriteFile (JSON / TXT 输出)                                 │
│   sarif.go    → SARIF 2.1.0 格式输出 (CI/IDE 集成)                          │
└──────────────────────────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────────────────┐
│                      internal/utils (工具层)                                │
│   utils.go    → Truncate / Masked / MapKeys / AtoiSafe                     │
└──────────────────────────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────────────────┐
│                      pkg/types (共享类型层)                                  │
│   types.go    → Template / Matcher / Extractor / Result / ScanOptions ...  │
└──────────────────────────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────────────────┐
│                      plugins/ (插件实现层)                                   │
│   init.go     → 集中导入所有插件包，触发 init() 注册                         │
│   cve_2022_22947/  → Spring Cloud Gateway SpEL RCE                         │
│   cve_2022_22963/  → Spring Cloud Function SpEL OOB                        │
│   jwt_secret_bruteforce/ → JWT 弱密钥爆破                                   │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 三、完整执行流程

### 3.1 scan 命令的完整调用链

```
gosleek scan -t http://target.com -v -id CVE-2021-44228
    │
    ▼
main()
  │
  └──► cmdScan(args)
        │
        ├──► parseScanFlags(args)
        │     → 解析 -t/-l 目标列表
        │     → 解析 -id/--tags/--severity 筛选
        │     → 解析 -c/-rl/-timeout 性能参数
        │     → 解析 -o/-format 输出参数
        │     → 解析 --oob/--ceye-key/--ceye-domain
        │     → 解析 -resume 断点续扫
        │     → 解析 -log-file/-log-level
        │
        ├──► config.Load("")
        │     → 尝试读取 config.yaml
        │     → 读取 configs/config.yaml
        │     → 回退到 DefaultConfig()
        │     → 如果 OOB 为空，尝试 oob.yaml / configs/oob.yaml
        │
        ├──► output.NewConsole(verbose)
        │     → 创建控制台输出处理器
        │
        ├──► console.PrintBanner(version)        // 显示 ASCII Banner
        ├──► console.PrintDisclaimer()            // 显示免责声明
        │
        ├──► template.LoadDir(tmplDir)
        │     → filepath.Walk 递归遍历目录
        │     → 每行 YAML 解析为 types.Template
        │     → 设置默认 matchers-condition="or"
        │     → 计算 SHA256 签名
        │     → 返回 []*types.Template
        │
        ├──► template.FilterByID()               // 按 ID 筛选
        ├──► template.FilterByTag()              // 按标签筛选
        ├──► template.FilterBySeverity()         // 按严重度筛选
        ├──► template.ExcludeByID()              // 按排除 ID 过滤
        ├──► template.SortBySeverity()            // 按严重度降序排序
        │
        ├──► plugin.All()                         // 获取所有已注册插件
        │     → 遍历 registry map (RWMutex)
        │     → 应用相同的 ID/Tag/Severity/Exclude 筛选
        │
        ├──► engine.NewScanner(cfg, verbose, OOBConfig, proxy, insecure)
        │     → 创建 httpclient.Client (含代理/限速/重试)
        │     → 创建 fingerprint.Detector
        │     → 返回 *engine.Scanner
        │
        ├──► output.NewLogger(logFile, logLevel, verbose)
        │     → 创建 slog.Logger + ptermHandler
        │     → 支持 console + JSON file 双路输出
        │     → scanner.SetLogger(logger)
        │
        ├──► engine.NewResumeState(resumeFile)   // 断点续扫
        │     → 从 JSON 文件加载已完成的任务对
        │     → 遍历 completed 列表，scanner.MarkDone(target, templateID)
        │
        ├──► scanner.SetCallbacks(
        │       onResult → console.PrintResult     // 命中结果
        │       onProgress → console.PrintProgress // 进度更新
        │       onVerbose → console.PrintVerb      // -v 日志
        │       onDebug → console.PrintDebug       // -vv 日志
        │       onRaw → console.PrintRaw           // 匹配详情
        │       onPacket → console.PrintPacket     // Burp-style 包输出
        │     )
        │
        ├──► context.WithCancel(context.Background())  // 创建取消上下文
        ├──► signal.Notify(sigCh, SIGINT, SIGTERM)    // 信号处理
        │     → goroutine: 收到信号 → cancel() → 优雅退出
        │
        └──► results := scanner.Run(ctx, templates, plugins, targets)
              │
              │  ★ 核心扫描逻辑 ★
              │
              ├──► 创建 results chan (buffered 256) — 结果收集通道
              │   var allResults []*types.Result
              │
              ├──► 启动 collector goroutine:
              │     for r := range resultsCh {
              │       allResults = append(allResults, r)
              │       onResult(r)  // 打印结果卡片
              │     }
              │
              ├──► 创建 jobs chan (buffered 1024) — 任务队列
              │   s.totalJobs = (len(templates) + len(plugins)) * len(targets)
              │
              ├──► 启动 N 个 worker goroutine (N = concurrency):
              │     for job := range jobs {
              │       if ctx.Err() != nil { return }
              │       s.runJob(ctx, job, resultsCh)
              │       atomic.AddInt64(&s.completed, 1)
              │       onProgress(completed, total, msg)
              │     }
              │
              ├──► 启动 producer goroutine:
              │     for target in targets {
              │       for tmpl in templates {
              │         select {
              │         case <-ctx.Done(): goto done
              │         case jobs <- Job{Target: target, Kind: Template, Template: tmpl}:
              │         }
              │       }
              │       for plugin in plugins {
              │         select {
              │         case <-ctx.Done(): goto done
              │         case jobs <- Job{Target: target, Kind: Plugin, Plugin: p}:
              │         }
              │       }
              │     }
              │    done:
              │     close(jobs)
              │
              ├──► wg.Wait()              // 等待所有 worker 完成
              ├──► close(resultsCh)       // 关闭结果通道
              ├──► collectorWG.Wait()     // 等待 collector 完成
              └──► return allResults
        │
        ├──► resumeState.Save()         // 保存续扫状态
        │
        ├──► console.PrintScanEnd(total, matched)  // 打印扫描汇总
        ├──► console.PrintVulnSummary(results)    // 打印漏洞汇总表
        │
        ├──► output.WriteFile(results, outputFile, format)
        │     ├── format="json" → writeJSON()
        │     ├── format="txt"  → writeTXT()
        │     └── format="sarif" → writeSARIF()
        │
        └──► if len(results) > 0: os.Exit(1)  // 有命中则退出码 1
```

### 3.2 单任务执行流程 (runJob)

```
runJob(ctx, job, results chan)
  │
  │  job 可以是 YAML 模板或 Go 插件
  │
  ├──► 确定模板 ID:
  │     if job.Kind == JobKindPlugin: id = job.Plugin.Meta().ID
  │     else:                           id = job.Template.ID
  │
  ├──► 去重检查 (sync.Map):
  │     dedupKey = target + "|" + id
  │     if _, exists := s.dedup.LoadOrStore(dedupKey, true); exists {
  │       → 已处理过，跳过 (日志记录)
  │       return
  │     }
  │
  ├──► 指纹预过滤 (可选):
  │     fps = job.Plugin.Fingerprints() 或 job.Template.Fingerprints
  │     if len(fps) > 0 {
  │       fp = s.fingerprint.Detect(ctx, target)
  │       → 发送 GET / 探测目标
  │       → 提取 Server 头、Title 标签
  │       → 识别技术栈 (apache/nginx/php/java/...)
  │       if !s.fingerprint.Matches(fp, fps) {
  │         → 指纹不匹配，跳过
  │         return
  │       }
  │     }
  │
  ├──► OOB 预检查 (可选):
  │     if !s.oobAvailable && job.Kind == JobKindTemplate
  │        && TemplateNeedsOOB(job.Template) {
  │       → OOB 模板但 ceye 未配置，跳过
  │       return
  │     }
  │
  ├──► 创建占位符引擎:
  │     ti = placeholder.ParseTarget(target)
  │       → 解析 URL → TargetInfo {BaseURL, Hostname, Port, Scheme, Path}
  │     eng = placeholder.New(ti, template.Variables)
  │       → 注册内置变量: Hostname, Port, Scheme, Path, baseURL, RootURL
  │       → 解析用户定义的 variables (支持多层依赖解析，最多5轮)
  │     if s.oobAvailable {
  │       eng.SetOOB(oobURL)               → 注入 {{oob}} / {{interactsh-url}}
  │       eng.SetExtracted("oob_label", ...) → 注入 {{oob_label}}
  │       eng.SetExtracted("oob_token", ...) → 注入 {{oob_token}}
  │       eng.SetExtracted("oob_domain", ...) → 注入 {{oob_domain}}
  │     }
  │
  ├──► 根据类型选择执行路径:
  │     │
  │     ├── JobKindPlugin → executePlugin(ctx, plugin, target, ti, eng)
  │     │
  │     ├── Template 且有 workflow → executeWorkflow(ctx, template, target, eng)
  │     │
  │     └── Template 普通 HTTP → executeHTTP(ctx, template, target, eng)
  │
  ├──► 如果 result != nil:
  │     atomic.AddInt64(&s.matched, 1)
  │     results <- result                // 发送结果到通道
  │     logger.InfoKV("matched", ...)
  │
  └──► return
```

### 3.3 HTTP 单模板执行流程 (executeHTTP)

```
executeHTTP(ctx, tmpl, target, eng)
  │
  ├──► 初始化: reqResults=[], evidence=[], allExtracted={}
  │
  └──► for i, req := range tmpl.HTTP {
        │
        ├──► 检查 ctx.Done()
        │
        ├──► 确定超时时间: req.Timeout 或 cfg.DefaultTimeout
        │
        ├──► run-if 条件检查:
        │     if req.RunIf != "" {
        │       val = eng.Replace(req.RunIf)
        │       if val == "" → 跳过 (continue)
        │       if val 包含未解析的 {{...}} → 跳过 (continue)
        │       if val == "false" 或 "0" → 跳过 (continue)
        │     }
        │
        ├──► 构造原始请求:
        │     rawReq = eng.ReplaceWithEscape(req.Raw)
        │     if rawReq == "" && len(req.Path) > 0 {
        │       rawReq = buildRawFromPath(method, path, headers, body)
        │       rawReq = eng.ReplaceWithEscape(rawReq)
        │     }
        │     → $$ 转义为 $ (用于 JNDI 等 payload)
        │
        ├──► 日志: s.logRequest(tmplID, i, rawReq)
        │     → -v: INFO 级别输出方法+路径
        │     → -vv: Burp-style 原始请求包
        │
        ├──► 解析请求: httpclient.ParseRaw(rawReq)
        │
        ├──► 发送请求:
        │     reqCtx, cancel := context.WithTimeout(ctx, timeout)
        │     resp, err := s.client.SendParsed(reqCtx, target, parsed)
        │     cancel()
        │     → 内部: ratelimit.Wait(host) → 限速
        │     → 内部: retry loop (指数退避)
        │     → 内部: doRequest() → http.Client.Do()
        │
        ├──► 日志: s.logResponse(tmplID, i, ...)
        │     → -v: INFO 级别输出状态码+大小+耗时
        │     → -vv: Burp-style 原始响应包
        │
        ├──► 构建匹配上下文:
        │     matchCtx = matcher.NewMatchContext(
        │       statusCode, body, allHeaders, elapsed)
        │     matchCtx.Debug = func(...) { s.debug(...) }  // 注入调试回调
        │
        ├──► 提取变量:
        │     extracted = matcher.Extract(req.Extractors, matchCtx)
        │     tmplExtracted = matcher.Extract(tmpl.Extractors, matchCtx)
        │     for k, v := range extracted {
        │       allExtracted[k] = v
        │       eng.SetExtracted(k, v)  // 存入引擎供后续步骤使用
        │     }
        │
        ├──► 确定 matchers 和 condition:
        │     matchers = req.Matchers (if empty → tmpl.Matchers)
        │     cond = req.MatchersCondition (if empty → tmpl.MatchersCondition)
        │
        ├──► 替换 matcher 中的占位符:
        │     matchers = substituteMatcherPlaceholders(matchers, eng)
        │     → Words/Regex/Header/Binary 中的 {{var}} 被替换
        │     → JSONPath/JSONField 中的 {{var}} 被替换
        │
        ├──► 执行匹配:
        │     matched, ev = matcher.Evaluate(matchers, cond, matchCtx)
        │     → 对每个 matcher 调用 evalSingle()
        │     → 根据 AND/OR 聚合结果
        │
        ├──► 日志: s.logMatcherResult(...)
        │
        ├──► 记录结果:
        │     reqResults = append(reqResults, matched)
        │     if matched && ev != "" { evidence = append(evidence, ev) }
        │
        └──► if (req.StopAtFirstMatch || tmpl.StopAtFirstMatch) && matched { break }
      }
  │
  ├──► 聚合请求级结果:
  │     overallCond = tmpl.MatchersCondition (default: "or")
  │     overallMatched = aggregateMatches(reqResults, overallCond)
  │     → AND: 所有请求都匹配
  │     → OR: 任一请求匹配
  │
  └──► if overallMatched {
        return &types.Result{
          TemplateID, Name, Severity, Description, Target,
          MatchedAt: time.Now().Format(...),
          Tags, Reference,
          Evidence: strings.Join(evidence, "; "),
          Extracted: allExtracted,
        }
      }
      return nil
```

### 3.4 工作流执行流程 (executeWorkflow)

```
executeWorkflow(ctx, tmpl, target, eng)
  │
  └──► wfExec := workflow.New(client, timeout, verbose, debug, verbosef, onRaw, onPacket, logger)
        │
        └──► wfExec.Execute(ctx, tmpl.Workflow, target, eng)
              │
              ├──► topoSort(steps)  // Kahn's 算法拓扑排序
              │     → 构建依赖图: requires → 依赖的前置步骤
              │     → 按依赖顺序确定执行顺序
              │     → 检测循环依赖
              │
              └──► for each step in sorted order {
                      │
                      ├──► 检查 ctx.Done()
                      │
                      ├──► 执行 Delay (秒):
                      │     if step.Delay > 0 {
                      │       select {
                      │       case <-ctx.Done(): return
                      │       case <-time.After(time.Duration(step.Delay) * time.Second):
                      │       }
                      │     }
                      │
                      ├──► executeHTTPBlocks(step.HTTP)
                      │     → 与 executeHTTP 类似，但带有 step 级别日志
                      │     → 提取结果写入 eng
                      │
                      └──► if !stepMatched {
                              if step.StopAtFirstMatch { break }
                              allMatched = false
                            }
                    }
              │
              └──► return allMatched, evidence, extracted
```

### 3.5 Go 插件执行流程 (executePlugin)

```
executePlugin(ctx, plugin, target, ti, eng)
  │
  └──► 构造插件执行上下文:
        pctx := &plugin.Context{
          Target:     target,
          TargetInfo:   ti,                          // 解析后的目标信息
          Client:     s.client,                    // HTTP 客户端 (含代理/限速/重试)
          Eng:        eng,                         // 占位符引擎
          Vars:       make(map[string]string),     // 跨请求共享变量
        }
        if s.oobAvailable {
          pctx.Ceye = plugin.NewCeyeHandle(oobLabel, oobURL, ceyeToken, s.client)
        }
        if s.logger != nil {
          pctx.Log = plugin.NewPluginLogger(plugin.Meta().ID, s.logger)
        }
        pctx.Reporter = plugin.NewPluginReporter(
          plugin.Meta().ID, s.verbose, s.logger, s.onPacket, s.onRaw)

  └──► result, err := plugin.Verify(ctx, pctx)
        │
        │  插件内部典型流程 (以 CVE-2022-22947 为例):
        │  1. 动态生成随机 route_id
        │  2. 构造 SpEL payload
        │  3. POST /actuator/gateway/routes/{id}  → 创建路由
        │  4. POST /actuator/gateway/refresh      → 刷新配置
        │  5. GET  /actuator/gateway/routes/{id}  → 触发 SpEL 求值
        │  6. 检查响应中是否包含 marker
        │  7. DELETE /actuator/gateway/routes/{id} → 清理路由
        │  8. 返回 Result 或 nil
        │
        └──► if err != nil { return nil }
             return result
```

---

## 四、关键组件详细分析

### 4.1 HTTP 客户端 (httpclient)

```
Client
  ├── httpClient: *http.Client
  │     ├── Transport: *http.Transport
  │     │     ├── MaxIdleConns: 200           // 最大空闲连接数
  │     │     ├── MaxIdleConnsPerHost: 20     // 每主机最大空闲连接
  │     │     ├── IdleConnTimeout: 30s        // 空闲连接超时
  │     │     ├── TLSHandshakeTimeout: 10s    // TLS 握手超时
  │     │     ├── ResponseHeaderTimeout: 30s  // 响应头超时
  │     │     └── DialContext: net.Dialer
  │     │           ├── Timeout: max(cfg.Timeout, 30s)  // 至少 30s
  │     │           └── KeepAlive: 30s
  │     ├── CheckRedirect: 重定向控制
  │     │     └── 超过 MaxRedirects 返回 http.ErrUseLastResponse
  │     └── TLSClientConfig: InsecureSkipVerify (默认跳过证书校验)
  │
  ├── limiter: *ratelimit.Limiter
  │     └── per-host token bucket
  │
  ├── maxRetries: 最大重试次数 (默认 2)
  ├── backoff: 退避间隔 (默认 2s，指数增长)
  └── userAgent: 用户代理

方法:
  ├── ParseRaw(raw string) → *RawRequest, error
  │     └─ 解析原始 HTTP 请求文本为结构体
  │
  ├── SendRaw(ctx, baseURL, raw) → *Response, error
  │     └─ 解析 + 发送 (便捷方法)
  │
  └── SendParsed(ctx, baseURL, req) → *Response, error
        │
        ├── limiter.Wait(host)          // 限速阻塞
        │
        └── for attempt = 0..maxRetries {
              ├── 指数退避等待 (attempt > 0)
              ├── doRequest(ctx, baseURL, req)
              │     │
              │     ├── 构建完整 URL:
              │     │     ├─ Case 1: path 是完整 URL → 直接使用
              │     │     ├─ Case 2: Host 头指向不同服务器 → 构造新 URL
              │     │     └─ Case 3: 正常拼接 baseURL + path
              │     │
              │     ├── http.NewRequestWithContext(ctx, method, fullURL, body)
              │     │     └─ 自动设置 Content-Length
              │     │     └─ 保留带点的 header 大小写
              │     │
              │     └── httpClient.Do(httpReq)
              │           └─ 返回 *http.Response
              │
              └── if err == nil: return resp
        }
        return error (所有重试失败)
```

### 4.2 限流器 (ratelimit)

```
Limiter
  ├── mu: sync.Mutex                      // 保护 limiters map
  ├── limiters: map[string]*tokenBucket   // per-host 限速器
  └── rate: int                           // 全局默认速率 (req/s)

方法:
  └── Wait(host string)
        │
        ├── 获取或创建该 host 的 tokenBucket
        │
        └── tb.take()
              │
              └── for {
                    │
                    ├── 按 elapsed 时间补充令牌
                    │     refill = int(elapsed.Seconds() * float64(rate))
                    │     从 lastFill 开始，精确到亚秒级
                    │
                    ├── 尝试从 channel 取出令牌 (非阻塞)
                    │     select {
                    │     case <-tb.tokens: return   // 成功
                    │     default:
                    │       time.Sleep(interval)      // 等待后重试
                    │     }
                    │
                    └── 循环直到拿到令牌
              }
```

### 4.3 匹配引擎 (matcher)

```
Evaluate(matchers []Matcher, condition string, ctx *MatchContext) (matched bool, evidence string)
  │
  ├── condition == "and" → 所有 matcher 都匹配
  └── condition == "or"  → 任一 matcher 匹配

evalSingle(m Matcher, ctx *MatchContext) (matched bool, evidence string)
  │
  └── switch m.Type {
        │
        ├── "status"     → matchStatus(m, ctx)
        │                  检查 StatusCode 是否在 Status 列表中
        │
        ├── "word"       → matchWord(m, ctx)
        │                  在 Body/Header/All 中做子串匹配
        │                  支持 CaseInsensitive
        │                  支持 AND/OR 条件
        │
        ├── "regex"      → matchRegex(m, ctx)
        │                  编译缓存 (cachedCompile)
        │                  支持 (?i) 前缀 (大小写不敏感)
        │
        ├── "header"     → matchHeader(m, ctx)
        │                  在响应头中匹配
        │
        ├── "size"       → matchSize(m, ctx)
        │                  支持 >/</==/>=/<=/!= 操作符
        │                  比较 ContentSize (body 长度)
        │
        ├── "time"       → matchTime(m, ctx)
        │                  比较 ResponseTime (秒)
        │
        ├── "binary"     → matchBinary(m, ctx)
        │                  Hex 解码后在响应中搜索字节序列
        │
        ├── "dsl"        → evalDSLs(m.DSL, ctx)
        │                  DSL 表达式引擎
        │
        └── "json-word"  → matchJSONWord(m, ctx)
                           JSON 解析 → 数组字段匹配 (OOB 专用)
                           默认大小写不敏感
        │
        └── Apply Negative: if m.Negative → matched = !matched
      }
```

### 4.4 DSL 表达式引擎

```
evalDSL(expr string, ctx *MatchContext) (bool, error)
  │
  └── recursive descent parser:
        │
        ├── parseOr()           ← || 最低优先级
        │     └── parseAnd()    ← &&
        │           └── parseNot() ← !
        │                 └── parsePrimary()
        │                       ├── (expr)  → 括号表达式
        │                       ├── len(var) > N  → 特殊: 数值比较
        │                       ├── func(arg) → 函数调用
        │                       │     ├── contains / contains_any / contains_all
        │                       │     ├── equals / regex / starts_with / ends_with
        │                       │     └── to_lower_contains
        │                       └── var op value → 变量比较
        │                             ├── 数值比较 (ParseFloat)
        │                             └── 字符串比较
        │
        └── 校验尾随输入 (防止 "status_code == 200 garbage")
```

### 4.5 占位符引擎 (placeholder)

```
Engine
  ├── vars: map[string]string         // 变量作用域
  ├── extracted: map[string]string    // extractor 结果
  ├── target: *TargetInfo             // 目标 URL 信息
  └── escapeDollar: bool              // $$ 转义标记

方法:
  ├── Replace(s string) string
  │     └─ 正则匹配 {{...}} 并替换
  │
  ├── ReplaceWithEscape(s string) string
  │     └─ 先替换 $$ → \x00DOLLAR\x00，再替换占位符，最后还原 $
  │
  └── resolve(expr string) string
        │
        ├── 1. 函数调用: func(args)
        │     ├── randstr / rand_int / rand_text_alpha / rand_text_hex
        │     ├── to_upper / to_lower / trim / reverse / concat / repeat
        │     ├── base64_encode / base64_decode
        │     ├── url_encode / url_decode
        │     ├── hex_encode / hex_decode
        │     ├── md5 / sha1 / sha256
        │     ├── timestamp / date
        │     └── uuid
        │
        ├── 2. 裸函数: randstr == randstr()
        │
        ├── 3. vars map (用户变量 / 静态占位符)
        │     ├── Hostname / Host / Port / Scheme / Path
        │     ├── baseURL / RootURL
        │     ├── oob / interactsh-url (OOB)
        │     ├── oob_label / oob_token / oob_domain
        │     └─ 用户定义的 variables
        │
        ├── 4. extracted map (extractor 结果)
        │
        └── 5. 未识别 → 返回 "{{expr}}" (保留占位符)
```

### 4.6 指纹探测 (fingerprint)

```
Detector
  ├── client: *httpclient.Client
  └── cache: sync.Map  // target → *TargetFingerprint

方法:
  └── Detect(ctx, target) *TargetFingerprint
        │
        ├── 检查缓存
        │
        └── 发送 GET / 探测请求
              │
              ├── 提取 Server 头 → fp.Server
              ├── 提取 <title> 标签 → fp.Titles
              ├── 识别技术栈:
              │     ├── Server 头包含 apache/nginx/tomcat/iis → TechStack
              │     ├── Title 包含 php → TechStack["php"]
              │     ├── x-powered-by 包含 php/asp → TechStack
              │     ├── set-cookie 包含 phpsessid/jsessionid → TechStack
              │     └── wordpress/joomla → TechStack
              │
              └── 缓存并返回

  Matches(fp, rules []FingerprintRule) bool
    └── 遍历规则，任一规则匹配即返回 true
          ├── Title 匹配: fp.Titles 包含 rule.Title（子串，大小写不敏感）
          ├── Body 匹配: fp.Body 包含 rule.Body（子串，大小写不敏感）
          └── Header 匹配: fp.Headers[key] 包含 pattern（支持格式 A/B）
```

### 4.7 OOB 验证 (plugin/helpers.go)

```
ceyeHandle 实现 OOBHandle 接口
  ├── Label() string       → 返回 oobLabel (如 "gs-a1b2c3d4")
  ├── URL() string         → 返回 oobURL (如 "gs-a1b2c3d4.foo.ceye.io")
  ├── VerifyDNS(ctx)       → 查询 ceye DNS 记录
  └── VerifyHTTP(ctx)      → 查询 ceye HTTP 记录

verifyRecords(ctx, recordType) (bool, error)
  │
  ├── 构造请求: GET /v1/records?token={token}&type={dns|http}
  ├── Host: api.ceye.io
  ├── 发送请求到 http://api.ceye.io
  ├── 解析 JSON 响应: {"data": [{"name": "..."}, ...]}
  └── 检查是否有记录的 name 包含 label (大小写不敏感)
```

### 4.8 输出系统

```
Console (控制台输出)
  ├── 3 级 verbosity:
  │     -1 (silent): 仅输出命中结果卡片
  │      0 (default): Banner/配置/模板加载/扫描起止/结果卡片
  │      1 (-v): INFO 行 (请求摘要/响应摘要/匹配结果/跳过原因)
  │      2 (-vv): DEBUG 行 (完整请求/响应/匹配详情)
  │
  ├── pLine(tag, levelMin, format, args...)
  │     → 带时间戳 + 彩色标签的统一输出格式
  │
  └── 主要方法:
        ├── PrintBanner(version)
        ├── PrintDisclaimer()
        ├── PrintScanConfig(info)
        ├── PrintTemplatesLoaded(count, dir)
        ├── PrintScanStart(targets, templates)
        ├── PrintProgress(completed, total, msg)
        ├── PrintResult(result)           // 结果卡片
        ├── PrintScanEnd(total, matched)   // 扫描汇总
        ├── PrintVulnSummary(results)      // 漏洞汇总表（表格形式）
        └── PrintWarning/Error/Info/Verb/Debug

Logger (结构化日志)
  ├── 基于 slog (标准库日志)
  ├── ptermHandler: 将 slog 记录渲染为彩色控制台输出
  ├── dualHandler: 同时输出到 console + JSON 文件
  └── 动态级别调整: SetMinLevel()

WriteFile (文件输出)
  ├── writeJSON() → JSON 格式
  ├── writeTXT()  → 纯文本格式
  └── writeSARIF() → SARIF 2.1.0 格式 (CI/IDE 集成)
```

---

## 五、包间依赖关系图

```
cmd/gosleek
    │
    ├── internal/config
    ├── internal/engine
    │     ├── internal/httpclient
    │     │     └── internal/ratelimit
    │     ├── internal/fingerprint
    │     │     └── internal/httpclient
    │     ├── internal/matcher
    │     │     └── internal/utils
    │     ├── internal/placeholder
    │     ├── internal/plugin
    │     │     ├── internal/httpclient
    │     │     └── internal/placeholder
    │     ├── internal/workflow
    │     │     ├── internal/httpclient
    │     │     ├── internal/matcher
    │     │     └── internal/placeholder
    │     └── internal/utils
    ├── internal/output
    │     └── internal/utils
    ├── internal/template
    │     └── pkg/types
    └── plugins (各插件包)
          ├── internal/plugin
          ├── internal/placeholder
          └── internal/utils

pkg/types
    └── (无内部依赖, 纯数据结构)
```

---

## 六、关键设计模式

| 模式 | 应用位置 | 说明 |
|------|----------|------|
| **观察者模式** | engine.SetCallbacks | 引擎通过回调将结果/进度/日志传递给输出层 |
| **策略模式** | matcher evalSingle | 9 种 matcher 类型通过 switch 分发到不同实现 |
| **工厂模式** | plugin.Register | 插件通过 init() 自动注册到全局 registry |
| **模板方法** | engine.runJob | 统一的执行框架，子类(插件/模板)填充具体逻辑 |
| **责任链** | workflow steps | 工作流步骤按依赖顺序依次执行 |
| **令牌桶** | ratelimit.Limiter | per-host 独立限速，精确到亚秒级 |
| **生产者-消费者** | jobs/results channels | worker 消费 jobs，collector 消费 results |
| **上下文传播** | context.Context | 贯穿整个调用链，支持超时和取消 |

---

## 七、并发安全设计

| 组件 | 同步机制 | 说明 |
|------|----------|------|
| dedup map | sync.Map | 线程安全的 (target|templateID) → bool 映射 |
| 统计计数器 | atomic int64 | completed/matched/total 使用 atomic 操作 |
| console 输出 | sync.Mutex | 防止多 goroutine 同时写终端导致交错 |
| regex 缓存 | sync.RWMutex | 多读单写，高性能缓存已编译的正则 |
| plugin registry | sync.RWMutex | 多读单写，保证插件注册安全 |
| placeholder engine | sync.RWMutex | 多读单写，变量作用域线程安全 |

---

## 八、测试覆盖现状

| 包 | 覆盖率 | 状态 |
|----|--------|------|
| internal/utils | 100% | ✅ 完整 |
| internal/ratelimit | 96.8% | ✅ 完整 |
| internal/config | 58.6% | ⚠️ 基本覆盖 |
| internal/matcher | 69.0% | ⚠️ 核心逻辑覆盖 |
| internal/placeholder | 58.8% | ⚠️ 基本覆盖 |
| internal/template | 20.8% | ⚠️ 加载逻辑有测试 |
| internal/workflow | 9.6% | ❌ 覆盖不足 |
| internal/engine | 0% | ❌ 无测试 |
| internal/httpclient | 0% | ❌ 无测试 |
| internal/fingerprint | 100% | ✅ 完整测试 |
| internal/output | 0% | ❌ 无测试 |
| internal/plugin | 0% | ❌ 无测试 |

---

## 九、扩展指南

### 9.1 新增 YAML 模板

1. 在 `templates/` 目录创建 `.yaml` 文件
2. 填写必填字段: id, name, description, severity, http
3. 定义 matchers 匹配规则
4. (可选) 定义 extractors 提取变量
5. (可选) 定义 workflow 多步工作流
6. 使用 `gosleek validate templates/` 校验语法
7. 使用 `gosleek scan -t <target>` 扫描

### 9.2 新增 Go 插件

1. 在 `plugins/` 目录创建新子包
2. 实现 `plugin.Plugin` 接口:
   ```go
   func init() { plugin.Register(&MyPlugin{}) }
   func (p *MyPlugin) Meta() types.TemplateMeta { ... }
   func (p *MyPlugin) Fingerprints() []types.FingerprintRule { ... }
   func (p *MyPlugin) Verify(ctx context.Context, pctx *plugin.Context) (*types.Result, error) { ... }
   ```
3. 在 `plugins/init.go` 中导入新包
4. 编译后使用 `gosleek list` 确认加载
5. 使用 `gosleek scan -t <target> --plugin <id>` 测试

---

## 十、总结

Go-Sleek-T 采用**分层架构**，核心流程为：

```
参数解析 → 配置加载 → 模板/插件加载 → 引擎调度 → 并发执行 → 结果收集 → 输出
```

**扩展性设计**：
- YAML 模板：新增漏洞只需添加 `.yaml` 文件
- Go 插件：新增漏洞只需实现 `plugin.Plugin` 接口
- 两者在引擎中地位对等，共享相同的执行框架和输出机制

**核心优势**：
- 模块化设计，各组件职责清晰
- 并发安全，使用 atomic 和 sync 原语
- 可扩展性强，模板和插件可独立开发
- 丰富的匹配能力，支持 9 种 matcher 类型和 DSL 表达式
- 完善的输出系统，支持 JSON/TXT/SARIF 和结构化日志
