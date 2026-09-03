# -*- coding: utf-8 -*-
import sys

path = r'C:\Users\lenovo\Desktop\go-sleek-s\docs\gosleek-plugin-development-guide.md'
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

# Check if already updated
if '19. 插件生命周期' in content:
    print('Already updated')
    sys.exit(0)

# Remove old footer
content = content.replace('*文档版本 v1.6.0 — 2026-08-31*', '')
content = content.replace('*文档版本 v1.3.1 — 2026-08-17*', '')

new_section = r'''
---

## 19. 插件生命周期：PreRun 与 PostRun

### 19.1 生命周期流程

插件执行有三个阶段：

1. **PreRun(ctx, pctx)** - 在 Verify 之前调用，返回 error 则跳过 Verify
2. **Verify(ctx, pctx)** - 核心检测逻辑
3. **PostRun(ctx, pctx)** - 在 Verify 之后调用，无论成功失败

### 19.2 PreRun 典型用途

- 登录获取认证 token
- 提取 CSRF token
- 初始化连接池

```go
func (p *Plugin) PreRun(ctx context.Context, pctx *plugin.Context) error {
    resp, err := pctx.Client.SendRaw(ctx, pctx.Target, loginRequest)
    if err != nil { return err }
    pctx.Vars["token"] = extractToken(resp.Body)
    return nil
}
```

### 19.3 PostRun 典型用途

- 退出登录
- 关闭连接
- 清理临时资源

```go
func (p *Plugin) PostRun(ctx context.Context, pctx *plugin.Context) {
    // 清理逻辑
}
```

### 19.4 新功能集成

| 功能 | 插件是否需要额外代码 |
|------|:------------------:|
| Web UI 结果展示 | 不需要，自动集成 |
| 报告生成 | 不需要，确保返回 RawRequest/RawResponse |
| AI 辅助分析 | 不需要，编程方式调用 ai.Provider |
| 分布式扫描 | 不需要，Worker 自动执行 |
| PreRun 登录 | 需要实现 |
| PostRun 清理 | 需要实现 |

---

## 20. 完整示例：带认证的认证绕过检测插件

```go
package auth_bypass

import (
    "context"
    "fmt"
    "strings"
    "github.com/gosleek/gosleek/internal/plugin"
    "github.com/gosleek/gosleek/pkg/types"
)

type AuthBypassPlugin struct{}

func init() { plugin.Register(&AuthBypassPlugin{}) }

func (p *AuthBypassPlugin) Meta() types.TemplateMeta {
    return types.TemplateMeta{ID: "auth-bypass", Name: "认证绕过测试", Severity: types.SeverityHigh, Tags: []string{"auth"}}
}
func (p *AuthBypassPlugin) Fingerprints() []types.FingerprintRule { return nil }

// PreRun: 登录获取 token
func (p *AuthBypassPlugin) PreRun(ctx context.Context, pctx *plugin.Context) error {
    loginReq := fmt.Sprintf("POST /api/login HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\n\r\n{\"user\":\"admin\",\"pass\":\"admin123\"}", pctx.TargetInfo.Hostname)
    resp, err := pctx.Client.SendRaw(ctx, pctx.Target, loginReq)
    if err != nil { return err }
    token := extractToken(resp.Body)
    if token == "" { return fmt.Errorf("未获取到 token") }
    pctx.Vars["auth_token"] = token
    return nil
}

// Verify: 检测认证绕过
func (p *AuthBypassPlugin) Verify(ctx context.Context, pctx *plugin.Context) (*types.Result, error) {
    noTokenReq := fmt.Sprintf("GET /api/admin HTTP/1.1\r\nHost: %s\r\n\r\n", pctx.TargetInfo.Hostname)
    resp, err := pctx.Client.SendRaw(ctx, pctx.Target, noTokenReq)
    if err != nil { return nil, nil }
    if resp.StatusCode == 200 && !strings.Contains(resp.Body, "401") && !strings.Contains(resp.Body, "403") {
        return &types.Result{
            TemplateID: p.Meta().ID, Name: p.Meta().Name, Severity: p.Meta().Severity,
            Target: pctx.Target, Evidence: fmt.Sprintf("未认证即可访问管理接口, status=%d", resp.StatusCode),
            RawRequest: noTokenReq, RawResponse: resp.Raw,
        }, nil
    }
    return nil, nil
}

// PostRun: 清理会话
func (p *AuthBypassPlugin) PostRun(ctx context.Context, pctx *plugin.Context) {
    token := pctx.Vars["auth_token"]
    if token != "" {
        logoutReq := fmt.Sprintf("POST /api/logout HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\n\r\n", pctx.TargetInfo.Hostname, token)
        pctx.Client.SendRaw(ctx, pctx.Target, logoutReq)
    }
}

func extractToken(body string) string {
    for _, line := range strings.Split(body, "\n") {
        if strings.Contains(line, "token") {
            parts := strings.SplitN(line, ":", 2)
            if len(parts) == 2 { return strings.TrimSpace(parts[1]) }
        }
    }
    return ""
}
```

---

*文档版本 v1.6.0 — 2026-08-31*
'''

content = content + new_section

with open(path, 'w', encoding='utf-8') as f:
    f.write(content)
print('Done')
