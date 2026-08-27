# Gosleek 优化计划

> 制定日期：2026-08-17
> 目标：增强 YAML 模板引擎能力，长期支持 WASM 插件

---

## 一、现状分析

### 1.1 当前能力边界

| 能力 | 当前状态 | 问题 |
|------|----------|------|
| 变量定义 | `variables` 模板级 | 仅静态值，不支持从 extractor 引用 |
| 变量传递 | 同模板内传递 | workflow 步骤间可传递，但 limited |
| 条件执行 | `run-if` | 仅检查非空，不支持表达式 |
| 自定义函数 | 内置函数固定 | 无法扩展 |
| 控制流 | 无 if/else | 无法实现条件分支 |
| 循环迭代 | 无 range | 无法实现循环 |

### 1.2 测试覆盖现状

| 包 | 覆盖率 | 状态 |
|----|--------|------|
| internal/engine | 0% | ❌ 无测试 |
| internal/workflow | 5.1% | ❌ 覆盖不足 |
| internal/template | 13.3% | ⚠️ 基本覆盖 |
| internal/matcher | 67.7% | ✅ 核心覆盖 |
| internal/placeholder | 58.9% | ⚠️ 基本覆盖 |

### 1.3 需要解决的问题

1. **变量作用域问题**：`variables` 中的值无法引用 extractor 的结果
2. **条件执行问题**：`run-if` 只支持简单的非空检查
3. **扩展性问题**：无法注册自定义函数
4. **测试缺失**：engine 和 workflow 缺乏测试

---

## 二、优化计划

### 阶段一：基础增强（1-2周）

#### 1.1 变量系统增强

**目标**：支持变量从 extractor 引用

**当前问题**：
```yaml
variables:
  route_id: "{{rand_text_alpha(8)}}"  # 静态值，无法引用 extractor
```

**改进方案**：
```yaml
variables:
  route_id: "{{rand_text_alpha(8)}}"      # 支持内置函数
  extracted_token: "{{jwt_token}}"        # 支持引用 extractor 结果
  dynamic_value: "{{step1_status_code}}" # 支持引用前一步结果
```

**实现步骤**：
1. 修改 `placeholder.Engine` 支持延迟解析
2. 在 `engine.go` 中增加变量重解析逻辑
3. 修改 `validate.go` 增加变量引用校验

**代码修改**：
- `internal/placeholder/engine.go`：增加 `ResolveLater()` 方法
- `internal/engine/engine.go`：在 extractor 执行后重解析变量
- `internal/template/validate.go`：增加变量引用校验

**测试**：
- 新增 `internal/placeholder/engine_test.go` 测试延迟解析
- 新增 `internal/engine/variable_test.go` 测试变量传递

---

#### 1.2 run-if 表达式增强

**目标**：支持 DSL 表达式作为 run-if 条件

**当前问题**：
```yaml
run-if: "{{status_code} == 200}"  # 实际只检查非空
```

**改进方案**：
```yaml
run-if: "status_code == 200"        # 支持 DSL 表达式
run-if: "contains(body, 'admin')"   # 支持函数调用
run-if: "len(body) > 100"           # 支持数值比较
```

**实现步骤**：
1. 修改 `evalRunIf()` 函数，使用 DSL 引擎解析
2. 复用 `internal/matcher/dsl.go` 的解析逻辑
3. 增加错误处理：语法错误时跳过请求

**代码修改**：
- `internal/engine/engine.go`：修改 `evalRunIf()` 使用 DSL 引擎
- 新增 `internal/engine/runif_test.go`

**测试**：
```go
func TestRunIfDSLExpression(t *testing.T) {
    // 测试各种 DSL 表达式
}
```

---

#### 1.3 自定义函数注册

**目标**：允许用户注册自定义函数

**当前问题**：
```go
// 函数硬编码在 placeholder/engine.go
func (e *Engine) resolveFunc(name string, args []string) string {
    switch name {
    case "randstr": ...
    case "md5": ...
    // 无法扩展
    }
}
```

**改进方案**：
```go
// 支持自定义函数注册
eng.RegisterFunction("my_func", func(args ...string) string {
    return strings.ToUpper(args[0])
})

// 模板中使用
variables:
  upper_name: "{{my_func('hello')}}"
```

**实现步骤**：
1. 在 `placeholder.Engine` 中增加 `functions map[string]Func`
2. 添加 `RegisterFunction(name string, fn func(...string) string)` 方法
3. 修改 `resolveFunc()` 支持自定义函数
4. 提供 CLI 接口注册函数（可选）

**代码修改**：
- `internal/placeholder/engine.go`：增加函数注册机制
- `internal/placeholder/engine_test.go`：增加测试

**测试**：
```go
func TestCustomFunction(t *testing.T) {
    eng := placeholder.New(...)
    eng.RegisterFunction("double", func(args ...string) string {
        return args[0] + args[0]
    })
    result := eng.Replace("{{double('ab')}}")
    if result != "abab" {
        t.Errorf("expected 'abab', got '%s'", result)
    }
}
```

---

### 阶段二：控制流增强（2-3周）

#### 2.1 条件分支（if/else）

**目标**：支持模板级条件分支

**改进方案**：
```yaml
http:
  - raw: |...
    matchers:
      - type: status
        status: [200]

  # 条件执行
  - raw: |...
    run-if: "status_code == 200 && contains(body, 'admin')"
    matchers:
      - type: word
        words: ["dashboard"]

  - raw: |...
    run-if: "status_code == 403"
    matchers:
      - type: word
        words: ["forbidden"]
```

**实现步骤**：
1. 增强 `run-if` 支持更复杂的 DSL 表达式
2. 支持逻辑运算符：`&&`、`||`、`!`
3. 支持比较运算符：`==`、`!=`、`>`、`<`、`>=`、`<=`

**代码修改**：
- `internal/matcher/dsl.go`：增强表达式解析
- `internal/engine/engine.go`：增强 `evalRunIf()`

**测试**：
```go
func TestRunIfComplexExpression(t *testing.T) {
    tests := []struct {
        expr string
        ctx  *MatchContext
        want bool
    }{
        {"status_code == 200", &MatchContext{StatusCode: 200}, true},
        {"status_code == 200 && contains(body, 'admin')", &MatchContext{StatusCode: 200, Body: "admin panel"}, true},
        {"!contains(body, 'error')", &MatchContext{Body: "success"}, true},
    }
    for _, tt := range tests {
        got := evalRunIf(tt.expr, tt.ctx)
        if got != tt.want {
            t.Errorf("evalRunIf(%q) = %v, want %v", tt.expr, got, tt.want)
        }
    }
}
```

---

#### 2.2 变量作用域增强

**目标**：支持跨步骤变量引用

**当前问题**：
```yaml
workflow:
  - name: step1
    http:
      - raw: |...
        extractors:
          - name: token
            type: regex
            regex: ['"token":"([^"]+)"']

  - name: step2
    http:
      - raw: |...
        # 无法引用 step1 的 token
```

**改进方案**：
```yaml
workflow:
  - name: step1
    http:
      - raw: |...
        extractors:
          - name: token
            type: regex
            regex: ['"token":"([^"]+)"']

  - name: step2
    http:
      - raw: |...
        # 可以引用 step1 提取的 token
        Authorization: Bearer {{token}}
```

**实现步骤**：
1. 修改 `workflow.Executor` 传递 extracted 变量
2. 确保 `eng.SetExtracted()` 在步骤间持久化
3. 增加变量作用域检查

**代码修改**：
- `internal/workflow/workflow.go`：增强变量传递
- `internal/engine/engine.go`：统一变量作用域

**测试**：
```go
func TestWorkflowVariablePassing(t *testing.T) {
    // 测试跨步骤变量传递
}
```

---

### 阶段三：测试完善（1-2周）

#### 3.1 增加 Engine 测试

**目标**：覆盖核心执行逻辑

**测试用例**：
```go
// internal/engine/engine_test.go

func TestExecuteHTTP(t *testing.T) {
    // 测试单模板执行
}

func TestExecuteWorkflow(t *testing.T) {
    // 测试工作流执行
}

func TestVariablePassing(t *testing.T) {
    // 测试变量传递
}

func TestRunIfCondition(t *testing.T) {
    // 测试条件执行
}
```

**目标覆盖率**：engine 包 60%+

---

#### 3.2 增加 Workflow 测试

**目标**：覆盖工作流执行逻辑

**测试用例**：
```go
// internal/workflow/workflow_test.go

func TestTopoSort(t *testing.T) {
    // 测试拓扑排序
}

func TestProviderSkip(t *testing.T) {
    // 测试 provider 跳过
}

func TestVariablePropagation(t *testing.T) {
    // 测试变量传递
}
```

**目标覆盖率**：workflow 包 50%+

---

### 阶段四：WASM 插件探索（长期，可选）

#### 4.1 WASM 运行时集成

**目标**：支持跨平台 WASM 插件

**技术方案**：
```go
// 引入 wasmtime 或 wasmer
import "github.com/wasmtime/wasmtime-go"

// 加载 WASM 插件
store := wasmtime.NewStore(engine)
module, _ := wasmtime.NewModule(engine, wasmBytes)
instance, _ := wasmtime.NewInstance(store, module, imports)

// 调用插件函数
result, _ := instance.exports["verify"].Func().Call(store, target, options)
```

**实现步骤**：
1. 选择 WASM 运行时（wasmtime 或 wasmer）
2. 定义插件接口（WASM export）
3. 实现插件加载器
4. 添加安全沙箱

**代码结构**：
```
internal/wasm/
├── loader.go      # WASM 加载器
├── plugin.go      # 插件接口定义
└── sandbox.go     # 沙箱实现
```

**测试**：
```go
func TestWasmPlugin(t *testing.T) {
    // 测试 WASM 插件加载和执行
}
```

---

## 三、实施顺序

```
阶段一（基础增强）
├── 1.1 变量系统增强（2天）
├── 1.2 run-if 表达式增强（1天）
├── 1.3 自定义函数注册（2天）
└── 测试完善（2天）

阶段二（控制流增强）
├── 2.1 条件分支（3天）
├── 2.2 变量作用域增强（2天）
└── 测试完善（2天）

阶段三（测试完善）
├── 3.1 Engine 测试（3天）
└── 3.2 Workflow 测试（2天）

阶段四（WASM 探索，可选）
├── 4.1 WASM 运行时集成（1周）
└── 4.2 安全沙箱（1周）
```

**总计**：约 4-6 周

---

## 四、验收标准

### 4.1 功能验收

- [ ] 变量支持从 extractor 引用
- [ ] run-if 支持 DSL 表达式
- [ ] 支持自定义函数注册
- [ ] 变量跨步骤传递正常
- [ ] 条件分支正常工作

### 4.2 测试验收

- [ ] engine 包覆盖率 60%+
- [ ] workflow 包覆盖率 50%+
- [ ] placeholder 包覆盖率 80%+
- [ ] matcher 包覆盖率 80%+
- [ ] 所有现有测试通过

### 4.3 文档验收

- [ ] 更新 YAML 模板开发手册
- [ ] 添加变量引用示例
- [ ] 添加 run-if 表达式示例
- [ ] 添加自定义函数示例

---

## 五、风险与缓解

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| 变量解析顺序问题 | 中 | 增加多轮解析，最多 5 轮 |
| DSL 表达式语法错误 | 低 | 捕获错误，输出 warning |
| 自定义函数性能 | 低 | 限制函数执行时间 |
| WASM 兼容性 | 高 | 仅作为可选功能，默认关闭 |

---

## 六、后续优化方向

1. **性能优化**：变量缓存、表达式编译缓存
2. **调试支持**：增加变量调试输出（`-vv` 级别）
3. **插件市场**：建立社区插件分享机制
4. **WASM 插件**：长期支持跨平台动态加载

---

*计划版本：v1.0*
*最后更新：2026-08-17*
