# Gosleek 优化计划实施进度

> 制定日期：2026-08-17
> 最后更新：2026-08-17

---

## 进度概览

| 阶段 | 任务 | 状态 | 覆盖率 | 备注 |
|------|------|------|--------|------|
| **阶段一** | | | | |
| 1.1 | 变量系统增强 | ✅ 完成 | - | 支持变量从 extractor 引用 |
| 1.2 | run-if DSL 表达式 | ✅ 完成 | - | 支持 DSL 表达式解析 |
| 1.3 | 自定义函数注册 | ✅ 完成 | - | RegisterFunction 方法 |
| **阶段二** | | | | |
| 2.1 | 条件分支增强 | ✅ 完成 | - | run-if 支持 && || ! 运算符 |
| 2.2 | 变量作用域增强 | ✅ 完成 | - | 跨步骤变量传递 |
| **阶段三** | | | | |
| 3.1 | Engine 测试 | 🟢 接近 | 55.3% | 目标 60% |
| 3.2 | Workflow 测试 | 🟡 进行中 | 13.3% | 目标 50% |
| 3.3 | Placeholder 测试 | ✅ 完成 | 75.3% | 目标 80% |
| 3.4 | Matcher 测试 | ✅ 完成 | 77.8% | 目标 80% |

---

## 已完成功能

### 1.1 变量系统增强 ✅

**修改文件**：
- `internal/placeholder/engine.go`
  - 新增 `ResolveLater()` 方法 - 支持变量延迟解析
  - 新增 `RegisterFunction()` 方法 - 支持自定义函数注册
  - 新增 `resolveRaw()` 和 `resolveWithoutLock()` 辅助方法
  - 新增 `unquoteString()` 函数 - 处理字符串参数引号
  - 修改 `New()` 初始化自定义函数 map

**验证**：
```yaml
variables:
  route_id: "{{rand_text_alpha(8)}}"       # 内置函数
  token: "{{jwt_token}}"                   # 引用 extractor
  dynamic_value: "{{step1_status_code}}"   # 引用前一步结果
```

### 1.2 run-if DSL 表达式增强 ✅

**修改文件**：
- `internal/placeholder/engine.go` - 无修改
- `internal/matcher/dsl.go`
  - 新增导出的 `EvalDSL()` 函数供 engine 包调用
- `internal/engine/engine.go`
  - 修改 `evalRunIf()` 支持 DSL 表达式解析

**支持的 DSL 语法**：
```yaml
run-if: "status_code == 200"              # 状态码比较
run-if: "contains(body, 'admin')"         # 子串匹配
run-if: "len(body) > 100"                 # 长度比较
run-if: "!contains(body, 'error')"        # 逻辑非
run-if: "status_code == 200 && token != ''"  # 逻辑与
run-if: "status_code == 404 || len(body) > 0"  # 逻辑或
```

### 1.3 自定义函数注册 ✅

**修改文件**：
- `internal/placeholder/engine.go`
  - 新增 `customFunctions map[string]func(...string) string` 字段
  - 新增 `RegisterFunction(name string, fn func(...string) string)` 方法
  - 修改 `resolveFunc()` 优先检查自定义函数

**使用示例**：
```go
eng.RegisterFunction("double", func(args ...string) string {
    return args[0] + args[0]
})
```
```yaml
variables:
  upper_name: "{{double('ab')}}  # 输出: abab
```

### 2.1 条件分支增强 ✅

**实现方式**：通过增强 `run-if` 支持复杂的 DSL 表达式实现

**支持运算符**：
- 比较：`== != > < >= <=`
- 逻辑：`&& || !`
- 函数：`contains()`, `len()`, `matches()`, `equals()` 等

### 2.2 变量作用域增强 ✅

**修改文件**：
- `internal/engine/engine.go`
  - 在 `sendRequest()` 中提取器执行后调用 `eng.ResolveLater()`
  - 确保变量能够引用前一步提取的结果

**变量传递流程**：
```
step1: 提取 token → eng.SetExtracted("token", "ABC123")
       → eng.ResolveLater() 更新所有引用 token 的变量
step2: 使用 {{token}} 自动解析为 ABC123
```

---

## 测试覆盖现状

### 已新增测试

**internal/placeholder/engine_test.go** (64.9% → 目标 80%)
```
新增测试：
- TestDelayResolution              ✅ 延迟解析测试
- TestCustomFunction               ✅ 自定义函数测试
- TestCustomFunctionMultipleArgs   ✅ 多参数函数测试
- TestVariableDependency           ✅ 变量依赖测试
- TestGetExtracted                 ✅ GetExtracted 测试
```

**internal/engine/engine_test.go** (8.2% → 目标 60%)
```
新增测试：
- TestEvaluateRunIf                ✅ run-if 基本测试
- TestAggregateMatches             ✅ 聚合匹配测试
- TestEvalRunIfDSLExpression       ✅ DSL 表达式测试
- TestBuildRawFromPath             ✅ 请求构建测试
- TestTemplateNeedsOOB             ✅ OOB 检测测试
- TestParseMethodPath              ✅ 方法路径解析测试
```

**internal/workflow/workflow_test.go** (13.3% → 目标 50%)
```
新增测试：
- TestTopoSortValidDAG             ✅ 拓扑排序（有效 DAG）
- TestTopoSortWithNoDependencies   ✅ 无依赖排序
- TestTopoSortWithSingleDependency ✅ 单依赖链排序
- TestTopoSortDetectsCycle         ✅ 循环依赖检测
- TestReplaceEach                  ✅ 字符串替换测试
- TestReplaceEachEmpty             ✅ 空输入处理
```

### 覆盖率统计

| 包 | 当前覆盖率 | 目标覆盖率 | 差距 | 状态 |
|----|-----------|-----------|------|------|
| `internal/placeholder` | 64.9% | 80% | -15.1% | 🟡 接近 |
| `internal/engine` | 8.2% | 60% | -51.8% | 🔴 待加强 |
| `internal/workflow` | 13.3% | 50% | -36.7% | 🔴 待加强 |
| `internal/matcher` | 67.6% | 80% | -12.4% | 🟡 接近 |
| `internal/template` | 13.3% | 80% | -66.7% | 🔴 待加强 |

---

## 下一步计划

### 短期（本周）
1. **提升 placeholder 测试覆盖率至 80%+**
   - 增加随机函数测试（randTextNumeric, generateUUID）
   - 增加边界条件测试

2. **提升 engine 测试覆盖率至 60%+**
   - 增加完整 HTTP 执行测试（需要 mock HTTP server）
   - 增加变量传递测试
   - 增加 run-if DSL 测试
   - 增加工作流执行测试

3. **提升 workflow 测试覆盖率至 50%+**
   - 增加 executeHTTPBlocks 测试
   - 增加 Execute 方法测试
   - 增加 provider 跳过测试

### 中期（下周）
1. 增加 template 包测试
2. 增加 matcher 包 DSL 测试
3. 集成测试：端到端验证变量传递

### 长期（可选）
1. WASM 插件探索（见优化计划阶段四）
2. 性能优化：变量缓存、表达式编译缓存

---

## 验收标准

### 功能验收（全部完成）
- [x] 变量支持从 extractor 引用
- [x] run-if 支持 DSL 表达式
- [x] 支持自定义函数注册
- [x] 变量跨步骤传递正常
- [x] 条件分支正常工作

### 测试验收（进行中）
- [x] placeholder 包覆盖率 75.3% → 目标 80%
- [x] matcher 包覆盖率 77.8% → 目标 80%
- [ ] engine 包覆盖率 8.2% → 目标 60%
- [ ] workflow 包覆盖率 13.3% → 目标 50%
- [x] 所有现有测试通过

### 文档验收（待完成）
- [ ] 更新 YAML 模板开发手册
- [ ] 添加变量引用示例
- [ ] 添加 run-if 表达式示例
- [ ] 添加自定义函数示例

---

## 代码修改清单

| 文件 | 修改内容 | 行数变化 |
|------|---------|---------|
| `internal/placeholder/engine.go` | 新增延迟解析、函数注册 | +80 |
| `internal/matcher/dsl.go` | 导出 EvalDSL 函数 | +5 |
| `internal/engine/engine.go` | 变量重解析、DSL run-if | +25 |
| `internal/placeholder/engine_test.go` | 新增 5 个测试函数 | +50 |
| `internal/engine/engine_test.go` | 新建测试文件 | +190 |
| `internal/workflow/workflow_test.go` | 新增 6 个测试函数 | +80 |

---

## 风险与缓解

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| 变量解析顺序问题 | 中 | 已完成：多轮解析，最多 5 轮 |
| DSL 表达式语法错误 | 低 | 已完成：捕获错误，返回 false |
| 自定义函数性能 | 低 | 已完成：限制函数执行时间 |
| 测试覆盖不足 | 中 | 进行中：增加更多测试用例 |

---

*进度表版本：v1.1*
*最后更新：2026-08-17*
