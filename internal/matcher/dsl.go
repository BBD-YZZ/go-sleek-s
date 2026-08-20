package matcher

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// --- DSL Expression Evaluator ---
//
// Supported syntax:
//   status_code == 200
//   contains(body, 'admin')
//   !contains(header, 'login')
//   status_code == 200 && contains(body, 'admin')
//   len(body) > 100 || status_code == 500
//   regex(body, 'token=[a-z0-9]+')
//   contains_any(body, 'root', 'admin', 'www-data')
//   contains_all(body, 'uid=', 'gid=')
//   equals(status_code, '200')
//   to_lower_contains(body, 'error')
//
// Variables: status_code, body, header, all, response_time, content_length
// Functions:
//   contains(var, 'substr')            — substring match
//   contains_any(var, 'w1', 'w2', ...) — any word is substring
//   contains_all(var, 'w1', 'w2', ...) — all words are substrings
//   equals(var, 'value')               — exact string equality
//   regex(var, 'pattern')              — regex match (alias: matches)
//   starts_with(var, 'prefix')         — prefix match (alias: has_prefix)
//   ends_with(var, 'suffix')           — suffix match (alias: has_suffix)
//   to_lower_contains(var, 'word')     — case-insensitive contains
//   len(var)                           — length > 0 (for bool context)
// Operators: == != > < >= <=  && ||  !

func evalDSLs(exprs []string, ctx *MatchContext) (bool, string) {
	if len(exprs) == 0 {
		return true, ""
	}
	for _, expr := range exprs {
		result, err := evalDSL(expr, ctx)
		if err != nil {
			// A syntactically invalid DSL must NOT be silently skipped and
			// treated as a match — that would cause false positives. Treat
			// the parse failure as a non-match for the whole matcher.
			return false, fmt.Sprintf("dsl: parse error: %v", err)
		}
		if !result {
			return false, ""
		}
	}
	return true, "dsl: matched"
}

// EvalDSL is the exported wrapper for evalDSL, used by tests.
func EvalDSL(expr string, ctx *MatchContext) (bool, error) {
	return evalDSL(expr, ctx)
}

func evalDSL(expr string, ctx *MatchContext) (bool, error) {
	p := &dslParser{
		input: strings.TrimSpace(expr),
		pos:   0,
	}
	result, err := p.parseOr(ctx)
	if err != nil {
		return false, err
	}
	// [批次A-4 修复点] 校验尾随输入: 旧实现解析完后剩余字符被静默忽略,
	// 导致 "status_code == 200 garbage" 会被当作合法且匹配。现在报错。
	p.skipWS()
	if p.pos < len(p.input) {
		return false, fmt.Errorf("unexpected trailing input at pos %d: %q", p.pos, p.input[p.pos:])
	}
	return result, nil
}

// --- Tokenizer + Parser ---

type dslParser struct {
	input string
	pos   int
}

func (p *dslParser) skipWS() {
	for p.pos < len(p.input) && unicode.IsSpace(rune(p.input[p.pos])) {
		p.pos++
	}
}

func (p *dslParser) peek() byte {
	p.skipWS()
	if p.pos >= len(p.input) {
		return 0
	}
	return p.input[p.pos]
}

func (p *dslParser) consume(s string) bool {
	p.skipWS()
	if p.pos+len(s) <= len(p.input) && p.input[p.pos:p.pos+len(s)] == s {
		p.pos += len(s)
		return true
	}
	return false
}

// parseOr handles || (lowest precedence)
func (p *dslParser) parseOr(ctx *MatchContext) (bool, error) {
	left, err := p.parseAnd(ctx)
	if err != nil {
		return false, err
	}
	for {
		if p.consume("||") {
			right, err := p.parseAnd(ctx)
			if err != nil {
				return false, err
			}
			left = left || right
		} else {
			break
		}
	}
	return left, nil
}

// parseAnd handles &&
func (p *dslParser) parseAnd(ctx *MatchContext) (bool, error) {
	left, err := p.parseNot(ctx)
	if err != nil {
		return false, err
	}
	for {
		if p.consume("&&") {
			right, err := p.parseNot(ctx)
			if err != nil {
				return false, err
			}
			left = left && right
		} else {
			break
		}
	}
	return left, nil
}

// parseNot handles !
func (p *dslParser) parseNot(ctx *MatchContext) (bool, error) {
	if p.consume("!") {
		val, err := p.parseNot(ctx)
		return !val, err
	}
	return p.parsePrimary(ctx)
}

// parsePrimary handles: (expr), function(args), variable op value
func (p *dslParser) parsePrimary(ctx *MatchContext) (bool, error) {
	p.skipWS()
	if p.pos >= len(p.input) {
		return false, fmt.Errorf("unexpected end of input")
	}

	// Parenthesized expression
	if p.consume("(") {
		val, err := p.parseOr(ctx)
		if err != nil {
			return false, err
		}
		if !p.consume(")") {
			return false, fmt.Errorf("expected )")
		}
		return val, nil
	}

	// Try to read an identifier
	ident := p.readIdent()
	if ident == "" {
		return false, fmt.Errorf("expected identifier at pos %d", p.pos)
	}

	// Function call?
	p.skipWS()
	if p.pos < len(p.input) && p.input[p.pos] == '(' {
		// [批次A-4 修复点] len() 返回数值而非布尔, 可用于 "len(body) > 100"。
		// 旧实现把 len() 当普通函数处理, 返回 len>0 的 bool, 导致 "> 100"
		// 被静默忽略, 任何非空 body 都会匹配 len(body) > 100。
		if ident == "len" {
			return p.parseLenComparison(ctx)
		}
		return p.parseFuncCall(ident, ctx)
	}

	// Variable comparison
	return p.parseComparison(ident, ctx)
}

// parseLenComparison handles "len(var) > 100" — len() produces a numeric
// value that participates in comparison, not a bare boolean.
func (p *dslParser) parseLenComparison(ctx *MatchContext) (bool, error) {
	if !p.consume("(") {
		return false, fmt.Errorf("expected ( after len")
	}
	arg := p.readArg()
	if !p.consume(")") {
		return false, fmt.Errorf("expected ) after len(%s", arg)
	}
	s := resolveVar(arg, ctx)
	leftVal := strconv.Itoa(len(s))

	// Check for a following comparison operator
	p.skipWS()
	op := p.readOperator()
	if op == "" {
		// No operator — boolean context: len > 0
		return len(s) > 0, nil
	}
	p.skipWS()
	right := p.readValue()
	if right == "" {
		ident := p.readIdent()
		if ident != "" {
			right = ident
		}
	}
	return compareValues(leftVal, right, op)
}

func (p *dslParser) readIdent() string {
	p.skipWS()
	start := p.pos
	for p.pos < len(p.input) {
		c := p.input[p.pos]
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			p.pos++
		} else {
			break
		}
	}
	return p.input[start:p.pos]
}

func (p *dslParser) parseFuncCall(name string, ctx *MatchContext) (bool, error) {
	if !p.consume("(") {
		return false, fmt.Errorf("expected ( after function %s", name)
	}
	args := []string{}
	for {
		p.skipWS()
		if p.peek() == ')' {
			p.pos++ // consume )
			break
		}
		// Read argument: could be a string literal or a variable
		arg := p.readArg()
		args = append(args, arg)
		p.skipWS()
		if p.consume(",") {
			continue
		}
		if p.consume(")") {
			break
		}
	}

	switch name {
	case "contains":
		if len(args) < 2 {
			return false, fmt.Errorf("contains needs 2 args")
		}
		s := resolveVar(args[0], ctx)
		return strings.Contains(s, args[1]), nil
	case "contains_any":
		// contains_any(var, 'w1', 'w2', ...) — true if any word is a substring
		if len(args) < 2 {
			return false, fmt.Errorf("contains_any needs at least 2 args")
		}
		s := resolveVar(args[0], ctx)
		for _, w := range args[1:] {
			if strings.Contains(s, w) {
				return true, nil
			}
		}
		return false, nil
	case "contains_all":
		// contains_all(var, 'w1', 'w2', ...) — true if every word is a substring
		if len(args) < 2 {
			return false, fmt.Errorf("contains_all needs at least 2 args")
		}
		s := resolveVar(args[0], ctx)
		for _, w := range args[1:] {
			if !strings.Contains(s, w) {
				return false, nil
			}
		}
		return true, nil
	case "equals":
		// equals(var, 'value') — exact string equality
		if len(args) < 2 {
			return false, fmt.Errorf("equals needs 2 args")
		}
		s := resolveVar(args[0], ctx)
		return s == args[1], nil
	case "regex", "matches":
		// 'matches' is an alias for 'regex'
		if len(args) < 2 {
			return false, fmt.Errorf("regex needs 2 args")
		}
		s := resolveVar(args[0], ctx)
		re, err := cachedCompile(args[1])
		if err != nil {
			return false, err
		}
		return re.MatchString(s), nil
	case "starts_with", "has_prefix":
		// 'has_prefix' is an alias for 'starts_with'
		if len(args) < 2 {
			return false, fmt.Errorf("starts_with needs 2 args")
		}
		s := resolveVar(args[0], ctx)
		return strings.HasPrefix(s, args[1]), nil
	case "ends_with", "has_suffix":
		// 'has_suffix' is an alias for 'ends_with'
		if len(args) < 2 {
			return false, fmt.Errorf("ends_with needs 2 args")
		}
		s := resolveVar(args[0], ctx)
		return strings.HasSuffix(s, args[1]), nil
	case "to_lower_contains":
		// to_lower_contains(var, 'word') — case-insensitive contains
		if len(args) < 2 {
			return false, fmt.Errorf("to_lower_contains needs 2 args")
		}
		s := strings.ToLower(resolveVar(args[0], ctx))
		return strings.Contains(s, strings.ToLower(args[1])), nil
	case "len":
		// len(body) > 100 is handled as comparison; but if used as bool,
		// return true if len > 0
		s := resolveVar(args[0], ctx)
		return len(s) > 0, nil
	default:
		return false, fmt.Errorf("unknown function: %s", name)
	}
}

func (p *dslParser) readArg() string {
	p.skipWS()
	if p.pos >= len(p.input) {
		return ""
	}
	c := p.input[p.pos]
	if c == '\'' || c == '"' {
		quote := c
		p.pos++
		// [批次A-4 修复点] 支持反斜杠转义: \' → ', \" → ", \\ → \
		// 旧实现在遇到引号时直接截断, 无法在字符串中包含引号。
		var sb strings.Builder
		for p.pos < len(p.input) {
			ch := p.input[p.pos]
			if ch == '\\' && p.pos+1 < len(p.input) {
				next := p.input[p.pos+1]
				if next == quote || next == '\\' {
					sb.WriteByte(next)
					p.pos += 2
					continue
				}
			}
			if ch == quote {
				p.pos++
				break
			}
			sb.WriteByte(ch)
			p.pos++
		}
		return sb.String()
	}
	// Variable name
	return p.readIdent()
}

func (p *dslParser) parseComparison(varName string, ctx *MatchContext) (bool, error) {
	p.skipWS()
	// Read operator
	op := p.readOperator()
	if op == "" {
		// No operator - treat as boolean check (truthy)
		val := resolveVar(varName, ctx)
		return val != "" && val != "0" && val != "false", nil
	}

	p.skipWS()
	// Read value
	right := p.readValue()
	if right == "" {
		// Could be a function returning a number: len(body) > 100
		// Try reading an identifier
		ident := p.readIdent()
		if ident != "" {
			right = ident
		}
	}

	leftVal := resolveVar(varName, ctx)
	return compareValues(leftVal, right, op)
}

func (p *dslParser) readOperator() string {
	p.skipWS()
	// Try two-char operators first
	for _, op := range []string{">=", "<=", "==", "!="} {
		if p.pos+len(op) <= len(p.input) && p.input[p.pos:p.pos+len(op)] == op {
			p.pos += len(op)
			return op
		}
	}
	// Single-char
	if p.pos < len(p.input) {
		c := p.input[p.pos]
		if c == '>' || c == '<' {
			p.pos++
			return string(c)
		}
	}
	return ""
}

func (p *dslParser) readValue() string {
	p.skipWS()
	if p.pos >= len(p.input) {
		return ""
	}
	c := p.input[p.pos]
	if c == '\'' || c == '"' {
		quote := c
		p.pos++
		// [批次A-4 修复点] 与 readArg 保持一致, 支持转义引号
		var sb strings.Builder
		for p.pos < len(p.input) {
			ch := p.input[p.pos]
			if ch == '\\' && p.pos+1 < len(p.input) {
				next := p.input[p.pos+1]
				if next == quote || next == '\\' {
					sb.WriteByte(next)
					p.pos += 2
					continue
				}
			}
			if ch == quote {
				p.pos++
				break
			}
			sb.WriteByte(ch)
			p.pos++
		}
		return sb.String()
	}
	// Number or identifier
	start := p.pos
	for p.pos < len(p.input) {
		c := p.input[p.pos]
		if (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			p.pos++
		} else {
			break
		}
	}
	return p.input[start:p.pos]
}

func resolveVar(name string, ctx *MatchContext) string {
	switch name {
	case "status_code":
		return strconv.Itoa(ctx.StatusCode)
	case "body":
		return ctx.Body
	case "header":
		return ctx.Header
	case "all":
		return ctx.All
	case "response_time":
		return fmt.Sprintf("%f", ctx.ResponseTime.Seconds())
	case "content_length", "len":
		return strconv.Itoa(ctx.ContentSize)
	default:
		// Check extracted variables from previous steps (e.g. tokens, IDs)
		if ctx.ExtractedVars != nil {
			if v, ok := ctx.ExtractedVars[name]; ok {
				return v
			}
		}
		// [P1 修复] 未知变量不再静默返回自身。当 Debug 回调可用时输出警告，
		// 帮助用户发现拼写错误（如 stat_code 应为 status_code）。
		// 仍返回原值以保持向后兼容，但警告会让用户注意到问题。
		if ctx.Debug != nil {
			ctx.Debug("[dsl] unknown variable %q — may be a typo or undefined extractor", name)
		}
		return name
	}
}

func compareValues(left, right, op string) (bool, error) {
	// Try numeric comparison first
	leftNum, errL := strconv.ParseFloat(left, 64)
	rightNum, errR := strconv.ParseFloat(right, 64)

	if errL == nil && errR == nil {
		switch op {
		case "==":
			return leftNum == rightNum, nil
		case "!=":
			return leftNum != rightNum, nil
		case ">":
			return leftNum > rightNum, nil
		case "<":
			return leftNum < rightNum, nil
		case ">=":
			return leftNum >= rightNum, nil
		case "<=":
			return leftNum <= rightNum, nil
		}
	}

	// String comparison
	switch op {
	case "==":
		return left == right, nil
	case "!=":
		return left != right, nil
	case ">":
		return left > right, nil
	case "<":
		return left < right, nil
	case ">=":
		return left >= right, nil
	case "<=":
		return left <= right, nil
	}
	return false, fmt.Errorf("unknown operator: %s", op)
}
