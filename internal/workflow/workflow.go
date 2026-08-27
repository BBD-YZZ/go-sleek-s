package workflow

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gosleek/gosleek/internal/httpclient"
	"github.com/gosleek/gosleek/internal/matcher"
	"github.com/gosleek/gosleek/internal/placeholder"
	"github.com/gosleek/gosleek/pkg/types"
)

// LoggerIface for structured logging inside workflow execution.
type LoggerIface interface {
	DebugKV(msg string, args ...interface{})
	InfoKV(msg string, args ...interface{})
	WarnKV(msg string, args ...interface{})
}

// isOOBRequest detects whether a parsed HTTP request is directed to an OOB provider.
// Returns (isOOB bool, provider string, oobInfo string).
func isOOBRequest(rawReq *httpclient.RawRequest) (bool, string, string) {
	host := strings.ToLower(rawReq.Headers["Host"])
	switch {
	case strings.Contains(host, "api.ceye.io"):
		return true, "ceye", "ceye query (api.ceye.io)"
	case strings.Contains(host, "47.244.138.18") || strings.Contains(host, "dnslog"):
		return true, "dnslog", "dnslog query (47.244.138.18)"
	case strings.Contains(host, "callback.red"):
		return true, "callbackred", "callback.red query"
	}
	return false, "", ""
}

// Executor handles multi-step workflow execution.
type Executor struct {
	client    *httpclient.Client
	timeout   int
	verbose   int
	onDebug   func(string, ...interface{})
	onVerbose func(string, ...interface{})
	onRaw     func(tag, format string, args ...interface{})
	onPacket  func(tag string, summary string, raw string)
	logger    LoggerIface

	// shared variable scope across steps
	scope map[string]string

	// global headers injected into every request
	globalHeaders map[string]string

	// activeProvider is the currently active OOB provider (e.g. "ceye", "dnslog", "callbackred")
	// If empty, all steps execute regardless of provider.
	activeProvider string
}

// New creates a workflow executor.
func New(client *httpclient.Client, timeout int, verbose int,
	onDebug func(string, ...interface{}),
	onVerbose func(string, ...interface{}),
	onRaw func(tag, format string, args ...interface{}),
	onPacket func(tag string, summary string, raw string),
	logger LoggerIface,
	globalHeaders map[string]string,
	activeProvider string,
) *Executor {
	return &Executor{
		client:         client,
		timeout:        timeout,
		verbose:        verbose,
		onDebug:        onDebug,
		onVerbose:      onVerbose,
		onRaw:          onRaw,
		onPacket:       onPacket,
		logger:         logger,
		scope:          make(map[string]string),
		globalHeaders:  globalHeaders,
		activeProvider: activeProvider,
	}
}

// Execute runs a workflow and returns whether it matched overall.
func (e *Executor) Execute(ctx context.Context, steps []types.WorkflowStep, target string, eng *placeholder.Engine) (bool, []string, map[string]string) {
	// Build dependency graph
	order, err := e.topoSort(steps)
	if err != nil {
		if e.logger != nil {
			e.logger.WarnKV("workflow topo sort failed", "error", err.Error())
		}
		return false, nil, nil
	}

	var evidence []string
	var allMatched bool = true
	extracted := make(map[string]string)

	// Track step index in execution order
	stepIdx := 0
	for _, stepName := range order {
		var step *types.WorkflowStep
		for i := range steps {
			if steps[i].Name == stepName {
				step = &steps[i]
				break
			}
		}
		if step == nil {
			continue
		}

		select {
		case <-ctx.Done():
			return false, evidence, extracted
		default:
		}

		// Delay before executing this step (e.g., waiting for OOB callback)
		if step.Delay > 0 {
			if e.logger != nil {
				e.logger.InfoKV("workflow step waiting",
					"step", step.Name, "delay_s", step.Delay)
			}
			select {
			case <-ctx.Done():
				return false, evidence, extracted
			case <-time.After(time.Duration(step.Delay) * time.Second):
			}
		}

		// Skip step if provider doesn't match active OOB provider
		if step.Provider != "" && step.Provider != e.activeProvider {
			if e.logger != nil {
				e.logger.InfoKV("workflow step skipped (provider mismatch)",
					"step", step.Name, "step_provider", step.Provider,
					"active_provider", e.activeProvider)
			}
			stepIdx++
			continue
		}

		if e.logger != nil {
			e.logger.InfoKV("workflow step executing",
				"step_index", stepIdx, "step", step.Name, "template_step", stepIdx)
		}

		// Execute step HTTP requests (inline)
		if len(step.HTTP) > 0 {
			stepMatched, stepEv, stepExt := e.executeHTTPBlocks(ctx, step.HTTP, target, eng, stepIdx, step.Name)
			for k, v := range stepExt {
				extracted[k] = v
				eng.SetExtracted(k, v)
			}
			if stepEv != "" {
				evidence = append(evidence, step.Name+": "+stepEv)
			}

			if !stepMatched {
				allMatched = false
				if step.StopAtFirstMatch {
					break
				}
			}
		}

		stepIdx++

		// If step references another template, it would be executed by the engine
		// (this is handled at the engine level, not here)
	}

	return allMatched, evidence, extracted
}

// sendWorkflowRequest sends a single request and processes its response.
// This is extracted to avoid duplicating the send/extract/match logic in
// both the path-mode and raw-mode branches.
func (e *Executor) sendWorkflowRequest(ctx context.Context, req types.HTTPRequest, rawReq string, target string, eng *placeholder.Engine,
	stepIdx int, stepName string, extracted map[string]string,
) (bool, string) {

	parsed, err := httpclient.ParseRaw(rawReq)
	if err != nil {
		if e.logger != nil {
			e.logger.WarnKV("workflow parse request failed",
				"step", stepName, "req", 0, "error", err.Error())
		}
		return false, ""
	}

	reqTimeout := e.timeout
	if req.Timeout > 0 {
		reqTimeout = req.Timeout
	}

	// Log request before sending — Burp-style packet
	resolvedURL := httpclient.ResolveURL(target, parsed)
	if e.logger != nil {
		e.logger.InfoKV("workflow HTTP request sent",
			"step", stepName, "step_index", stepIdx, "req", 0,
			"url", resolvedURL, "method", parsed.Method)
	}
	if e.verbose >= 2 && e.onPacket != nil {
		summary := fmt.Sprintf("workflow[%s] step[%d] req[0]  %s %s  %d bytes",
			stepName, stepIdx, parsed.Method, resolvedURL, len(rawReq))
		e.onPacket("请求", summary, rawReq)
	}

	reqCtx, cancel := context.WithTimeout(ctx, time.Duration(reqTimeout)*time.Second)
	resp, err := e.client.SendParsed(reqCtx, target, parsed)
	cancel()
	if err != nil {
		if e.logger != nil {
			e.logger.WarnKV("workflow HTTP request failed",
				"step", stepName, "step_index", stepIdx, "req", 0, "error", err.Error())
		}
		return false, ""
	}

	// Log response — Burp-style packet
	if e.logger != nil {
		e.logger.InfoKV("workflow HTTP response received",
			"step", stepName, "step_index", stepIdx, "req", 0,
			"status", resp.StatusCode, "time_ms", resp.Time.Milliseconds(),
			"bytes", len(resp.Body))
	}
	if e.verbose >= 2 && e.onPacket != nil {
		summary := fmt.Sprintf("workflow[%s] step[%d] req[0]  status=%d  %s  %d bytes",
			stepName, stepIdx, resp.StatusCode,
			resp.Time.Round(time.Millisecond), len(resp.Body))
		e.onPacket("响应", summary, resp.Raw)
	}

	// For OOB verify steps (queries to api.ceye.io), log body regardless
	if strings.Contains(strings.ToLower(parsed.Headers["Host"]), "ceye.io") {
		bodyDisplay := resp.Body
		if len(bodyDisplay) > 800 {
			bodyDisplay = bodyDisplay[:800] + "\n... (truncated, total " + fmt.Sprintf("%d", len(resp.Body)) + " bytes)"
		}
		if e.logger != nil {
			e.logger.DebugKV("ceye.io response",
				"step", stepName, "req", 0, "status", resp.StatusCode,
				"body", bodyDisplay)
		}
	}

	matchCtx := matcher.NewMatchContextWithCookies(
		resp.StatusCode,
		resp.Body,
		resp.AllHeaders(),
		resp.GetHeader("Set-Cookie"),
		resp.Time,
	)
	// Carry forward extracted variables for DSL interpolation across steps
	matchCtx.ExtractedVars = extracted

	// Extract
	ext := matcher.Extract(req.Extractors, matchCtx)
	for k, v := range ext {
		extracted[k] = v
		eng.SetExtracted(k, v)
	}

	// Match — first substitute placeholders inside each matcher's
	// string fields (Words/Regex/Header/JSONPath/JSONField etc.)
	// because YAML-loaders never run them through the placeholder
	// engine; only the raw HTTP request does.
	matchers := matcher.SubstituterMatcherPlaceholders(req.Matchers, eng)
	matched, ev := matcher.Evaluate(matchers, req.MatchersCondition, matchCtx)

	// Log matcher result
	if e.logger != nil {
		mTypes := make([]string, 0, len(req.Matchers))
		for _, m := range req.Matchers {
			mTypes = append(mTypes, m.Type)
		}
		if matched {
			e.logger.InfoKV("workflow matcher PASS",
				"step", stepName, "step_index", stepIdx, "req", 0,
				"condition", req.MatchersCondition,
				"types", strings.Join(mTypes, ","), "evidence", ev)
		} else {
			e.logger.InfoKV("workflow matcher FAIL",
				"step", stepName, "step_index", stepIdx, "req", 0,
				"condition", req.MatchersCondition,
				"types", strings.Join(mTypes, ","))
		}
	}
	if e.verbose >= 2 && e.onRaw != nil {
		status := "PASS"
		if !matched {
			status = "FAIL"
		}
		mTypes := make([]string, 0, len(req.Matchers))
		for _, m := range req.Matchers {
			mTypes = append(mTypes, m.Type)
		}
		e.onRaw("匹配", "workflow[%s] step[%d] req[0]  %s  cond=%s  types=%s  evidence=%q",
			stepName, stepIdx, status, req.MatchersCondition,
			strings.Join(mTypes, ","), ev)
	}

	return matched, ev
}

func (e *Executor) executeHTTPBlocks(ctx context.Context, blocks []types.HTTPRequest, target string, eng *placeholder.Engine, stepIdx int, stepName string) (bool, string, map[string]string) {
	var results []bool
	var evidence []string
	extracted := make(map[string]string)
	// copiedExtracted is returned on early exits to preserve extracted variables
	// collected before the abort (e.g. context cancellation mid-step).
	copiedExtracted := extracted

	for i, req := range blocks {
		select {
		case <-ctx.Done():
			return false, "", copiedExtracted
		default:
		}

		// run-if: skip this request block if condition is false.
		if req.RunIf != "" {
			if !evalRunIf(req.RunIf, extracted, eng) {
				if e.logger != nil {
					e.logger.InfoKV("workflow request skipped (run-if false)",
						"step", stepName, "req", i, "run-if", req.RunIf)
				}
				continue
			}
		}

		// Replace placeholders in raw request
		rawReq := eng.ReplaceWithEscape(req.Raw)
		if rawReq == "" {
			// Merge per-request headers with global headers
			mergedHeaders := make(map[string]string, len(req.Headers)+len(e.globalHeaders))
			for k, v := range req.Headers {
				mergedHeaders[k] = v
			}
			for k, v := range e.globalHeaders {
				if _, exists := mergedHeaders[k]; !exists {
					mergedHeaders[k] = v
				}
			}
			// Build raw from path with merged headers
			if len(req.Path) > 0 {
				method := req.Method
				if method == "" {
					method = "GET"
				}
				// Iterate over all paths in the list
				for _, p := range req.Path {
					pathReq := buildRawFromPathWithBodyType(method, p, mergedHeaders, req.Body, req.BodyType)
					pathReq = eng.ReplaceWithEscape(pathReq)
					if pathReq == "" {
						continue
					}

					// Range injection on path mode: replace placeholder FIRST, then resolve engine vars
					if req.Range != nil && len(req.Range.Values) > 0 {
						rangeSent := false
						for _, val := range req.Range.Values {
							rangeReq := strings.ReplaceAll(pathReq, "{{"+req.Range.Key+"}}", val)
							if rangeReq == pathReq {
								// Placeholder not found in this path — skip
								continue
							}
							rangeReq = eng.ReplaceWithEscape(rangeReq)
							if rangeReq == "" {
								continue
							}
							matched, _ := e.sendWorkflowRequest(ctx, req, rangeReq, target, eng, stepIdx, stepName, extracted)
							results = append(results, matched)
							rangeSent = true
							if req.StopAtFirstMatch && matched {
								break
							}
						}
						if !rangeSent {
							// No placeholder matched — send original
							matched, ev := e.sendWorkflowRequest(ctx, req, pathReq, target, eng, stepIdx, stepName, extracted)
							results = append(results, matched)
							if ev != "" {
								evidence = append(evidence, ev)
							}
						}
					} else {
						matched, ev := e.sendWorkflowRequest(ctx, req, pathReq, target, eng, stepIdx, stepName, extracted)
						results = append(results, matched)
						if ev != "" {
							evidence = append(evidence, ev)
						}
					}
					continue
				}
			}
			if rawReq == "" {
				continue
			}
		} else {
			// Range injection: iterate over values and replace placeholder FIRST
			// (must be done before placeholder substitution so that {{key}}
			// patterns survive the variable resolution)
			if req.Range != nil && len(req.Range.Values) > 0 {
				rangeSent := false
				for _, val := range req.Range.Values {
					select {
					case <-ctx.Done():
						return false, "", copiedExtracted
					default:
					}
					rangeReq := strings.ReplaceAll(rawReq, "{{"+req.Range.Key+"}}", val)
					if rangeReq == rawReq {
						// Placeholder not found — skip this value
						continue
					}
					// Apply placeholder substitution AFTER range replacement
					finalReq := eng.ReplaceWithEscape(rangeReq)
					if finalReq == "" {
						continue
					}
					// Inject global headers into raw request
					finalReq = injectGlobalHeaders(finalReq, e.globalHeaders)
					matched, ev := e.sendWorkflowRequest(ctx, req, finalReq, target, eng, stepIdx, stepName, extracted)
					results = append(results, matched)
					if ev != "" {
						evidence = append(evidence, ev)
					}
					rangeSent = true
					if req.StopAtFirstMatch && matched {
						break
					}
				}
				if !rangeSent {
					// Placeholder not found in any value — send original
					finalReq := injectGlobalHeaders(rawReq, e.globalHeaders)
					matched, ev := e.sendWorkflowRequest(ctx, req, finalReq, target, eng, stepIdx, stepName, extracted)
					results = append(results, matched)
					if ev != "" {
						evidence = append(evidence, ev)
					}
				}
				continue
			}
			// Inject global headers into raw request
			rawReq = injectGlobalHeaders(rawReq, e.globalHeaders)
		}

		matched, ev := e.sendWorkflowRequest(ctx, req, rawReq, target, eng, stepIdx, stepName, extracted)
		results = append(results, matched)
		if ev != "" {
			evidence = append(evidence, ev)
		}

		if req.StopAtFirstMatch && matched {
			break
		}
	}

	// Aggregate: step-level condition.
	// A2 fix: prefer the LAST block's MatchersCondition so that a
	// template can express "each block matches AND all blocks together must match"
	// by putting 'and' on the final block (or 'or' on the first for legacy).
	if len(blocks) == 0 {
		return false, "", copiedExtracted
	}
	cond := "or"
	for i := len(blocks) - 1; i >= 0; i-- {
		if blocks[i].MatchersCondition != "" {
			cond = blocks[i].MatchersCondition
			break
		}
	}

	overall := false
	if cond == "and" {
		overall = true
		for _, r := range results {
			if !r {
				overall = false
				break
			}
		}
	} else {
		for _, r := range results {
			if r {
				overall = true
				break
			}
		}
	}

	return overall, strings.Join(evidence, "; "), extracted
}

// evalRunIf evaluates a run-if condition for a request block.
// It checks both the extracted map (from previous requests in the same step)
// and the engine's extracted values (from previous steps) for variable resolution.
func evalRunIf(expr string, extracted map[string]string, eng *placeholder.Engine) bool {
	val := eng.Replace(expr)
	if val == "" {
		return false
	}
	// Check for unresolved placeholders
	if strings.Contains(val, "{{") && strings.Contains(val, "}}") {
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(val))
	if lower == "false" || lower == "0" {
		return false
	}
	// If the expression looks like a DSL expression (contains ==, !=, etc.),
	// evaluate it using the DSL engine.
	// Note: for run-if, unknown extracted variables should resolve to ""
	// (not their name string) so that len(missing) == 0 evaluates correctly.
	if strings.Contains(val, "==") || strings.Contains(val, "!=") ||
		strings.Contains(val, ">") || strings.Contains(val, "<") ||
		strings.Contains(val, "contains") || strings.Contains(val, "regex") ||
		strings.Contains(val, "!") {
		// Build a match context with extracted variables from BOTH
		// the local extracted map AND the engine's extracted values,
		// so that variables extracted in previous workflow steps are available.
		mergedVars := make(map[string]string, len(extracted))
		for k, v := range extracted {
			mergedVars[k] = v
		}
		// Copy engine's extracted values (they take precedence)
		engineExtracted := eng.GetExtractedMap()
		for k, v := range engineExtracted {
			mergedVars[k] = v
		}
		ctx := &matcher.MatchContext{
			StatusCode:     200,
			Body:           "",
			Header:         "",
			ExtractedVars:  mergedVars,
			UnknownVarMode: "empty",
		}
		if result, err := matcher.EvalDSL(val, ctx); err == nil {
			return result
		}
		// If DSL evaluation fails, fall through to default behavior
	}
	return true
}

// topoSort performs a topological sort of workflow steps based on requires.
func (e *Executor) topoSort(steps []types.WorkflowStep) ([]string, error) {
	// Build adjacency list and in-degree
	graph := make(map[string][]string)
	inDegree := make(map[string]int)
	nameSet := make(map[string]bool)

	for _, step := range steps {
		nameSet[step.Name] = true
		if _, ok := inDegree[step.Name]; !ok {
			inDegree[step.Name] = 0
		}
		for _, dep := range step.Requires {
			graph[dep] = append(graph[dep], step.Name)
			inDegree[step.Name]++
		}
	}

	// Kahn's algorithm
	var queue []string
	for name := range nameSet {
		if inDegree[name] == 0 {
			queue = append(queue, name)
		}
	}

	var order []string
	for len(queue) > 0 {
		// Pop
		node := queue[0]
		queue = queue[1:]
		order = append(order, node)

		for _, neighbor := range graph[node] {
			inDegree[neighbor]--
			if inDegree[neighbor] == 0 {
				queue = append(queue, neighbor)
			}
		}
	}

	if len(order) != len(steps) {
		return nil, fmt.Errorf("circular dependency detected in workflow")
	}

	return order, nil
}

// buildRawFromPath constructs a raw HTTP request string from method, path, headers and body.
func buildRawFromPath(method, path string, headers map[string]string, body string) string {
	return buildRawFromPathWithBodyType(method, path, headers, body, "")
}

// buildRawFromPathWithBodyType constructs a raw HTTP request with body type support.
func buildRawFromPathWithBodyType(method, path string, headers map[string]string, body, bodyType string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", method, path))
	sb.WriteString("Host: {{Hostname}}\r\n")

	if bodyType != "" && body != "" {
		switch strings.ToLower(bodyType) {
		case "form", "form-urlencoded":
			for k, v := range headers {
				sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
			}
			sb.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
			sb.WriteString("Connection: close\r\n")
			sb.WriteString("\r\n")
			sb.WriteString(body)
			return sb.String()
		case "multipart", "multipart-form-data":
			boundary := "----gosleekFormBoundary" + placeholder.RandTextHex(8)
			contentType := "multipart/form-data; boundary=" + boundary
			for k, v := range headers {
				sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
			}
			sb.WriteString("Content-Type: " + contentType + "\r\n")
			sb.WriteString("Connection: close\r\n")
			sb.WriteString("\r\n")
			sb.WriteString(buildMultipartBody(body, boundary))
			return sb.String()
		}
	}

	for k, v := range headers {
		sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	sb.WriteString("Connection: close\r\n")
	sb.WriteString("\r\n")
	if body != "" {
		sb.WriteString(body)
	}
	return sb.String()
}

// buildMultipartBody generates a multipart form body from key=value pairs.
func buildMultipartBody(body, boundary string) string {
	var sb strings.Builder
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, "=")
		if idx < 0 {
			continue
		}
		key := line[:idx]
		value := line[idx+1:]
		sb.WriteString("--" + boundary + "\r\n")
		sb.WriteString(fmt.Sprintf("Content-Disposition: form-data; name=\"%s\"\r\n\r\n", key))
		sb.WriteString(value + "\r\n")
	}
	sb.WriteString("--" + boundary + "--\r\n")
	return sb.String()
}

// injectGlobalHeaders inserts global CLI headers into a raw HTTP request string.
// It inserts missing headers BEFORE the blank line that separates headers from body,
// so that ParseRaw correctly parses them as HTTP headers rather than body content.
func injectGlobalHeaders(raw string, headers map[string]string) string {
	if len(headers) == 0 {
		return raw
	}
	sep := "\r\n\r\n"
	idx := strings.Index(raw, sep)
	if idx < 0 {
		idx = strings.Index(raw, "\n\n")
	}
	if idx >= 0 {
		// Insert BEFORE the blank line so new headers appear in the header block.
		var sb strings.Builder
		sb.WriteString(raw[:idx])
		sb.WriteString("\r\n")
		for k, v := range headers {
			sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
		}
		sb.WriteString(raw[idx:])
		return sb.String()
	}
	// No separator found — append headers at the end.
	raw = strings.TrimRight(raw, "\r\n")
	return raw + "\r\n" + injectHeadersMap(headers)
}

// injectHeadersMap formats a headers map into HTTP header lines.
func injectHeadersMap(headers map[string]string) string {
	var sb strings.Builder
	for k, v := range headers {
		sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	return sb.String()
}
