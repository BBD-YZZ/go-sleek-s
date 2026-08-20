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

func (e *Executor) executeHTTPBlocks(ctx context.Context, blocks []types.HTTPRequest, target string, eng *placeholder.Engine, stepIdx int, stepName string) (bool, string, map[string]string) {
	var results []bool
	var evidence []string
	extracted := make(map[string]string)

	for i, req := range blocks {
		select {
		case <-ctx.Done():
			return false, "", extracted
		default:
		}

		// Replace placeholders
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

					// Parse and send
					parsed, err := httpclient.ParseRaw(pathReq)
					if err != nil {
						if e.logger != nil {
							e.logger.WarnKV("workflow parse request failed",
								"step", stepName, "req", i, "error", err.Error())
						}
						continue
					}

					reqTimeout := e.timeout
					if req.Timeout > 0 {
						reqTimeout = req.Timeout
					}

					// Log request before sending — Burp-style packet
					resolvedURL := httpclient.ResolveURL(target, parsed)
					if e.logger != nil {
						e.logger.InfoKV("workflow HTTP request sent",
							"step", stepName, "step_index", stepIdx, "req", i,
							"url", resolvedURL, "method", parsed.Method)
					}
					if e.verbose >= 2 && e.onPacket != nil {
						summary := fmt.Sprintf("workflow[%s] step[%d] req[%d]  %s %s  %d bytes",
							stepName, stepIdx, i, parsed.Method, resolvedURL, len(pathReq))
						e.onPacket("请求", summary, pathReq)
					}

					reqCtx, cancel := context.WithTimeout(ctx, time.Duration(reqTimeout)*time.Second)
					resp, err := e.client.SendParsed(reqCtx, target, parsed)
					cancel()
					if err != nil {
						if e.logger != nil {
							e.logger.WarnKV("workflow HTTP request failed",
								"step", stepName, "step_index", stepIdx, "req", i, "error", err.Error())
						}
						results = append(results, false)
						continue
					}

					// Log response — Burp-style packet
					if e.logger != nil {
						e.logger.InfoKV("workflow HTTP response received",
							"step", stepName, "step_index", stepIdx, "req", i,
							"status", resp.StatusCode, "time_ms", resp.Time.Milliseconds(),
							"bytes", len(resp.Body))
					}
					if e.verbose >= 2 && e.onPacket != nil {
						summary := fmt.Sprintf("workflow[%s] step[%d] req[%d]  status=%d  %s  %d bytes",
							stepName, stepIdx, i, resp.StatusCode,
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
								"step", stepName, "req", i, "status", resp.StatusCode,
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
					matchers := substituteMatcherPlaceholders(req.Matchers, eng)
					matched, ev := matcher.Evaluate(matchers, req.MatchersCondition, matchCtx)

					// Log matcher result
					if e.logger != nil {
						mTypes := make([]string, 0, len(req.Matchers))
						for _, m := range req.Matchers {
							mTypes = append(mTypes, m.Type)
						}
						if matched {
							e.logger.InfoKV("workflow matcher PASS",
								"step", stepName, "step_index", stepIdx, "req", i,
								"condition", req.MatchersCondition,
								"types", strings.Join(mTypes, ","), "evidence", ev)
						} else {
							e.logger.InfoKV("workflow matcher FAIL",
								"step", stepName, "step_index", stepIdx, "req", i,
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
						e.onRaw("匹配", "workflow[%s] step[%d] req[%d]  %s  cond=%s  types=%s  evidence=%q",
							stepName, stepIdx, i, status, req.MatchersCondition,
							strings.Join(mTypes, ","), ev)
					}

					results = append(results, matched)
					if ev != "" {
						evidence = append(evidence, ev)
					}

					if req.StopAtFirstMatch && matched {
						break
					}
				}
				continue
			}
			if rawReq == "" {
				continue
			}
		} else {
			// Inject global headers into raw request
			rawReq = injectGlobalHeaders(rawReq, e.globalHeaders)
			rawReq = eng.ReplaceWithEscape(rawReq)
		}

		// Parse and send
		parsed, err := httpclient.ParseRaw(rawReq)
		if err != nil {
			if e.logger != nil {
				e.logger.WarnKV("workflow parse request failed",
					"step", stepName, "req", i, "error", err.Error())
			}
			continue
		}

		reqTimeout := e.timeout
		if req.Timeout > 0 {
			reqTimeout = req.Timeout
		}

		// Log request before sending — Burp-style packet
		resolvedURL := httpclient.ResolveURL(target, parsed)
		if e.logger != nil {
			e.logger.InfoKV("workflow HTTP request sent",
				"step", stepName, "step_index", stepIdx, "req", i,
				"url", resolvedURL, "method", parsed.Method)
		}
		if e.verbose >= 2 && e.onPacket != nil {
			summary := fmt.Sprintf("workflow[%s] step[%d] req[%d]  %s %s  %d bytes",
				stepName, stepIdx, i, parsed.Method, resolvedURL, len(rawReq))
			e.onPacket("请求", summary, rawReq)
		}

		reqCtx, cancel := context.WithTimeout(ctx, time.Duration(reqTimeout)*time.Second)
		resp, err := e.client.SendParsed(reqCtx, target, parsed)
		cancel()
		if err != nil {
			if e.logger != nil {
				e.logger.WarnKV("workflow HTTP request failed",
					"step", stepName, "step_index", stepIdx, "req", i, "error", err.Error())
			}
			results = append(results, false)
			continue
		}

		// Log response — Burp-style packet
		if e.logger != nil {
			e.logger.InfoKV("workflow HTTP response received",
				"step", stepName, "step_index", stepIdx, "req", i,
				"status", resp.StatusCode, "time_ms", resp.Time.Milliseconds(),
				"bytes", len(resp.Body))
		}
		if e.verbose >= 2 && e.onPacket != nil {
			summary := fmt.Sprintf("workflow[%s] step[%d] req[%d]  status=%d  %s  %d bytes",
				stepName, stepIdx, i, resp.StatusCode,
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
					"step", stepName, "req", i, "status", resp.StatusCode,
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
		matchers := substituteMatcherPlaceholders(req.Matchers, eng)
		matched, ev := matcher.Evaluate(matchers, req.MatchersCondition, matchCtx)

		// Log matcher result
		if e.logger != nil {
			mTypes := make([]string, 0, len(req.Matchers))
			for _, m := range req.Matchers {
				mTypes = append(mTypes, m.Type)
			}
			if matched {
				e.logger.InfoKV("workflow matcher PASS",
					"step", stepName, "step_index", stepIdx, "req", i,
					"condition", req.MatchersCondition,
					"types", strings.Join(mTypes, ","), "evidence", ev)
			} else {
				e.logger.InfoKV("workflow matcher FAIL",
					"step", stepName, "step_index", stepIdx, "req", i,
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
			e.onRaw("匹配", "workflow[%s] step[%d] req[%d]  %s  cond=%s  types=%s  evidence=%q",
				stepName, stepIdx, i, status, req.MatchersCondition,
				strings.Join(mTypes, ","), ev)
		}

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
		return false, "", extracted
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

// substituteMatcherPlaceholders runs the placeholder engine over the
// string fields of each matcher so that templates can use placeholders
// like {{oob_label}} inside matchers.words (the YAML-loader bypasses
// the placeholder engine for matcher fields, only req.Raw is replaced).
func substituteMatcherPlaceholders(matchers []types.Matcher, eng *placeholder.Engine) []types.Matcher {
	out := make([]types.Matcher, len(matchers))
	for i, m := range matchers {
		out[i] = m // copy
		// Replace each string slice that may carry placeholders.
		out[i].Words = replaceEach(out[i].Words, eng)
		out[i].Regex = replaceEach(out[i].Regex, eng)
		out[i].Header = replaceEach(out[i].Header, eng)
		out[i].Binary = replaceEach(out[i].Binary, eng)
		out[i].JSONPath = eng.ReplaceWithEscape(out[i].JSONPath)
		out[i].JSONField = eng.ReplaceWithEscape(out[i].JSONField)
	}
	return out
}

func replaceEach(in []string, eng *placeholder.Engine) []string {
	if len(in) == 0 {
		return in
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = eng.ReplaceWithEscape(s)
	}
	return out
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
// It appends missing headers after the header block (after the blank line separating headers from body).
func injectGlobalHeaders(raw string, headers map[string]string) string {
	if len(headers) == 0 {
		return raw
	}
	sep := "\r\n\r\n"
	idx := strings.Index(raw, sep)
	if idx < 0 {
		idx = strings.Index(raw, "\n\n")
		if idx < 0 {
			return raw
		}
		idx += 2
	} else {
		idx += len(sep)
	}
	var sb strings.Builder
	sb.WriteString(raw[:idx])
	for k, v := range headers {
		sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	sb.WriteString(raw[idx:])
	return sb.String()
}
