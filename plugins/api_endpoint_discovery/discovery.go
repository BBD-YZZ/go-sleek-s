package api_endpoint_discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gosleek/gosleek/internal/httpclient"
	"github.com/gosleek/gosleek/internal/plugin"
	"github.com/gosleek/gosleek/pkg/types"
)

// APIDiscoveryPlugin discovers API endpoints by probing common actuator/config endpoints.
type APIDiscoveryPlugin struct{}

func (p *APIDiscoveryPlugin) Meta() types.TemplateMeta {
	return types.TemplateMeta{
		ID:          "api-endpoint-discovery",
		Name:        "API 端点自动发现",
		Description: "通过探测常见 Actuator/Config 端点自动发现 API 路径",
		Severity:    "info",
		Author:      "gosleek",
		Tags:        []string{"discovery", "api", "actuator", "recon"},
	}
}

func (p *APIDiscoveryPlugin) Fingerprints() []types.FingerprintRule {
	return []types.FingerprintRule{
		{Title: "Spring Boot"},
		{Header: []string{"X-Application-Context"}},
	}
}

func (p *APIDiscoveryPlugin) NeedsOOB() bool { return false }

func (p *APIDiscoveryPlugin) Verify(ctx context.Context, pctx *plugin.Context) (*types.Result, error) {
	// Probe common endpoints to discover API structure
	endpoints := []string{
		"/actuator",
		"/actuator/env",
		"/actuator/health",
		"/actuator/info",
		"/actuator/mappings",
		"/actuator/beans",
		"/api/v1",
		"/v1",
		"/swagger-ui.html",
		"/v2/api-docs",
		"/graphql",
		"/papi",
	}

	var discovered []string
	for _, ep := range endpoints {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		rawReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: gosleek/1.0\r\nConnection: close\r\n\r\n", ep, pctx.TargetInfo.Hostname)
		parsed, err := httpclient.ParseRaw(rawReq)
		if err != nil {
			continue
		}
		resp, err := pctx.Client.SendParsed(ctx, pctx.Target, parsed)
		if err != nil {
			continue
		}
		// 2xx or 3xx = endpoint exists
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			discovered = append(discovered, ep)
		}
	}

	if len(discovered) == 0 {
		return nil, nil
	}

	// Build JSON output with discovered endpoints
	output, _ := json.MarshalIndent(map[string]interface{}{
		"target":        pctx.Target,
		"discovered":    discovered,
		"count":         len(discovered),
		"discovery_time": time.Now().Format("2006-01-02 15:04:05"),
	}, "", "  ")

	return &types.Result{
		TemplateID:  p.Meta().ID,
		Name:        p.Meta().Name,
		Severity:    p.Meta().Severity,
		Description: fmt.Sprintf("发现 %d 个活跃端点", len(discovered)),
		Target:      pctx.Target,
		MatchedAt:   time.Now().Format("2006-01-02 15:04:05"),
		Tags:        p.Meta().Tags,
		Evidence:    strings.Join(discovered, ", "),
		Extracted: map[string]string{
			"endpoints": strings.Join(discovered, "|"),
		},
		RawResponse: string(output),
	}, nil
}
