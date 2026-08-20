package api_endpoint_discovery

import (
	"testing"

	"github.com/gosleek/gosleek/internal/plugin"
)

func TestAPIDiscoveryMeta(t *testing.T) {
	p := &APIDiscoveryPlugin{}
	meta := p.Meta()
	if meta.ID != "api-endpoint-discovery" {
		t.Errorf("expected ID 'api-endpoint-discovery', got %q", meta.ID)
	}
	if meta.Severity != "info" {
		t.Errorf("expected severity 'info', got %q", meta.Severity)
	}
}

func TestAPIDiscoveryFingerprints(t *testing.T) {
	p := &APIDiscoveryPlugin{}
fps := p.Fingerprints()
	if len(fps) != 2 {
		t.Errorf("expected 2 fingerprint rules, got %d", len(fps))
	}
}

func TestAPIDiscoveryNeedsOOB(t *testing.T) {
	p := &APIDiscoveryPlugin{}
	if p.NeedsOOB() {
		t.Error("api-endpoint-discovery should not need OOB")
	}
}

func TestAPIDiscoveryPluginInterface(t *testing.T) {
	var _ plugin.Plugin = &APIDiscoveryPlugin{}
}
