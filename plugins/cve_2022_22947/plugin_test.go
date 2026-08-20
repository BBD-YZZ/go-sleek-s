package cve_2022_22947

import (
	"testing"

	"github.com/gosleek/gosleek/internal/plugin"
)

func TestCVE202222947Meta(t *testing.T) {
	p := &CVE202222947{}
	meta := p.Meta()
	if meta.ID != "CVE-2022-22947-go" {
		t.Errorf("expected ID 'CVE-2022-22947-go', got %q", meta.ID)
	}
	if meta.Severity != "critical" {
		t.Errorf("expected severity 'critical', got %q", meta.Severity)
	}
	if len(meta.Tags) == 0 {
		t.Error("expected non-empty tags")
	}
}

func TestCVE202222947NeedsOOB(t *testing.T) {
	p := &CVE202222947{}
	if p.NeedsOOB() {
		t.Error("CVE-2022-22947 should not need OOB")
	}
}

func TestCVE202222947PluginInterface(t *testing.T) {
	// Verify the plugin satisfies the plugin.Plugin interface
	var _ plugin.Plugin = &CVE202222947{}
}
