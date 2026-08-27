package cve_2022_22963

import (
	"testing"

	"github.com/gosleek/gosleek/internal/plugin"
)

func TestCVE202222963Meta(t *testing.T) {
	p := &CVE202222963{}
	meta := p.Meta()
	if meta.ID != "CVE-2022-22963-go" {
		t.Errorf("expected ID 'CVE-2022-22963-go', got %q", meta.ID)
	}
	if meta.Severity != "critical" {
		t.Errorf("expected severity 'critical', got %q", meta.Severity)
	}
}

func TestCVE202222963NeedsOOB(t *testing.T) {
	p := &CVE202222963{}
	if !p.NeedsOOB() {
		t.Error("CVE-2022-22963 should need OOB")
	}
}

func TestCVE202222963PluginInterface(t *testing.T) {
	var _ plugin.Plugin = &CVE202222963{}
}
