package jwt_secret_bruteforce

import (
	"testing"

	"github.com/gosleek/gosleek/internal/plugin"
)

func TestJWTMeta(t *testing.T) {
	p := &JWTSecretBruteforce{}
	meta := p.Meta()
	if meta.ID != "jwt-weak-secret-bruteforce" {
		t.Errorf("expected ID 'jwt-weak-secret-bruteforce', got %q", meta.ID)
	}
	if meta.Severity != "high" {
		t.Errorf("expected severity 'high', got %q", meta.Severity)
	}
}

func TestJWTNeedsOOB(t *testing.T) {
	p := &JWTSecretBruteforce{}
	if p.NeedsOOB() {
		t.Error("jwt-secret-bruteforce should not need OOB")
	}
}

func TestJWTPluginInterface(t *testing.T) {
	var _ plugin.Plugin = &JWTSecretBruteforce{}
}
