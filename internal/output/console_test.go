package output

import (
	"testing"
)

func TestParseRequestMethodPath(t *testing.T) {
	tests := []struct {
		name         string
		raw          string
		wantMethod   string
		wantPath     string
	}{
		{
			name:       "GET with full headers",
			raw:        "GET /actuator/env HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantMethod: "GET",
			wantPath:   "/actuator/env",
		},
		{
			name:       "POST with body",
			raw:        "POST /functionRouter HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/plain\r\n\r\n{payload}",
			wantMethod: "POST",
			wantPath:   "/functionRouter",
		},
		{
			name:       "request without headers",
			raw:        "GET / HTTP/1.1",
			wantMethod: "GET",
			wantPath:   "/",
		},
		{
			name:       "invalid request",
			raw:        "invalid",
			wantMethod: "invalid",
			wantPath:   "",
		},
		{
			name:       "empty request",
			raw:        "",
			wantMethod: "",
			wantPath:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method, path := parseRequestMethodPath(tt.raw)
			if method != tt.wantMethod {
				t.Errorf("parseRequestMethodPath() method = %q, want %q", method, tt.wantMethod)
			}
			if path != tt.wantPath {
				t.Errorf("parseRequestMethodPath() path = %q, want %q", path, tt.wantPath)
			}
		})
	}
}

func TestBuildVulnURL(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		path    string
		wantURL string
	}{
		{
			name:    "relative path with leading slash",
			target:  "http://192.168.80.128:8080",
			path:    "/actuator/env",
			wantURL: "http://192.168.80.128:8080/actuator/env",
		},
		{
			name:    "path replaces target path",
			target:  "http://example.com/api",
			path:    "/env",
			wantURL: "http://example.com/env",
		},
		{
			name:    "absolute URL in path",
			target:  "http://example.com",
			path:    "http://evil.com/callback",
			wantURL: "http://evil.com/callback",
		},
		{
			name:    "path with query params",
			target:  "http://example.com",
			path:    "/search?q=test",
			wantURL: "http://example.com/search%3Fq=test", // url.Parse encodes ?
		},
		{
			name:    "path with trailing slash",
			target:  "http://example.com/",
			path:    "api/v1",
			wantURL: "http://example.com/api/v1",
		},
		{
			name:    "invalid target falls back",
			target:  "://invalid",
			path:    "/test",
			wantURL: "://invalid/test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildVulnURL(tt.target, tt.path)
			if got != tt.wantURL {
				t.Errorf("buildVulnURL() = %q, want %q", got, tt.wantURL)
			}
		})
	}
}
