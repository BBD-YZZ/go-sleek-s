package httpclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRedirectChainCapture verifies that the client captures intermediate
// redirect responses in the RedirectChain field of the final Response.
func TestRedirectChainCapture(t *testing.T) {
	redirectCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/step1":
			redirectCount++
			w.Header().Set("Location", "/step2")
			w.WriteHeader(http.StatusFound)
		case "/step2":
			redirectCount++
			w.Header().Set("Location", "/final")
			w.WriteHeader(http.StatusMovedPermanently)
		case "/final":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("final response"))
		}
	}))
	defer srv.Close()

	cfg := ClientConfig{
		MaxRedirects: 10,
		FollowRedirect: true,
	}
	client := New(cfg)

	req := &RawRequest{
		Method: "GET",
		Path:   "/step1",
		Headers: map[string]string{
			"Host": srv.Listener.Addr().String(),
		},
	}

	resp, err := client.SendParsed(context.Background(), srv.URL, req)
	if err != nil {
		t.Fatalf("SendParsed failed: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	if len(resp.RedirectChain) != 2 {
		t.Fatalf("expected 2 redirect entries, got %d", len(resp.RedirectChain))
	}

	// Verify first redirect entry
	if resp.RedirectChain[0].StatusCode != http.StatusFound {
		t.Errorf("expected redirect[0] status %d, got %d", http.StatusFound, resp.RedirectChain[0].StatusCode)
	}
	if resp.RedirectChain[0].Location != "/step2" {
		t.Errorf("expected redirect[0] location '/step2', got '%s'", resp.RedirectChain[0].Location)
	}

	// Verify second redirect entry
	if resp.RedirectChain[1].StatusCode != http.StatusMovedPermanently {
		t.Errorf("expected redirect[1] status %d, got %d", http.StatusMovedPermanently, resp.RedirectChain[1].StatusCode)
	}
	if resp.RedirectChain[1].Location != "/final" {
		t.Errorf("expected redirect[1] location '/final', got '%s'", resp.RedirectChain[1].Location)
	}

	// Verify raw response is non-empty
	if resp.RedirectChain[0].Raw == "" {
		t.Error("expected non-empty raw response for redirect[0]")
	}
}

// TestRedirectChainNoRedirect verifies that non-redirect responses have an
// empty RedirectChain.
func TestRedirectChainNoRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	cfg := ClientConfig{
		MaxRedirects: 10,
		FollowRedirect: true,
	}
	client := New(cfg)

	req := &RawRequest{
		Method: "GET",
		Path:   "/",
		Headers: map[string]string{
			"Host": srv.Listener.Addr().String(),
		},
	}

	resp, err := client.SendParsed(context.Background(), srv.URL, req)
	if err != nil {
		t.Fatalf("SendParsed failed: %v", err)
	}

	if len(resp.RedirectChain) != 0 {
		t.Errorf("expected 0 redirect entries for non-redirect response, got %d", len(resp.RedirectChain))
	}
}

// TestRedirectChainMaxLimit verifies that redirect following stops at max limit.
func TestRedirectChainMaxLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always redirect back to /loop
		w.Header().Set("Location", "/loop")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	cfg := ClientConfig{
		MaxRedirects: 2,
		FollowRedirect: true,
	}
	client := New(cfg)

	req := &RawRequest{
		Method: "GET",
		Path:   "/loop",
		Headers: map[string]string{
			"Host": srv.Listener.Addr().String(),
		},
	}

	resp, err := client.SendParsed(context.Background(), srv.URL, req)
	if err != nil {
		t.Fatalf("SendParsed failed: %v", err)
	}

	// Should stop at max 2 redirects, returning the last redirect response.
	if len(resp.RedirectChain) > 2 {
		t.Errorf("expected at most 2 redirect entries, got %d", len(resp.RedirectChain))
	}
	if resp.StatusCode != http.StatusFound {
		t.Errorf("expected status %d (last redirect), got %d", http.StatusFound, resp.StatusCode)
	}
}
