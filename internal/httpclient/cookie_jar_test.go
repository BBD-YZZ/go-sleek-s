package httpclient

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"
)

// TestCookieJarPersistence verifies that cookies set by the server in one
// request are sent back in subsequent requests.
func TestCookieJarPersistence(t *testing.T) {
	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		switch r.URL.Path {
		case "/set-cookie":
			cookie := &http.Cookie{
				Name:     "session_id",
				Value:    "abc123",
				Expires:  time.Now().Add(24 * time.Hour),
				HttpOnly: true,
			}
			http.SetCookie(w, cookie)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("cookie set"))
		case "/check-cookie":
			c, err := r.Cookie("session_id")
			if err != nil || c == nil {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte("no cookie"))
				return
			}
			if c.Value != "abc123" {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("wrong cookie value"))
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("cookie present: " + c.Value))
		}
	}))
	defer srv.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("failed to create cookie jar: %v", err)
	}

	cfg := ClientConfig{
		MaxRedirects:   10,
		FollowRedirect: true,
	}
	client := New(cfg)

	// Step 1: Set a cookie.
	ctx1 := SetCookieJar(context.Background(), jar)
	req1 := &RawRequest{
		Method: "GET",
		Path:   "/set-cookie",
		Headers: map[string]string{
			"Host": srv.Listener.Addr().String(),
		},
	}
	resp1, err := client.SendParsed(ctx1, srv.URL, req1)
	if err != nil {
		t.Fatalf("step 1 SendParsed failed: %v", err)
	}
	if resp1.StatusCode != 200 {
		t.Errorf("step 1: expected status 200, got %d", resp1.StatusCode)
	}

	// Step 2: Verify the cookie was stored by the jar and sent back.
	ctx2 := SetCookieJar(context.Background(), jar)
	req2 := &RawRequest{
		Method: "GET",
		Path:   "/check-cookie",
		Headers: map[string]string{
			"Host": srv.Listener.Addr().String(),
		},
	}
	resp2, err := client.SendParsed(ctx2, srv.URL, req2)
	if err != nil {
		t.Fatalf("step 2 SendParsed failed: %v", err)
	}
	if resp2.StatusCode != 200 {
		t.Fatalf("step 2: expected status 200, got %d: %s", resp2.StatusCode, resp2.Body)
	}
	if resp2.Body != "cookie present: abc123" {
		t.Errorf("step 2: unexpected body: %s", resp2.Body)
	}

	_ = requestCount
}
