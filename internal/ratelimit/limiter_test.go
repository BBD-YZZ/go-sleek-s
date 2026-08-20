package ratelimit

import (
	"sync"
	"testing"
	"time"
)

func TestNewBucketPreFills(t *testing.T) {
	tb := newBucket(5)
	// Should have exactly 5 tokens pre-filled
	if len(tb.tokens) != 5 {
		t.Errorf("expected 5 pre-filled tokens, got %d", len(tb.tokens))
	}
}

func TestWaitBlocksWhenEmpty(t *testing.T) {
	limit := New(2) // 2 req/s
	// Drain all tokens
	for i := 0; i < 2; i++ {
		limit.Wait("host1")
	}
	// Next Wait should block until a token is available
	start := time.Now()
	limit.Wait("host1")
	elapsed := time.Since(start)
	// Should have waited at least ~500ms (1/2 req/s = 500ms per token)
	if elapsed < 400*time.Millisecond {
		t.Errorf("expected to wait ~500ms, got %v", elapsed)
	}
}

func TestWaitDoesNotBlockWhenRateIsZero(t *testing.T) {
	limit := New(0)
	start := time.Now()
	limit.Wait("host1")
	elapsed := time.Since(start)
	if elapsed > 50*time.Millisecond {
		t.Errorf("expected near-instant return when rate=0, got %v", elapsed)
	}
}

func TestPerHostLimiting(t *testing.T) {
	limit := New(10)
	// Two different hosts should not interfere
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(2)
		go func() { wg.Done(); limit.Wait("hostA") }()
		go func() { wg.Done(); limit.Wait("hostB") }()
	}
	wg.Wait()
	elapsed := time.Since(start)
	// 10 requests per host at 10 req/s = ~1s total (sequential per host)
	// But they run in parallel across hosts, so should be ~1s not ~2s
	if elapsed > 2500*time.Millisecond {
		t.Errorf("per-host limiting seems broken, elapsed %v", elapsed)
	}
}

func TestRefillTokens(t *testing.T) {
	limit := New(100) // 100 req/s
	// Drain all tokens
	for i := 0; i < 100; i++ {
		limit.Wait("host1")
	}
	// Wait 50ms — should refill ~5 tokens at 100/s
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	// These should complete quickly since tokens were refilled
	for i := 0; i < 5; i++ {
		limit.Wait("host1")
	}
	elapsed := time.Since(start)
	if elapsed > 100*time.Millisecond {
		t.Errorf("token refill not working, elapsed %v", elapsed)
	}
}
