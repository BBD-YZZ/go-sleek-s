package ratelimit

import (
	"sync"
	"time"
)

// Limiter is a per-host rate limiter using token bucket.
type Limiter struct {
	mu       sync.Mutex
	limiters map[string]*tokenBucket
	rate     int // tokens per second
}

type tokenBucket struct {
	tokens   chan struct{}
	lastFill time.Time
	rate     int
	mu       sync.Mutex
}

// New creates a rate limiter with the given global rate (req/sec).
func New(rate int) *Limiter {
	return &Limiter{
		limiters: make(map[string]*tokenBucket),
		rate:     rate,
	}
}

// Wait blocks until a token is available for the given host.
func (l *Limiter) Wait(host string) {
	if l.rate <= 0 {
		return
	}
	l.mu.Lock()
	tb, ok := l.limiters[host]
	if !ok {
		tb = newBucket(l.rate)
		l.limiters[host] = tb
	}
	l.mu.Unlock()
	tb.take()
}

// SetRate updates the global rate limit.
func (l *Limiter) SetRate(rate int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rate = rate
	// Update existing buckets
	for _, tb := range l.limiters {
		tb.mu.Lock()
		tb.rate = rate
		tb.mu.Unlock()
	}
}

// GetRate returns the current global rate.
func (l *Limiter) GetRate() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.rate
}

func newBucket(rate int) *tokenBucket {
	tb := &tokenBucket{
		tokens:   make(chan struct{}, rate),
		lastFill: time.Now(),
		rate:     rate,
	}
	// Pre-fill the bucket so the first `rate` requests don't block.
	for i := 0; i < rate; i++ {
		tb.tokens <- struct{}{}
	}
	return tb
}

// take consumes one token, blocking until one is available.
func (b *tokenBucket) take() {
	for {
		b.mu.Lock()
		// Refill tokens proportional to elapsed time
		elapsed := time.Since(b.lastFill)
		refill := int(elapsed.Seconds() * float64(b.rate))
		if refill > 0 {
			added := 0
			for i := 0; i < refill && len(b.tokens) < b.rate; i++ {
				select {
				case b.tokens <- struct{}{}:
					added++
				default:
				}
			}
			// Advance lastFill by exactly the time that corresponds to the
			// tokens we just added, preserving sub-second precision.
			if added > 0 {
				b.lastFill = b.lastFill.Add(
					time.Duration(added) * time.Second / time.Duration(b.rate),
				)
			} else {
				// Bucket was full — tokens couldn't be added, so just advance
				// the clock to now to avoid re-counting this elapsed window.
				b.lastFill = time.Now()
			}
		}
		b.mu.Unlock()

		// Try to consume a token (non-blocking first, to keep fast path cheap)
		select {
		case <-b.tokens:
			return
		default:
			// No token available — wait one interval then retry the loop.
			// The loop guarantees we eventually consume a real token.
			interval := time.Second / time.Duration(b.rate)
			time.Sleep(interval)
		}
	}
}
