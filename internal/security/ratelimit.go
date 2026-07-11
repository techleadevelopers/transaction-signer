package security

import (
	"sync"
	"time"
)

// RateLimiter interface para diferentes algoritmos
type RateLimiter interface {
	Allow(key string) bool
	AllowWithLimit(key string, limit int, window time.Duration) bool
	Reset(key string)
	Metrics() RateLimitMetrics
}

// RateLimitMetrics métricas do rate limiter
type RateLimitMetrics struct {
	TotalRequests int64
	Allowed       int64
	Rejected      int64
	CurrentActive int64
	LastReset     time.Time
}

// TokenBucket implementa Token Bucket Algorithm
type TokenBucket struct {
	mu      sync.RWMutex
	buckets map[string]*tokenBucket
	rate    float64 // tokens por segundo
	burst   int     // capacidade máxima
}

type tokenBucket struct {
	tokens     float64
	lastRefill time.Time
}

func NewTokenBucket(rate float64, burst int) *TokenBucket {
	return &TokenBucket{
		buckets: make(map[string]*tokenBucket),
		rate:    rate,
		burst:   burst,
	}
}

func (tb *TokenBucket) Allow(key string) bool {
	return tb.AllowWithLimit(key, tb.burst, time.Second)
}

func (tb *TokenBucket) AllowWithLimit(key string, limit int, window time.Duration) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	bucket, exists := tb.buckets[key]
	if !exists {
		bucket = &tokenBucket{
			tokens:     float64(limit),
			lastRefill: time.Now(),
		}
		tb.buckets[key] = bucket
	}

	// Refill tokens
	now := time.Now()
	elapsed := now.Sub(bucket.lastRefill).Seconds()
	bucket.tokens = min(float64(limit), bucket.tokens+elapsed*tb.rate)
	bucket.lastRefill = now

	if bucket.tokens >= 1.0 {
		bucket.tokens--
		return true
	}
	return false
}

func (tb *TokenBucket) Reset(key string) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	delete(tb.buckets, key)
}

func (tb *TokenBucket) Metrics() RateLimitMetrics {
	tb.mu.RLock()
	defer tb.mu.RUnlock()
	return RateLimitMetrics{
		CurrentActive: int64(len(tb.buckets)),
		LastReset:     time.Now(),
	}
}

// SlidingWindow implementa Sliding Window Algorithm
type SlidingWindow struct {
	mu      sync.RWMutex
	windows map[string][]time.Time
	limit   int
	window  time.Duration
}

func NewSlidingWindow(limit int, window time.Duration) *SlidingWindow {
	return &SlidingWindow{
		windows: make(map[string][]time.Time),
		limit:   limit,
		window:  window,
	}
}

func (sw *SlidingWindow) Allow(key string) bool {
	return sw.AllowWithLimit(key, sw.limit, sw.window)
}

func (sw *SlidingWindow) AllowWithLimit(key string, limit int, window time.Duration) bool {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-window)

	// Clean old entries
	requests, exists := sw.windows[key]
	if !exists {
		sw.windows[key] = []time.Time{now}
		return true
	}

	// Filter requests dentro da janela
	var valid []time.Time
	for _, t := range requests {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= limit {
		sw.windows[key] = valid
		return false
	}

	// Adiciona nova requisição
	sw.windows[key] = append(valid, now)
	return true
}

func (sw *SlidingWindow) Reset(key string) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	delete(sw.windows, key)
}

func (sw *SlidingWindow) Metrics() RateLimitMetrics {
	sw.mu.RLock()
	defer sw.mu.RUnlock()
	return RateLimitMetrics{
		CurrentActive: int64(len(sw.windows)),
		LastReset:     time.Now(),
	}
}

// RateLimiterFactory cria rate limiters com base no tipo
type RateLimiterType string

const (
	TokenBucketType   RateLimiterType = "token_bucket"
	SlidingWindowType RateLimiterType = "sliding_window"
)

func NewRateLimiter(limiterType RateLimiterType, limit int, window time.Duration) RateLimiter {
	switch limiterType {
	case TokenBucketType:
		rate := float64(limit) / window.Seconds()
		return NewTokenBucket(rate, limit)
	case SlidingWindowType:
		return NewSlidingWindow(limit, window)
	default:
		return NewTokenBucket(float64(limit)/window.Seconds(), limit)
	}
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
