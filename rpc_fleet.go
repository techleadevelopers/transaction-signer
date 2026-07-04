package main

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type rpcFailureKind int

const (
	rpcFailureRemote rpcFailureKind = iota
	rpcFailureTimeout
	rpcFailureRateLimited
	rpcFailureCapacityExhausted
	rpcFailureTransport
)

type rpcEndpointState struct {
	failures           uint32
	timeoutFailures    uint32
	rateLimitFailures  uint32
	disabled           bool
	disabledReason     string
	cooldownUntil      time.Time
	avgLatency         time.Duration
	lastFailureDecay   time.Time
	recentReservations []rpcReservation
	lastSelectedAt     time.Time
}

type rpcReservation struct {
	at    time.Time
	units uint32
}

type rpcEndpoint struct {
	id    int
	name  string
	url   string
	state rpcEndpointState
	mu    sync.Mutex
}

type rpcFleet struct {
	endpoints []*rpcEndpoint
	rotation  atomic.Uint64
}

type rpcHandle struct {
	id   int
	name string
	url  string
}

const (
	rpcBurstWindow   = 1200 * time.Millisecond
	rpcFailureDecay  = 20 * time.Second
	rpcBurstCapacity = uint32(18)
	rpcSendBurstCost = uint32(7)
)

func newRPCFleet(urls []string) *rpcFleet {
	seen := map[string]bool{}
	var endpoints []*rpcEndpoint
	for _, raw := range urls {
		url := strings.TrimSpace(raw)
		if url == "" || seen[url] {
			continue
		}
		seen[url] = true
		endpoints = append(endpoints, &rpcEndpoint{
			id:   len(endpoints),
			name: rpcEndpointName(len(endpoints), url),
			url:  url,
			state: rpcEndpointState{
				lastFailureDecay: time.Now(),
			},
		})
	}
	if len(endpoints) == 0 {
		endpoints = append(endpoints, &rpcEndpoint{id: 0, name: "bsc-default-0", url: "https://bsc-dataseed.binance.org/", state: rpcEndpointState{lastFailureDecay: time.Now()}})
	}
	return &rpcFleet{endpoints: endpoints}
}

func rpcEndpointName(id int, url string) string {
	lower := strings.ToLower(url)
	switch {
	case strings.Contains(lower, "alchemy"):
		return "alchemy-bsc-" + itoaSmall(id)
	case strings.Contains(lower, "ankr"):
		return "ankr-bsc-" + itoaSmall(id)
	case strings.Contains(lower, "binance"):
		return "binance-bsc-" + itoaSmall(id)
	default:
		return "bsc-rpc-" + itoaSmall(id)
	}
}

func itoaSmall(value int) string {
	return string(rune('0' + value))
}

func (f *rpcFleet) sendCandidates(limit int) []rpcHandle {
	now := time.Now()
	type scored struct {
		ep    *rpcEndpoint
		score float64
	}
	var candidates []scored
	for _, ep := range f.endpoints {
		if score, ok := ep.score(now); ok {
			candidates = append(candidates, scored{ep: ep, score: score})
		}
	}
	if len(candidates) == 0 {
		for _, ep := range f.endpoints {
			ep.mu.Lock()
			ep.state.cooldownUntil = time.Time{}
			ep.mu.Unlock()
			if score, ok := ep.score(now); ok {
				candidates = append(candidates, scored{ep: ep, score: score})
			}
		}
	}
	for i := 0; i < len(candidates); i++ {
		for j := i + 1; j < len(candidates); j++ {
			if candidates[j].score < candidates[i].score {
				candidates[i], candidates[j] = candidates[j], candidates[i]
			}
		}
	}
	topN := len(candidates)
	if topN > 2 {
		topN = 2
	}
	if topN > 1 {
		shift := int(f.rotation.Add(1)-1) % topN
		candidates = append(candidates[shift:topN], candidates[:shift]...)
	}
	if limit <= 0 || limit > len(candidates) {
		limit = len(candidates)
	}
	handles := make([]rpcHandle, 0, limit)
	for _, item := range candidates[:limit] {
		item.ep.reserve(now)
		handles = append(handles, rpcHandle{id: item.ep.id, name: item.ep.name, url: item.ep.url})
	}
	return handles
}

func (ep *rpcEndpoint) score(now time.Time) (float64, bool) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	ep.prune(now)
	ep.decay(now)
	if ep.state.disabled || (!ep.state.cooldownUntil.IsZero() && ep.state.cooldownUntil.After(now)) {
		return 0, false
	}
	burst := ep.burstLoad(now)
	burstRatio := float64(burst) / float64(rpcBurstCapacity)
	latencyMs := 120.0
	if ep.state.avgLatency > 0 {
		latencyMs = float64(ep.state.avgLatency.Milliseconds())
	}
	recencyPenalty := 0.0
	if !ep.state.lastSelectedAt.IsZero() {
		if elapsed := now.Sub(ep.state.lastSelectedAt); elapsed < 180*time.Millisecond {
			recencyPenalty = float64((180*time.Millisecond - elapsed).Milliseconds()) * 2.4
		}
	}
	burstPenalty := burstRatio * burstRatio * 2200
	if burstRatio >= 1 {
		burstPenalty = 25000 + (burstRatio-1)*8000
	}
	return latencyMs +
		float64(ep.state.failures)*180 +
		float64(ep.state.rateLimitFailures)*900 +
		burstPenalty +
		recencyPenalty, true
}

func (ep *rpcEndpoint) reserve(now time.Time) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	ep.prune(now)
	ep.state.recentReservations = append(ep.state.recentReservations, rpcReservation{at: now, units: rpcSendBurstCost})
	ep.state.lastSelectedAt = now
	if ep.burstLoad(now) >= rpcBurstCapacity*2 {
		ep.state.cooldownUntil = now.Add(900 * time.Millisecond)
	}
}

func (f *rpcFleet) recordSuccess(id int, latency time.Duration) {
	ep := f.endpoint(id)
	if ep == nil {
		return
	}
	now := time.Now()
	ep.mu.Lock()
	defer ep.mu.Unlock()
	ep.prune(now)
	ep.decay(now)
	if ep.state.avgLatency > 0 {
		ep.state.avgLatency = time.Duration(float64(ep.state.avgLatency)*0.72 + float64(latency)*0.28)
	} else {
		ep.state.avgLatency = latency
	}
	if ep.state.failures > 0 {
		ep.state.failures--
	}
	if ep.state.timeoutFailures > 0 {
		ep.state.timeoutFailures--
	}
	if ep.state.rateLimitFailures > 0 {
		ep.state.rateLimitFailures--
	}
	if !ep.state.cooldownUntil.IsZero() && ep.state.cooldownUntil.Before(now) {
		ep.state.cooldownUntil = time.Time{}
	}
}

func (f *rpcFleet) recordFailure(id int, kind rpcFailureKind) {
	ep := f.endpoint(id)
	if ep == nil {
		return
	}
	now := time.Now()
	ep.mu.Lock()
	defer ep.mu.Unlock()
	ep.prune(now)
	ep.decay(now)
	ep.state.failures++
	cooldown := 500 * time.Millisecond
	switch kind {
	case rpcFailureRateLimited:
		ep.state.rateLimitFailures++
		cooldown = time.Duration(2*(1<<minUint32(ep.state.rateLimitFailures, 4))) * time.Second
	case rpcFailureCapacityExhausted:
		ep.state.rateLimitFailures += 10
		ep.state.disabled = true
		ep.state.disabledReason = "provider capacity exhausted"
		cooldown = 24 * time.Hour
	case rpcFailureTimeout:
		ep.state.timeoutFailures++
		cooldown = time.Duration(400*(1<<minUint32(ep.state.timeoutFailures, 5))) * time.Millisecond
	case rpcFailureTransport:
		cooldown = 700 * time.Millisecond
	}
	if cooldown > 45*time.Second {
		cooldown = 45 * time.Second
	}
	until := now.Add(cooldown)
	if ep.state.cooldownUntil.Before(until) {
		ep.state.cooldownUntil = until
	}
}

func classifyRPCFailure(err error) rpcFailureKind {
	if err == nil {
		return rpcFailureRemote
	}
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "monthly capacity limit exceeded"),
		strings.Contains(lower, "capacity limit exceeded"),
		strings.Contains(lower, "quota exceeded"),
		strings.Contains(lower, "billing"):
		return rpcFailureCapacityExhausted
	case strings.Contains(lower, "429"),
		strings.Contains(lower, "rate limit"),
		strings.Contains(lower, "too many requests"),
		strings.Contains(lower, "throughput limit"):
		return rpcFailureRateLimited
	case strings.Contains(lower, "timeout"),
		strings.Contains(lower, "timed out"),
		strings.Contains(lower, "deadline exceeded"):
		return rpcFailureTimeout
	case strings.Contains(lower, "connection"),
		strings.Contains(lower, "socket"),
		strings.Contains(lower, "dns"),
		strings.Contains(lower, "econnreset"),
		strings.Contains(lower, "broken pipe"),
		strings.Contains(lower, "eof"):
		return rpcFailureTransport
	default:
		return rpcFailureRemote
	}
}

func (f *rpcFleet) endpoint(id int) *rpcEndpoint {
	for _, ep := range f.endpoints {
		if ep.id == id {
			return ep
		}
	}
	return nil
}

func (ep *rpcEndpoint) prune(now time.Time) {
	keep := ep.state.recentReservations[:0]
	for _, item := range ep.state.recentReservations {
		if now.Sub(item.at) <= rpcBurstWindow {
			keep = append(keep, item)
		}
	}
	ep.state.recentReservations = keep
}

func (ep *rpcEndpoint) decay(now time.Time) {
	if ep.state.lastFailureDecay.IsZero() {
		ep.state.lastFailureDecay = now
		return
	}
	steps := uint32(now.Sub(ep.state.lastFailureDecay) / rpcFailureDecay)
	if steps == 0 {
		return
	}
	ep.state.lastFailureDecay = ep.state.lastFailureDecay.Add(time.Duration(steps) * rpcFailureDecay)
	ep.state.failures = subtractUint32(ep.state.failures, steps*2)
	ep.state.timeoutFailures = subtractUint32(ep.state.timeoutFailures, steps*2)
	ep.state.rateLimitFailures = subtractUint32(ep.state.rateLimitFailures, steps*4)
}

func (ep *rpcEndpoint) burstLoad(now time.Time) uint32 {
	var total uint32
	for _, item := range ep.state.recentReservations {
		if now.Sub(item.at) <= rpcBurstWindow {
			total += item.units
		}
	}
	return total
}

func subtractUint32(value, amount uint32) uint32 {
	if amount > value {
		return 0
	}
	return value - amount
}

func minUint32(value, max uint32) uint32 {
	if value > max {
		return max
	}
	return value
}
