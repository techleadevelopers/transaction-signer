package security

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

type RequestContext struct {
	RequestID string
	Timestamp int64
	Nonce     string
	APIKey    string
	ClientIP  string
	UserAgent string
	Path      string
	Method    string
	BodyHash  string
	Validated bool
	StartTime time.Time
}

type RequestValidator struct {
	hmac         *HMACValidator
	nonceManager *NonceManager
	rateLimiter  RateLimiter
	maxBodySize  int64
}

type RequestValidatorConfig struct {
	HMACSecret      string
	HMACMaxSkew     int64
	NonceStore      NonceStore
	NonceTTL        time.Duration
	RateLimit       int
	RateWindow      time.Duration
	RateLimiterType RateLimiterType
	MaxBodySize     int64
	OldSecret       string
}

func NewRequestValidator(config RequestValidatorConfig) *RequestValidator {
	hmacValidator := NewHMACValidator(config.HMACSecret, config.HMACMaxSkew)
	if config.OldSecret != "" {
		hmacValidator.SetOldSecret(config.OldSecret)
	}
	return &RequestValidator{
		hmac:         hmacValidator,
		nonceManager: NewNonceManager(config.NonceStore, config.NonceTTL),
		rateLimiter:  NewRateLimiter(config.RateLimiterType, config.RateLimit, config.RateWindow),
		maxBodySize:  config.MaxBodySize,
	}
}

func (rv *RequestValidator) ValidateRequest(r *http.Request) (*RequestContext, error) {
	ctx := &RequestContext{
		RequestID: generateRequestID(),
		StartTime: time.Now(),
		Path:      r.URL.Path,
		Method:    r.Method,
		ClientIP:  getClientIP(r),
		UserAgent: r.UserAgent(),
	}

	if rv.maxBodySize > 0 && r.ContentLength > rv.maxBodySize {
		return ctx, fmt.Errorf("body size exceeds limit: %d > %d", r.ContentLength, rv.maxBodySize)
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, rv.maxBodySize))
	if err != nil {
		return ctx, fmt.Errorf("failed to read body: %w", err)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	bodyHash := sha256.Sum256(body)
	ctx.BodyHash = hex.EncodeToString(bodyHash[:])

	tsStr := r.Header.Get("X-Request-Timestamp")
	nonce := r.Header.Get("X-Request-Nonce")
	hmacHeader := r.Header.Get("X-Request-Signature")
	legacySignerHMAC := false
	if tsStr == "" && nonce == "" && hmacHeader == "" {
		tsStr = r.Header.Get("x-ts")
		nonce = r.Header.Get("x-nonce")
		hmacHeader = r.Header.Get("x-signer-hmac")
		legacySignerHMAC = hmacHeader != ""
	}

	apiKey := r.Header.Get("X-API-Key")
	if apiKey != "" {
		ctx.APIKey = apiKey
	}

	if hmacHeader != "" {
		if legacySignerHMAC {
			err = rv.hmac.ValidateRawBodyHMAC(tsStr, nonce, hmacHeader, body)
		} else {
			err = rv.hmac.ValidateHMAC(tsStr, nonce, hmacHeader, body)
		}
		if err != nil {
			return ctx, fmt.Errorf("hmac validation failed: %w", err)
		}
		ctx.Validated = true
	}

	if nonce != "" {
		if err := rv.nonceManager.ValidateNonce(r.Context(), nonce); err != nil {
			return ctx, fmt.Errorf("nonce validation failed: %w", err)
		}
	}

	rateKey := ctx.ClientIP
	if ctx.APIKey != "" {
		rateKey = ctx.APIKey
	}
	if !rv.rateLimiter.Allow(rateKey) {
		return ctx, fmt.Errorf("rate limit exceeded for key: %s", rateKey)
	}

	if tsStr != "" {
		ts, _ := strconv.ParseInt(tsStr, 10, 64)
		ctx.Timestamp = ts
	}
	ctx.Nonce = nonce
	return ctx, nil
}

func (rv *RequestValidator) SecurityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, err := rv.ValidateRequest(r)
		if err != nil {
			http.Error(w, fmt.Sprintf("Security validation failed: %v", err), http.StatusUnauthorized)
			return
		}
		ctxValue := context.WithValue(r.Context(), RequestContextKey, ctx)
		next.ServeHTTP(w, r.WithContext(ctxValue))
	})
}

type contextKey string

const RequestContextKey contextKey = "request_context"

func GetRequestContext(ctx context.Context) *RequestContext {
	if val := ctx.Value(RequestContextKey); val != nil {
		if rc, ok := val.(*RequestContext); ok {
			return rc
		}
	}
	return nil
}

func generateRequestID() string {
	nonce := GenerateNonce()
	if len(nonce) > 8 {
		nonce = nonce[:8]
	}
	return fmt.Sprintf("req-%d-%s", time.Now().UnixNano(), hex.EncodeToString([]byte(nonce)))
}

func getClientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	return r.RemoteAddr
}
