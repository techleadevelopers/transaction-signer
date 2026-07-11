// Package security fornece funcionalidades de segurança para APIs:
//
// - HMAC-SHA256 com validação de assinatura
// - Anti-replay com Nonces (memória/Redis)
// - Rate Limiting (Token Bucket / Sliding Window)
// - Request Validation completa
// - Middleware HTTP
// - Rotação de segredos
// - Métricas e auditoria
//
// Uso básico:
//
//   store := security.NewInMemoryNonceStore()
//   config := security.RequestValidatorConfig{
//       HMACSecret:   "seu-segredo",
//       HMACMaxSkew:  300,
//       NonceStore:   store,
//       NonceTTL:     5 * time.Minute,
//       RateLimit:    100,
//       RateWindow:   time.Minute,
//       MaxBodySize:  1024 * 1024, // 1MB
//   }
//   validator := security.NewRequestValidator(config)
//
//   // Middleware
//   middleware := security.NewMiddleware(validator, security.SecurityOptions{
//       Enabled: true,
//       RequireHMAC: true,
//       RequireNonce: true,
//   })
//
//   http.Handle("/api/", middleware.Handler(yourHandler))
package security
