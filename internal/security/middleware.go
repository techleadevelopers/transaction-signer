package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// SecurityOptions configura o middleware de segurança
type SecurityOptions struct {
	Enabled        bool
	RequireHMAC    bool
	RequireNonce   bool
	RequireAPIKey  bool
	MaxBodySize    int64
	AllowedMethods []string
	AllowedPaths   []string
	ExcludePaths   []string
}

// Middleware configuração do middleware HTTP
type Middleware struct {
	validator *RequestValidator
	options   SecurityOptions
}

// NewMiddleware cria um novo middleware de segurança
func NewMiddleware(validator *RequestValidator, options SecurityOptions) *Middleware {
	return &Middleware{
		validator: validator,
		options:   options,
	}
}

// Handler aplica o middleware de segurança
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verifica se a rota deve ser excluída
		if m.isExcluded(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Verifica método permitido
		if !m.isMethodAllowed(r.Method) {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Se não estiver habilitado, passa adiante
		if !m.options.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Valida requisição
		ctx, err := m.validator.ValidateRequest(r)
		if err != nil {
			respondWithError(w, err, http.StatusUnauthorized)
			return
		}

		// Se requer HMAC e não foi validado
		if m.options.RequireHMAC && !ctx.Validated {
			respondWithError(w, fmt.Errorf("HMAC signature required"), http.StatusUnauthorized)
			return
		}

		// Se requer Nonce
		if m.options.RequireNonce && ctx.Nonce == "" {
			respondWithError(w, fmt.Errorf("nonce required"), http.StatusUnauthorized)
			return
		}

		// Se requer API Key
		if m.options.RequireAPIKey && ctx.APIKey == "" {
			respondWithError(w, fmt.Errorf("API key required"), http.StatusUnauthorized)
			return
		}

		// Injeta contexto na requisição
		newCtx := context.WithValue(r.Context(), RequestContextKey, ctx)
		next.ServeHTTP(w, r.WithContext(newCtx))
	})
}

func (m *Middleware) isExcluded(path string) bool {
	for _, p := range m.options.ExcludePaths {
		if p == path {
			return true
		}
	}
	return false
}

func (m *Middleware) isMethodAllowed(method string) bool {
	if len(m.options.AllowedMethods) == 0 {
		return true
	}
	for _, mtd := range m.options.AllowedMethods {
		if mtd == method {
			return true
		}
	}
	return false
}

func respondWithError(w http.ResponseWriter, err error, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":     err.Error(),
		"status":    "error",
		"code":      status,
		"timestamp": time.Now().Unix(),
	})
}
