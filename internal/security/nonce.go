package security

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// NonceStore interface para armazenamento de nonces
type NonceStore interface {
	// Store armazena um nonce com TTL
	Store(ctx context.Context, nonce string, ttl time.Duration) error
	// Exists verifica se um nonce já foi usado
	Exists(ctx context.Context, nonce string) (bool, error)
	// Delete remove um nonce (opcional)
	Delete(ctx context.Context, nonce string) error
	// Cleanup remove nonces expirados (opcional)
	Cleanup(ctx context.Context) error
}

// NonceManager gerencia anti-replay com nonces
type NonceManager struct {
	store NonceStore
	ttl   time.Duration
}

// NewNonceManager cria um novo gerenciador de nonces
func NewNonceManager(store NonceStore, ttl time.Duration) *NonceManager {
	return &NonceManager{
		store: store,
		ttl:   ttl,
	}
}

// ValidateNonce valida e consome um nonce (anti-replay)
func (n *NonceManager) ValidateNonce(ctx context.Context, nonce string) error {
	if nonce == "" {
		return fmt.Errorf("nonce ausente")
	}

	exists, err := n.store.Exists(ctx, nonce)
	if err != nil {
		return fmt.Errorf("erro ao verificar nonce: %w", err)
	}

	if exists {
		return fmt.Errorf("nonce já utilizado (replay attack)")
	}

	// Consome o nonce
	if err := n.store.Store(ctx, nonce, n.ttl); err != nil {
		return fmt.Errorf("erro ao armazenar nonce: %w", err)
	}

	return nil
}

// GenerateNonce gera um nonce criptograficamente seguro
func GenerateNonce() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback para timestamp + random
		return fmt.Sprintf("%d-%x", time.Now().UnixNano(), time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}

// --- Implementações de NonceStore ---

// InMemoryNonceStore implementação em memória (thread-safe)
type InMemoryNonceStore struct {
	mu    sync.RWMutex
	store map[string]time.Time
}

func NewInMemoryNonceStore() *InMemoryNonceStore {
	return &InMemoryNonceStore{
		store: make(map[string]time.Time),
	}
}

func (s *InMemoryNonceStore) Store(ctx context.Context, nonce string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Remove se já existir (evita overwrite)
	if _, exists := s.store[nonce]; exists {
		return fmt.Errorf("nonce já existe")
	}

	s.store[nonce] = time.Now().Add(ttl)
	return nil
}

func (s *InMemoryNonceStore) Exists(ctx context.Context, nonce string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	expiration, exists := s.store[nonce]
	if !exists {
		return false, nil
	}

	// Verifica se já expirou
	if time.Now().After(expiration) {
		// Remove não retorna erro, apenas false
		go s.Delete(ctx, nonce)
		return false, nil
	}

	return true, nil
}

func (s *InMemoryNonceStore) Delete(ctx context.Context, nonce string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.store, nonce)
	return nil
}

func (s *InMemoryNonceStore) Cleanup(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for nonce, expiration := range s.store {
		if now.After(expiration) {
			delete(s.store, nonce)
		}
	}
	return nil
}

// RedisNonceStore implementação com Redis
type RedisNonceStore struct {
	client interface{} // Substituir pelo cliente Redis real
}

// NewRedisNonceStore cria um novo store Redis
func NewRedisNonceStore(client interface{}) *RedisNonceStore {
	return &RedisNonceStore{client: client}
}

// Store armazena nonce no Redis com TTL
func (s *RedisNonceStore) Store(ctx context.Context, nonce string, ttl time.Duration) error {
	// Exemplo com go-redis:
	// return s.client.Set(ctx, "nonce:"+nonce, "1", ttl).Err()
	return nil
}

// Exists verifica se nonce existe no Redis
func (s *RedisNonceStore) Exists(ctx context.Context, nonce string) (bool, error) {
	// Exemplo com go-redis:
	// val, err := s.client.Exists(ctx, "nonce:"+nonce).Result()
	// return val > 0, err
	return false, nil
}

// Delete remove nonce do Redis
func (s *RedisNonceStore) Delete(ctx context.Context, nonce string) error {
	// Exemplo com go-redis:
	// return s.client.Del(ctx, "nonce:"+nonce).Err()
	return nil
}

// Cleanup não necessário no Redis (TTL automático)
func (s *RedisNonceStore) Cleanup(ctx context.Context) error {
	return nil
}
