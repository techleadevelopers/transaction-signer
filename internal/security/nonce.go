package security

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
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
	client *redis.Client
	prefix string
}

// NewRedisNonceStore cria um novo store Redis
func NewRedisNonceStore(redisURL string) (*RedisNonceStore, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}
	opt.PoolSize = 16
	opt.MinIdleConns = 2
	opt.MaxRetries = 2
	opt.DialTimeout = 2 * time.Second
	opt.ReadTimeout = 700 * time.Millisecond
	opt.WriteTimeout = 700 * time.Millisecond
	opt.PoolTimeout = 800 * time.Millisecond

	client := redis.NewClient(opt)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, err
	}
	return &RedisNonceStore{client: client, prefix: "signer:nonce:"}, nil
}

// Store armazena nonce no Redis com TTL
func (s *RedisNonceStore) Store(ctx context.Context, nonce string, ttl time.Duration) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("redis nonce store nao inicializado")
	}
	ok, err := s.client.SetNX(ctx, s.key(nonce), "1", ttl).Result()
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("nonce ja existe")
	}
	return nil
}

// Exists verifica se nonce existe no Redis
func (s *RedisNonceStore) Exists(ctx context.Context, nonce string) (bool, error) {
	if s == nil || s.client == nil {
		return false, fmt.Errorf("redis nonce store nao inicializado")
	}
	val, err := s.client.Exists(ctx, s.key(nonce)).Result()
	return val > 0, err
}

// Delete remove nonce do Redis
func (s *RedisNonceStore) Delete(ctx context.Context, nonce string) error {
	if s == nil || s.client == nil {
		return nil
	}
	return s.client.Del(ctx, s.key(nonce)).Err()
}

// Cleanup não necessário no Redis (TTL automático)
func (s *RedisNonceStore) Cleanup(ctx context.Context) error {
	return nil
}

func (s *RedisNonceStore) Close() error {
	if s == nil || s.client == nil {
		return nil
	}
	return s.client.Close()
}

func (s *RedisNonceStore) key(nonce string) string {
	return s.prefix + nonce
}
