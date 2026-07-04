package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

type signerStore interface {
	AcceptNonce(ctx context.Context, nonce string, ttl time.Duration) (bool, error)
	ClaimResult(ctx context.Context, key string) (TransferResponse, bool, bool, error)
	GetResult(ctx context.Context, key string) (TransferResponse, bool, error)
	SaveResult(ctx context.Context, key string, resp TransferResponse) error
	ReleaseClaim(ctx context.Context, key string) error
	Ready(ctx context.Context) error
	Close() error
}

func openSignerStore(ctx context.Context, cfg *SignerConfig) (signerStore, error) {
	if cfg.DatabaseURL == "" {
		if cfg.AppEnv == "production" {
			return nil, errors.New("SIGNER_DATABASE_URL ou DATABASE_URL obrigatorio em producao")
		}
		return newMemorySignerStore(), nil
	}
	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	store := &postgresSignerStore{db: db}
	if err := store.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

type postgresSignerStore struct {
	db *sql.DB
}

func (s *postgresSignerStore) migrate(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS signer_nonces (
			nonce TEXT PRIMARY KEY,
			expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
		CREATE TABLE IF NOT EXISTS signer_idempotency (
			idempotency_key TEXT PRIMARY KEY,
			response JSONB NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
		CREATE TABLE IF NOT EXISTS signer_idempotency_locks (
			idempotency_key TEXT PRIMARY KEY,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
		CREATE INDEX IF NOT EXISTS idx_signer_nonces_expires_at ON signer_nonces (expires_at);
	`)
	return err
}

func (s *postgresSignerStore) AcceptNonce(ctx context.Context, nonce string, ttl time.Duration) (bool, error) {
	if nonce == "" {
		return false, nil
	}
	_, _ = s.db.ExecContext(ctx, `DELETE FROM signer_nonces WHERE expires_at < now()`)
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO signer_nonces (nonce, expires_at) VALUES ($1, now() + ($2 || ' seconds')::interval) ON CONFLICT DO NOTHING`,
		nonce, int(ttl.Seconds()))
	if err != nil {
		return false, err
	}
	rows, err := res.RowsAffected()
	return rows == 1, err
}

func (s *postgresSignerStore) GetResult(ctx context.Context, key string) (TransferResponse, bool, error) {
	if key == "" {
		return TransferResponse{}, false, nil
	}
	var raw []byte
	err := s.db.QueryRowContext(ctx, `SELECT response FROM signer_idempotency WHERE idempotency_key = $1`, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return TransferResponse{}, false, nil
	}
	if err != nil {
		return TransferResponse{}, false, err
	}
	var resp TransferResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return TransferResponse{}, false, err
	}
	return resp, true, nil
}

func (s *postgresSignerStore) ClaimResult(ctx context.Context, key string) (TransferResponse, bool, bool, error) {
	if key == "" {
		return TransferResponse{}, false, true, nil
	}
	if resp, ok, err := s.GetResult(ctx, key); err != nil || ok {
		return resp, ok, false, err
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO signer_idempotency_locks (idempotency_key) VALUES ($1) ON CONFLICT DO NOTHING`, key)
	if err != nil {
		return TransferResponse{}, false, false, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return TransferResponse{}, false, false, err
	}
	return TransferResponse{}, false, rows == 1, nil
}

func (s *postgresSignerStore) SaveResult(ctx context.Context, key string, resp TransferResponse) error {
	if key == "" {
		return nil
	}
	raw, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx,
		`INSERT INTO signer_idempotency (idempotency_key, response) VALUES ($1, $2) ON CONFLICT (idempotency_key) DO NOTHING`,
		key, raw)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM signer_idempotency_locks WHERE idempotency_key = $1`, key); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *postgresSignerStore) ReleaseClaim(ctx context.Context, key string) error {
	if key == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM signer_idempotency_locks WHERE idempotency_key = $1`, key)
	return err
}

func (s *postgresSignerStore) Ready(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *postgresSignerStore) Close() error {
	return s.db.Close()
}

type memorySignerStore struct {
	mu      sync.Mutex
	nonces  map[string]time.Time
	results map[string]TransferResponse
	locks   map[string]struct{}
}

func newMemorySignerStore() *memorySignerStore {
	return &memorySignerStore{nonces: make(map[string]time.Time), results: make(map[string]TransferResponse), locks: make(map[string]struct{})}
}

func (s *memorySignerStore) AcceptNonce(_ context.Context, nonce string, ttl time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for key, expires := range s.nonces {
		if now.After(expires) {
			delete(s.nonces, key)
		}
	}
	if _, exists := s.nonces[nonce]; exists {
		return false, nil
	}
	s.nonces[nonce] = now.Add(ttl)
	return true, nil
}

func (s *memorySignerStore) GetResult(_ context.Context, key string) (TransferResponse, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	resp, ok := s.results[key]
	return resp, ok, nil
}

func (s *memorySignerStore) ClaimResult(_ context.Context, key string) (TransferResponse, bool, bool, error) {
	if key == "" {
		return TransferResponse{}, false, true, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if resp, ok := s.results[key]; ok {
		return resp, true, false, nil
	}
	if _, locked := s.locks[key]; locked {
		return TransferResponse{}, false, false, nil
	}
	s.locks[key] = struct{}{}
	return TransferResponse{}, false, true, nil
}

func (s *memorySignerStore) SaveResult(_ context.Context, key string, resp TransferResponse) error {
	if key == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results[key] = resp
	delete(s.locks, key)
	return nil
}

func (s *memorySignerStore) ReleaseClaim(_ context.Context, key string) error {
	if key == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.locks, key)
	return nil
}

func (s *memorySignerStore) Ready(context.Context) error { return nil }

func (s *memorySignerStore) Close() error { return nil }
