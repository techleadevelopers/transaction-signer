package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
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
	RecordCustodyEvent(ctx context.Context, event CustodyEvent) error
	OpenCustodyIncident(ctx context.Context, reason, mode string) error
	ActiveCustodyIncident(ctx context.Context) (CustodyIncident, bool, error)
	ResolveCustodyIncident(ctx context.Context, note string) error
	ReserveChainNonce(ctx context.Context, wallet, network string, chainPending uint64) (uint64, error)
	MarkChainNonceSubmitted(ctx context.Context, wallet, network string, nonce uint64, txHash string) error
	MarkChainNonceFailed(ctx context.Context, wallet, network string, nonce uint64, reason string) error
	CreateSignerTransaction(ctx context.Context, tx SignerTransaction) error
	MarkSignerTransactionStatus(ctx context.Context, txHash, status, reason string, confirmations uint64) error
	ListOpenSignerTransactions(ctx context.Context, limit int) ([]SignerTransaction, error)
	DailySubmittedOutflow(ctx context.Context, token, network string) (float64, error)
	Ready(ctx context.Context) error
	Close() error
}

type CustodyEvent struct {
	Kind   string
	Reason string
	Mode   string
	TxHash string
	Wallet string
	Data   map[string]any
}

type CustodyIncident struct {
	ID        int64
	Reason    string
	Mode      string
	CreatedAt time.Time
}

type SignerTransaction struct {
	IdempotencyKey string
	WalletFrom     string
	WalletTo       string
	Token          string
	Amount         string
	Network        string
	Nonce          uint64
	TxHash         string
	Status         string
	Reason         string
	Confirmations  uint64
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
		CREATE TABLE IF NOT EXISTS custody_events (
			id BIGSERIAL PRIMARY KEY,
			kind TEXT NOT NULL,
			reason TEXT NOT NULL DEFAULT '',
			mode TEXT NOT NULL DEFAULT '',
			tx_hash TEXT NOT NULL DEFAULT '',
			wallet TEXT NOT NULL DEFAULT '',
			data JSONB NOT NULL DEFAULT '{}'::jsonb,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
		CREATE TABLE IF NOT EXISTS custody_incidents (
			id BIGSERIAL PRIMARY KEY,
			reason TEXT NOT NULL,
			mode TEXT NOT NULL,
			resolved_at TIMESTAMPTZ,
			resolution_note TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_custody_incidents_active ON custody_incidents ((true)) WHERE resolved_at IS NULL;
		CREATE TABLE IF NOT EXISTS signer_chain_nonces (
			wallet TEXT NOT NULL,
			network TEXT NOT NULL,
			nonce BIGINT NOT NULL,
			status TEXT NOT NULL,
			tx_hash TEXT NOT NULL DEFAULT '',
			reason TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			PRIMARY KEY (wallet, network, nonce)
		);
		CREATE TABLE IF NOT EXISTS signer_transactions (
			tx_hash TEXT PRIMARY KEY,
			idempotency_key TEXT NOT NULL DEFAULT '',
			wallet_from TEXT NOT NULL,
			wallet_to TEXT NOT NULL,
			token TEXT NOT NULL DEFAULT '',
			amount TEXT NOT NULL,
			network TEXT NOT NULL,
			nonce BIGINT NOT NULL,
			status TEXT NOT NULL,
			reason TEXT NOT NULL DEFAULT '',
			confirmations BIGINT NOT NULL DEFAULT 0,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
		CREATE INDEX IF NOT EXISTS idx_signer_nonces_expires_at ON signer_nonces (expires_at);
		CREATE INDEX IF NOT EXISTS idx_signer_transactions_status ON signer_transactions (status, created_at);
		CREATE INDEX IF NOT EXISTS idx_signer_transactions_daily ON signer_transactions (network, token, created_at);
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

func (s *postgresSignerStore) RecordCustodyEvent(ctx context.Context, event CustodyEvent) error {
	raw, err := json.Marshal(event.Data)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO custody_events (kind, reason, mode, tx_hash, wallet, data)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		event.Kind, event.Reason, event.Mode, event.TxHash, event.Wallet, raw)
	return err
}

func (s *postgresSignerStore) OpenCustodyIncident(ctx context.Context, reason, mode string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO custody_incidents (reason, mode)
		VALUES ($1, $2)
		ON CONFLICT ((true)) WHERE resolved_at IS NULL DO NOTHING`, reason, mode)
	return err
}

func (s *postgresSignerStore) ActiveCustodyIncident(ctx context.Context) (CustodyIncident, bool, error) {
	var incident CustodyIncident
	err := s.db.QueryRowContext(ctx, `
		SELECT id, reason, mode, created_at
		FROM custody_incidents
		WHERE resolved_at IS NULL
		ORDER BY created_at DESC
		LIMIT 1`).Scan(&incident.ID, &incident.Reason, &incident.Mode, &incident.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return CustodyIncident{}, false, nil
	}
	if err != nil {
		return CustodyIncident{}, false, err
	}
	return incident, true, nil
}

func (s *postgresSignerStore) ResolveCustodyIncident(ctx context.Context, note string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE custody_incidents
		SET resolved_at = now(), resolution_note = $1
		WHERE resolved_at IS NULL`, note)
	return err
}

func (s *postgresSignerStore) ReserveChainNonce(ctx context.Context, wallet, network string, chainPending uint64) (uint64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))`, wallet, network); err != nil {
		return 0, err
	}
	var maxNonce sql.NullInt64
	if err := tx.QueryRowContext(ctx, `
		SELECT max(nonce)
		FROM signer_chain_nonces
		WHERE wallet = $1 AND network = $2 AND status IN ('reserved', 'submitted')`, wallet, network).Scan(&maxNonce); err != nil {
		return 0, err
	}
	next := chainPending
	if maxNonce.Valid && uint64(maxNonce.Int64)+1 > next {
		next = uint64(maxNonce.Int64) + 1
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO signer_chain_nonces (wallet, network, nonce, status)
		VALUES ($1, $2, $3, 'reserved')`, wallet, network, next)
	if err != nil {
		return 0, err
	}
	return next, tx.Commit()
}

func (s *postgresSignerStore) MarkChainNonceSubmitted(ctx context.Context, wallet, network string, nonce uint64, txHash string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE signer_chain_nonces
		SET status = 'submitted', tx_hash = $4, updated_at = now()
		WHERE wallet = $1 AND network = $2 AND nonce = $3`, wallet, network, nonce, txHash)
	return err
}

func (s *postgresSignerStore) MarkChainNonceFailed(ctx context.Context, wallet, network string, nonce uint64, reason string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE signer_chain_nonces
		SET status = 'failed', reason = $4, updated_at = now()
		WHERE wallet = $1 AND network = $2 AND nonce = $3`, wallet, network, nonce, reason)
	return err
}

func (s *postgresSignerStore) CreateSignerTransaction(ctx context.Context, item SignerTransaction) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO signer_transactions
			(tx_hash, idempotency_key, wallet_from, wallet_to, token, amount, network, nonce, status, reason, confirmations)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (tx_hash) DO UPDATE SET
			status = excluded.status,
			reason = excluded.reason,
			confirmations = excluded.confirmations,
			updated_at = now()`,
		item.TxHash, item.IdempotencyKey, item.WalletFrom, item.WalletTo, item.Token, item.Amount, item.Network, item.Nonce, item.Status, item.Reason, item.Confirmations)
	return err
}

func (s *postgresSignerStore) MarkSignerTransactionStatus(ctx context.Context, txHash, status, reason string, confirmations uint64) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE signer_transactions
		SET status = $2, reason = $3, confirmations = $4, updated_at = now()
		WHERE tx_hash = $1`, txHash, status, reason, confirmations)
	return err
}

func (s *postgresSignerStore) ListOpenSignerTransactions(ctx context.Context, limit int) ([]SignerTransaction, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT tx_hash, idempotency_key, wallet_from, wallet_to, token, amount, network, nonce, status, reason, confirmations
		FROM signer_transactions
		WHERE status IN ('submitted', 'signed')
		ORDER BY created_at ASC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SignerTransaction
	for rows.Next() {
		var item SignerTransaction
		var nonce int64
		var confirmations int64
		if err := rows.Scan(&item.TxHash, &item.IdempotencyKey, &item.WalletFrom, &item.WalletTo, &item.Token, &item.Amount, &item.Network, &nonce, &item.Status, &item.Reason, &confirmations); err != nil {
			return nil, err
		}
		item.Nonce = uint64(nonce)
		item.Confirmations = uint64(confirmations)
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *postgresSignerStore) DailySubmittedOutflow(ctx context.Context, token, network string) (float64, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT amount
		FROM signer_transactions
		WHERE network = $1 AND token = $2 AND status IN ('submitted', 'confirmed')
		  AND created_at >= date_trunc('day', now())`, network, token)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var total float64
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return 0, err
		}
		value, err := strconv.ParseFloat(raw, 64)
		if err == nil {
			total += value
		}
	}
	return total, rows.Err()
}

func (s *postgresSignerStore) Ready(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *postgresSignerStore) Close() error {
	return s.db.Close()
}

type memorySignerStore struct {
	mu             sync.Mutex
	nonces         map[string]time.Time
	results        map[string]TransferResponse
	locks          map[string]struct{}
	chainNonces    map[string]uint64
	transactions   map[string]SignerTransaction
	activeIncident *CustodyIncident
	events         []CustodyEvent
}

func newMemorySignerStore() *memorySignerStore {
	return &memorySignerStore{
		nonces:       make(map[string]time.Time),
		results:      make(map[string]TransferResponse),
		locks:        make(map[string]struct{}),
		chainNonces:  make(map[string]uint64),
		transactions: make(map[string]SignerTransaction),
	}
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

func (s *memorySignerStore) RecordCustodyEvent(_ context.Context, event CustodyEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}

func (s *memorySignerStore) OpenCustodyIncident(_ context.Context, reason, mode string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeIncident == nil {
		s.activeIncident = &CustodyIncident{ID: 1, Reason: reason, Mode: mode, CreatedAt: time.Now()}
	}
	return nil
}

func (s *memorySignerStore) ActiveCustodyIncident(_ context.Context) (CustodyIncident, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeIncident == nil {
		return CustodyIncident{}, false, nil
	}
	return *s.activeIncident, true, nil
}

func (s *memorySignerStore) ResolveCustodyIncident(_ context.Context, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activeIncident = nil
	return nil
}

func (s *memorySignerStore) ReserveChainNonce(_ context.Context, wallet, network string, chainPending uint64) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := wallet + "|" + network
	next := chainPending
	if current, ok := s.chainNonces[key]; ok && current+1 > next {
		next = current + 1
	}
	s.chainNonces[key] = next
	return next, nil
}

func (s *memorySignerStore) MarkChainNonceSubmitted(context.Context, string, string, uint64, string) error {
	return nil
}

func (s *memorySignerStore) MarkChainNonceFailed(context.Context, string, string, uint64, string) error {
	return nil
}

func (s *memorySignerStore) CreateSignerTransaction(_ context.Context, item SignerTransaction) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.transactions[item.TxHash] = item
	return nil
}

func (s *memorySignerStore) MarkSignerTransactionStatus(_ context.Context, txHash, status, reason string, confirmations uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.transactions[txHash]
	if !ok {
		return nil
	}
	item.Status = status
	item.Reason = reason
	item.Confirmations = confirmations
	s.transactions[txHash] = item
	return nil
}

func (s *memorySignerStore) ListOpenSignerTransactions(_ context.Context, limit int) ([]SignerTransaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []SignerTransaction
	for _, item := range s.transactions {
		if item.Status == "submitted" || item.Status == "signed" {
			out = append(out, item)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (s *memorySignerStore) DailySubmittedOutflow(_ context.Context, token, network string) (float64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var total float64
	for _, item := range s.transactions {
		if item.Token != token || item.Network != network || (item.Status != "submitted" && item.Status != "confirmed") {
			continue
		}
		value, err := strconv.ParseFloat(item.Amount, 64)
		if err == nil {
			total += value
		}
	}
	return total, nil
}

func (s *memorySignerStore) Ready(context.Context) error { return nil }

func (s *memorySignerStore) Close() error { return nil }
