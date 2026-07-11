package main

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestMemoryStoreReserveChainNonce(t *testing.T) {
	ctx := context.Background()
	store := newMemorySignerStore()

	first, err := store.ReserveChainNonce(ctx, "0xabc", "BSC", 7)
	if err != nil {
		t.Fatalf("ReserveChainNonce first: %v", err)
	}
	second, err := store.ReserveChainNonce(ctx, "0xabc", "BSC", 7)
	if err != nil {
		t.Fatalf("ReserveChainNonce second: %v", err)
	}

	if first != 7 || second != 8 {
		t.Fatalf("nonce reservation mismatch: first=%d second=%d", first, second)
	}
}

func TestValidateTreasuryPolicyBlocksDailyOutflow(t *testing.T) {
	ctx := context.Background()
	store := newMemorySignerStore()
	cfg := &SignerConfig{
		DefaultNetwork:        "BSC",
		BSCUSDTContract:       "0x55d398326f99059fF775485246999027B3197955",
		TreasuryMaxDailyOut:   100,
		TreasuryLockThreshold: 90,
	}
	req := TransferRequest{Amount: "91", TokenContract: cfg.BSCUSDTContract}

	err := validateTreasuryPolicy(ctx, cfg, store, req, "BSC")
	if err == nil || !strings.Contains(err.Error(), "treasury lockdown") {
		t.Fatalf("expected treasury lockdown, got %v", err)
	}
}

func TestCustodyGuardShadowModeRecordsWithoutLock(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	store := newMemorySignerStore()
	cfg := &SignerConfig{
		EVMPrivateKey:       hex.EncodeToString(crypto.FromECDSA(key)),
		CustodyGuardEnabled: true,
		CustodyMode:         "shadow",
	}
	guard, err := NewCustodyGuard(cfg, store)
	if err != nil {
		t.Fatalf("NewCustodyGuard: %v", err)
	}

	guard.Lock("test incident")
	locked, reason := guard.Locked()
	if locked {
		t.Fatalf("shadow mode should not lock, reason=%s", reason)
	}
	if len(store.events) != 1 {
		t.Fatalf("expected custody event, got %d", len(store.events))
	}
}
