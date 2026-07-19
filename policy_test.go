package main

import (
	"context"
	"math/big"
	"testing"
	"time"
)

func TestValidateTransferPolicy_BSC(t *testing.T) {
	cfg := &SignerConfig{
		DefaultNetwork:        "BSC",
		AllowedNetworks:       map[string]bool{"BSC": true},
		AllowedTokenContracts: map[string]bool{"0X55D398326F99059FF775485246999027B3197955": true},
		BSCUSDTContract:       "0x55d398326f99059fF775485246999027B3197955",
		MaxTransferAmount:     100,
	}
	req := TransferRequest{
		Network: "BSC",
		To:      "0x829829508824f81d939F8CFFdCac71dE47a808bE",
		Amount:  "12.34",
	}
	if err := validateTransferPolicy(cfg, req, requestedNetwork(cfg, req)); err != nil {
		t.Fatalf("BSC valido rejeitado: %v", err)
	}
}

func TestValidateTransferPolicy_BlocksAmountLimit(t *testing.T) {
	cfg := &SignerConfig{
		DefaultNetwork:    "BSC",
		AllowedNetworks:   map[string]bool{"BSC": true},
		MaxTransferAmount: 10,
	}
	req := TransferRequest{
		Network:       "bsc",
		To:            "0x829829508824f81d939F8CFFdCac71dE47a808bE",
		Amount:        "10.01",
		TokenContract: "0x55d398326f99059fF775485246999027B3197955",
	}
	if err := validateTransferPolicy(cfg, req, requestedNetwork(cfg, req)); err == nil {
		t.Fatal("limite de valor deveria bloquear a transferencia")
	}
}

func TestMemorySignerStore_IdempotencyAndNonce(t *testing.T) {
	store := newMemorySignerStore()
	ctx := context.Background()
	accepted, err := store.AcceptNonce(ctx, "nonce-1", time.Minute)
	if err != nil || !accepted {
		t.Fatalf("nonce inicial deveria ser aceito: accepted=%v err=%v", accepted, err)
	}
	accepted, err = store.AcceptNonce(ctx, "nonce-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if accepted {
		t.Fatal("nonce repetido deveria ser bloqueado")
	}
	resp := TransferResponse{TxHash: "0xabc", From: "0x829829508824f81d939F8CFFdCac71dE47a808bE", Network: "BSC"}
	if err := store.SaveResult(ctx, "buy-1", resp); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.GetResult(ctx, "buy-1")
	if err != nil || !ok {
		t.Fatalf("resultado idempotente deveria existir: ok=%v err=%v", ok, err)
	}
	if got.TxHash != resp.TxHash || got.Network != resp.Network {
		t.Fatalf("resultado incorreto: %+v", got)
	}
}

func TestMemorySignerStore_ClaimBlocksConcurrentIdempotency(t *testing.T) {
	store := newMemorySignerStore()
	ctx := context.Background()

	_, done, claimed, err := store.ClaimResult(ctx, "buy-1")
	if err != nil || done || !claimed {
		t.Fatalf("first claim should reserve key: done=%v claimed=%v err=%v", done, claimed, err)
	}
	_, done, claimed, err = store.ClaimResult(ctx, "buy-1")
	if err != nil {
		t.Fatal(err)
	}
	if done || claimed {
		t.Fatalf("second claim should be blocked while in progress: done=%v claimed=%v", done, claimed)
	}

	resp := TransferResponse{TxHash: "0xabc", From: "0x829829508824f81d939F8CFFdCac71dE47a808bE", Network: "BSC"}
	if err := store.SaveResult(ctx, "buy-1", resp); err != nil {
		t.Fatal(err)
	}
	got, done, claimed, err := store.ClaimResult(ctx, "buy-1")
	if err != nil || !done || claimed || got.TxHash != resp.TxHash {
		t.Fatalf("completed key should return previous result: got=%+v done=%v claimed=%v err=%v", got, done, claimed, err)
	}
}

func TestSignerValidateProductionRequiresTokenAllowlist(t *testing.T) {
	cfg := &SignerConfig{
		AppEnv:          "production",
		DatabaseURL:     "postgres://user:pass@localhost/db",
		AllowSimulation: false,
		Security: SecurityConfig{
			HMACSecret:  "0123456789abcdef0123456789abcdef",
			RequireHMAC: true,
		},
		AllowedNetworks:   map[string]bool{"BSC": true},
		BSCUSDTContract:   "0x55d398326f99059fF775485246999027B3197955",
		MaxTransferAmount: 100,
	}
	if err := cfg.ValidateProduction(); err == nil {
		t.Fatal("expected missing token allowlist to fail production validation")
	}
}

func TestSettlementOperationIDMatchesHardhatVector(t *testing.T) {
	got, err := settlementOperationID(
		31337,
		"0x1111111111111111111111111111111111111111",
		"settlement-001",
		"0x2222222222222222222222222222222222222222",
		"0x3333333333333333333333333333333333333333",
		big.NewInt(10000000),
	)
	if err != nil {
		t.Fatal(err)
	}
	const expected = "0xddf2d849f366d3663412542b335fe30a92e2e01b0869ddf5d24f9b68eaf6ad52"
	if got.Hex() != expected {
		t.Fatalf("operationId mismatch: got %s want %s", got.Hex(), expected)
	}
}

func TestValidateSettlementExecuteRequest(t *testing.T) {
	vault := "0x1111111111111111111111111111111111111111"
	token := "0x2222222222222222222222222222222222222222"
	recipient := "0x3333333333333333333333333333333333333333"
	amountRaw := big.NewInt(10000000)
	operationID, err := settlementOperationID(31337, vault, "settlement-001", token, recipient, amountRaw)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &SignerConfig{
		DefaultNetwork:        "BSC",
		AllowedNetworks:       map[string]bool{"BSC": true},
		AllowedTokenContracts: map[string]bool{"0X2222222222222222222222222222222222222222": true},
		BSCUSDTContract:       token,
		BSCTreasuryContract:   vault,
		BSCChainID:            31337,
	}
	req := SettlementExecuteRequest{
		OperationID:        operationID.Hex(),
		SettlementIntentID: "settlement-001",
		OrderID:            "ord-001",
		Side:               "BUY",
		Network:            "BSC",
		ChainID:            31337,
		Vault:              vault,
		Token:              token,
		Recipient:          recipient,
		AmountRaw:          amountRaw.String(),
		PolicyVersion:      settlementPolicyVersion,
		ExpiresAt:          time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339Nano),
	}
	if _, _, err := validateSettlementExecuteRequest(cfg, req); err != nil {
		t.Fatalf("settlement valido rejeitado: %v", err)
	}

	bad := req
	bad.AmountRaw = "10000001"
	if _, _, err := validateSettlementExecuteRequest(cfg, bad); err == nil {
		t.Fatal("operationId divergente deveria ser rejeitado")
	}

	expired := req
	expired.ExpiresAt = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	if _, _, err := validateSettlementExecuteRequest(cfg, expired); err == nil {
		t.Fatal("authorization expirada deveria ser rejeitada")
	}
}
