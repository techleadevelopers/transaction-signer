package main

import (
	"context"
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
