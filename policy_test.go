package main

import (
	"context"
	"testing"
	"time"
)

func TestValidateTransferPolicy_TRON(t *testing.T) {
	cfg := &SignerConfig{
		DefaultNetwork:        "TRON",
		AllowedNetworks:       map[string]bool{"TRON": true},
		AllowedTokenContracts: map[string]bool{"TR7NHQJEKQXGTCI8Q8ZY4PL8OTSZGJLJ6T": true},
		TronUSDTContract:      "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
		MaxTransferAmount:     100,
	}
	req := TransferRequest{
		Network: "tron",
		To:      "TQn9Y2khEsLJW1ChVWFMSMeRDow5KcbLSE",
		Amount:  "12.34",
	}
	if err := validateTransferPolicy(cfg, req, requestedNetwork(cfg, req)); err != nil {
		t.Fatalf("TRON valido rejeitado: %v", err)
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
	resp := TransferResponse{TxHash: "0xabc", From: "TQn9Y2khEsLJW1ChVWFMSMeRDow5KcbLSE", Network: "TRON"}
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
