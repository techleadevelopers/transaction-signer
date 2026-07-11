package main

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
)

func TestExtractEIP7702Delegate(t *testing.T) {
	delegate := common.HexToAddress("0x1111111111111111111111111111111111111111")
	code := append([]byte{0xef, 0x01, 0x00}, delegate.Bytes()...)

	got, ok := ExtractEIP7702Delegate(code)
	if !ok || got != delegate {
		t.Fatalf("expected delegate %s, got %s ok=%v", delegate.Hex(), got.Hex(), ok)
	}
}

func TestSignEIP7702AuthorizationRecoversAuthority(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	delegate := common.HexToAddress("0x2222222222222222222222222222222222222222")

	auth, err := SignEIP7702Authorization(key, big.NewInt(56), delegate, 7)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := auth.Authority()
	if err != nil {
		t.Fatal(err)
	}
	if authority != crypto.PubkeyToAddress(key.PublicKey) {
		t.Fatalf("authority mismatch: got %s", authority.Hex())
	}
}

func TestCustodyGuardLocksOnUnknownDelegate(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	authority := crypto.PubkeyToAddress(key.PublicKey)
	unknownDelegate := common.HexToAddress("0x3333333333333333333333333333333333333333")
	auth, err := types.SignSetCode(key, types.SetCodeAuthorization{
		ChainID: *uint256.NewInt(56),
		Address: unknownDelegate,
		Nonce:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	tx := types.NewTx(&types.SetCodeTx{
		ChainID:   uint256.NewInt(56),
		Nonce:     1,
		GasTipCap: uint256.NewInt(1),
		GasFeeCap: uint256.NewInt(1),
		Gas:       100000,
		To:        authority,
		Value:     uint256.NewInt(0),
		AuthList:  []types.SetCodeAuthorization{auth},
	})
	guard := &CustodyGuard{
		protected: map[common.Address]bool{authority: true},
		trusted:   map[common.Address]common.Hash{},
	}
	guard.reason.Store("")

	guard.inspectTransaction("pending", tx)

	locked, reason := guard.Locked()
	if !locked || reason == "" {
		t.Fatalf("expected lockdown for unknown delegate, locked=%v reason=%q", locked, reason)
	}
}
