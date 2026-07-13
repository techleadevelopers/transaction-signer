package main

import (
	"crypto/ecdsa"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
)

// ---------------------------------------------------------------------
// LAYER 3b — CUSTODY GUARD (EIP-7702 delegate extraction & allowlist break)
//
// Attack map item: "Custody Guard -> Concorrência EIP-7702 & Quebra de
// Allowlist". These tests attack the two things an attacker actually
// controls: the raw bytecode ExtractEIP7702Delegate parses, and the
// concurrency safety of the lockdown flag under a burst of transactions.
// ---------------------------------------------------------------------

func TestEIP7702Extract_AdversarialCodePayloads_NeverMisparse(t *testing.T) {
	delegate := common.HexToAddress("0x1111111111111111111111111111111111111111")
	validCode := append([]byte{0xef, 0x01, 0x00}, delegate.Bytes()...)

	cases := []struct {
		name     string
		code     []byte
		expectOK bool
	}{
		{"empty code (EOA, no delegation)", []byte{}, false},
		{"nil code", nil, false},
		{"22 bytes — one short of the minimum 23", validCode[:22], false},
		{"exact 23-byte valid delegation", validCode, true},
		{"correct prefix, truncated address", []byte{0xef, 0x01, 0x00, 0x11, 0x22}, false},
		{"near-miss prefix 0xef0101", append([]byte{0xef, 0x01, 0x01}, delegate.Bytes()...), false},
		{"near-miss prefix 0xee0100", append([]byte{0xee, 0x01, 0x00}, delegate.Bytes()...), false},
		{"prefix shifted one byte right (leading padding)", append([]byte{0x00, 0xef, 0x01, 0x00}, delegate.Bytes()...), false},
		{"valid prefix with large trailing garbage appended", append(append([]byte{}, validCode...), make([]byte, 10_000)...), true},
		{"all-zero 23 bytes", make([]byte, 23), false},
		{"all-0xff 23 bytes", func() []byte {
			b := make([]byte, 23)
			for i := range b {
				b[i] = 0xff
			}
			return b
		}(), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ExtractEIP7702Delegate(tc.code)
			if ok != tc.expectOK {
				t.Fatalf("ExtractEIP7702Delegate(%x) ok=%v, want %v (got delegate=%s)", tc.code, ok, tc.expectOK, got.Hex())
			}
			if tc.expectOK && got != delegate {
				t.Fatalf("expected delegate %s, got %s", delegate.Hex(), got.Hex())
			}
		})
	}
}

// buildSetCodeTx signs an EIP-7702 SetCode authorization from authorityKey
// delegating to delegate, wrapped in a minimal SetCodeTx, mirroring what
// inspectTransaction actually receives from a pending-block scan.
func buildSetCodeTx(t *testing.T, authorityKey *testAuthority, delegate common.Address, nonce uint64) *types.Transaction {
	t.Helper()
	auth, err := types.SignSetCode(authorityKey.key, types.SetCodeAuthorization{
		ChainID: *uint256.NewInt(56),
		Address: delegate,
		Nonce:   nonce,
	})
	if err != nil {
		t.Fatalf("failed to sign authorization: %v", err)
	}
	return types.NewTx(&types.SetCodeTx{
		ChainID:   uint256.NewInt(56),
		Nonce:     nonce,
		GasTipCap: uint256.NewInt(1),
		GasFeeCap: uint256.NewInt(1),
		Gas:       100000,
		To:        authorityKey.address,
		Value:     uint256.NewInt(0),
		AuthList:  []types.SetCodeAuthorization{auth},
	})
}

type testAuthority struct {
	key     *ecdsa.PrivateKey
	address common.Address
}

func newTestAuthorityKey(t *testing.T) *testAuthority {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	return &testAuthority{key: key, address: crypto.PubkeyToAddress(key.PublicKey)}
}

// TestCustodyGuard_AllowlistBreak_UnknownDelegateAlwaysLocksRegardlessOfNonce
// attacks the allowlist directly: no matter what nonce/selector an attacker
// tries, delegating a protected wallet's code to an address absent from
// CustodyTrustedRaw must lock the signer every single time.
func TestCustodyGuard_AllowlistBreak_UnknownDelegateAlwaysLocksRegardlessOfNonce(t *testing.T) {
	authority := newTestAuthorityKey(t)
	unknownDelegate := common.HexToAddress("0x9999999999999999999999999999999999999999")

	for _, nonce := range []uint64{0, 1, 42, 1 << 32} {
		guard := &CustodyGuard{
			protected: map[common.Address]bool{authority.address: true},
			trusted:   map[common.Address]common.Hash{},
		}
		guard.reason.Store("")

		tx := buildSetCodeTx(t, authority, unknownDelegate, nonce)
		guard.inspectTransaction("pending", tx)

		locked, reason := guard.Locked()
		if !locked || reason == "" {
			t.Fatalf("nonce=%d: expected lockdown for unknown delegate, locked=%v reason=%q", nonce, locked, reason)
		}
	}
}

// TestCustodyGuard_AllowlistBreak_UnprotectedWalletIsIgnored is the mirror
// check: a SetCode authorization from a wallet the guard does NOT protect
// must be silently ignored (it's not this guard's job), and must never
// itself trigger a lockdown — otherwise an attacker could DoS the signer
// by broadcasting unrelated EIP-7702 transactions from arbitrary wallets.
func TestCustodyGuard_AllowlistBreak_UnprotectedWalletIsIgnored(t *testing.T) {
	unrelatedWallet := newTestAuthorityKey(t)
	unknownDelegate := common.HexToAddress("0x8888888888888888888888888888888888888888")

	guard := &CustodyGuard{
		protected: map[common.Address]bool{common.HexToAddress("0x1234567890123456789012345678901234567890"): true},
		trusted:   map[common.Address]common.Hash{},
	}
	guard.reason.Store("")

	tx := buildSetCodeTx(t, unrelatedWallet, unknownDelegate, 0)
	guard.inspectTransaction("pending", tx)

	if locked, reason := guard.Locked(); locked {
		t.Fatalf("🚨 DoS: transação de wallet não-protegida travou o signer indevidamente (reason=%q)", reason)
	}
}

// TestCustodyGuard_ConcurrentInspection_LockdownIsRaceFree fires many
// SetCode transactions concurrently — a mix of legitimate-looking (trusted
// delegate) and malicious (unknown delegate) — to make sure the atomic
// lockdown flag can't be raced into a false "unlocked" state, and that a
// single malicious transaction hidden in a burst is never lost to a race.
func TestCustodyGuard_ConcurrentInspection_LockdownIsRaceFree(t *testing.T) {
	authority := newTestAuthorityKey(t)
	trustedDelegate := common.HexToAddress("0x2222222222222222222222222222222222222222")
	maliciousDelegate := common.HexToAddress("0x6666666666666666666666666666666666666666")

	guard := &CustodyGuard{
		protected: map[common.Address]bool{authority.address: true},
		trusted:   map[common.Address]common.Hash{trustedDelegate: {}},
	}
	guard.reason.Store("")

	const benignTxs = 50
	var wg sync.WaitGroup
	for i := 0; i < benignTxs; i++ {
		wg.Add(1)
		go func(nonce uint64) {
			defer wg.Done()
			tx := buildSetCodeTx(t, authority, trustedDelegate, nonce)
			guard.inspectTransaction("pending", tx)
		}(uint64(i))
	}
	// One malicious transaction hidden in the burst.
	wg.Add(1)
	go func() {
		defer wg.Done()
		tx := buildSetCodeTx(t, authority, maliciousDelegate, benignTxs+1)
		guard.inspectTransaction("pending", tx)
	}()
	wg.Wait()

	locked, reason := guard.Locked()
	if !locked || reason == "" {
		t.Fatalf("🚨 FALHA DE CUSTÓDIA: transação maliciosa concorrente com tráfego benigno não travou o signer (locked=%v)", locked)
	}
}
