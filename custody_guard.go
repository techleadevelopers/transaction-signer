package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"log/slog"
	"math/big"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/holiman/uint256"
)

const eip7702DelegationPrefix = "0xef0100"

type CustodyGuard struct {
	cfg             *SignerConfig
	store           signerStore
	protected       map[common.Address]bool
	trusted         map[common.Address]common.Hash
	allowedSelector map[[4]byte]bool
	locked          atomic.Bool
	reason          atomic.Value
}

type rpcBlockWithTransactions struct {
	Number       *hexutil.Big         `json:"number"`
	Transactions []*types.Transaction `json:"transactions"`
}

func NewCustodyGuard(cfg *SignerConfig, store signerStore) (*CustodyGuard, error) {
	guard := &CustodyGuard{
		cfg:             cfg,
		store:           store,
		protected:       parseAddressSet(cfg.CustodyProtectedRaw),
		trusted:         make(map[common.Address]common.Hash),
		allowedSelector: parseSelectorSet(cfg.CustodySelectorsRaw),
	}
	if cfg.EVMPrivateKey != "" {
		privateKey, err := crypto.HexToECDSA(strings.TrimPrefix(cfg.EVMPrivateKey, "0x"))
		if err != nil {
			return nil, err
		}
		guard.protected[crypto.PubkeyToAddress(privateKey.PublicKey)] = true
	}
	if len(guard.protected) == 0 {
		return nil, errors.New("custody guard sem wallet protegida")
	}
	for address := range parseAddressSet(cfg.CustodyTrustedRaw) {
		guard.trusted[address] = common.Hash{}
	}
	guard.reason.Store("")
	return guard, nil
}

func (g *CustodyGuard) Enabled() bool {
	return g != nil && g.cfg.CustodyGuardEnabled
}

func (g *CustodyGuard) Locked() (bool, string) {
	if g == nil {
		return false, ""
	}
	reason, _ := g.reason.Load().(string)
	return g.locked.Load(), reason
}

func (g *CustodyGuard) Lock(reason string) {
	mode := "paper"
	if g.cfg != nil {
		mode = normalizeCustodyMode(g.cfg.CustodyMode)
	}
	g.recordEvent("signer_locked", reason, "", "")
	if mode == "shadow" {
		slog.Warn("custody guard detectou risco em shadow mode", "reason", reason)
		return
	}
	g.locked.Store(true)
	g.reason.Store(reason)
	if g.store != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := g.store.OpenCustodyIncident(ctx, reason, mode); err != nil {
			slog.Error("falha ao persistir incidente de custodia", "error", err)
		}
	}
	slog.Error("custody guard ativou lockdown", "reason", reason, "mode", mode)
}

func (g *CustodyGuard) Start(ctx context.Context) {
	if !g.Enabled() {
		return
	}
	if g.store != nil {
		if incident, ok, err := g.store.ActiveCustodyIncident(ctx); err == nil && ok {
			g.locked.Store(true)
			g.reason.Store("incidente persistente: " + incident.Reason)
		}
	}
	poll := time.Duration(g.cfg.CustodyGuardPollMs) * time.Millisecond
	if poll < 500*time.Millisecond {
		poll = 500 * time.Millisecond
	}
	if err := g.loadTrustedDelegateHashes(ctx); err != nil {
		g.Lock("falha ao carregar hashes dos delegates confiaveis: " + err.Error())
		return
	}
	slog.Info("custody guard EIP-7702 iniciado", "protected_wallets", len(g.protected), "trusted_delegates", len(g.trusted), "poll_ms", poll.Milliseconds(), "mode", g.cfg.CustodyMode)
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			g.scanOnce(ctx)
		}
	}
}

func (g *CustodyGuard) scanOnce(ctx context.Context) {
	if g.locked.Load() {
		return
	}
	for _, tag := range []string{"pending", "latest"} {
		if err := g.scanBlockTag(ctx, tag); err != nil {
			slog.Warn("custody guard scan falhou", "tag", tag, "error", err)
		}
		if g.locked.Load() {
			return
		}
	}
}

func (g *CustodyGuard) scanBlockTag(ctx context.Context, tag string) error {
	for _, url := range g.cfg.RPCURLs {
		client, err := rpc.DialContext(ctx, url)
		if err != nil {
			continue
		}
		var block rpcBlockWithTransactions
		err = client.CallContext(ctx, &block, "eth_getBlockByNumber", tag, true)
		client.Close()
		if err != nil {
			continue
		}
		for _, tx := range block.Transactions {
			g.inspectTransaction(tag, tx)
			if g.locked.Load() {
				return nil
			}
		}
		return nil
	}
	return errors.New("nenhum RPC respondeu eth_getBlockByNumber")
}

func (g *CustodyGuard) inspectTransaction(source string, tx *types.Transaction) {
	if tx == nil || tx.Type() != types.SetCodeTxType {
		return
	}
	selector := calldataSelector(tx.Data())
	for _, auth := range tx.SetCodeAuthorizations() {
		authority, err := auth.Authority()
		if err != nil || !g.protected[authority] {
			continue
		}
		if len(g.allowedSelector) > 0 {
			if _, ok := g.allowedSelector[selector]; !ok {
				g.recordEvent("unknown_selector", "EIP-7702 selector nao permitido", tx.Hash().Hex(), authority.Hex())
				g.Lock("EIP-7702 selector nao permitido source=" + source + " tx=" + tx.Hash().Hex())
				return
			}
		}
		expectedHash, trusted := g.trusted[auth.Address]
		if !trusted {
			g.recordEvent("unknown_delegate", "EIP-7702 delegate desconhecido", tx.Hash().Hex(), authority.Hex())
			g.Lock("EIP-7702 delegate desconhecido source=" + source + " wallet=" + authority.Hex() + " delegate=" + auth.Address.Hex() + " tx=" + tx.Hash().Hex())
			return
		}
		if expectedHash != (common.Hash{}) {
			if err := g.verifyDelegateHash(auth.Address, expectedHash); err != nil {
				g.Lock("EIP-7702 delegate hash alterado: " + err.Error())
				return
			}
		}
	}
}

func (g *CustodyGuard) Unlock(ctx context.Context, note string) error {
	if g == nil {
		return nil
	}
	if g.store != nil {
		incident, ok, err := g.store.ActiveCustodyIncident(ctx)
		if err != nil {
			return err
		}
		if ok {
			cooldownSeconds := 0
			if g.cfg != nil {
				cooldownSeconds = g.cfg.CustodyUnlockCooldown
			}
			cooldown := time.Duration(cooldownSeconds) * time.Second
			if cooldown > 0 && time.Since(incident.CreatedAt) < cooldown {
				return errors.New("cooldown de custodia ainda ativo")
			}
			if err := g.store.ResolveCustodyIncident(ctx, note); err != nil {
				return err
			}
		}
	}
	g.locked.Store(false)
	g.reason.Store("")
	g.recordEvent("signer_unlocked", note, "", "")
	return nil
}

func (g *CustodyGuard) recordEvent(kind, reason, txHash, wallet string) {
	if g == nil || g.store == nil {
		return
	}
	mode := "paper"
	if g.cfg != nil {
		mode = normalizeCustodyMode(g.cfg.CustodyMode)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := g.store.RecordCustodyEvent(ctx, CustodyEvent{
		Kind:   kind,
		Reason: reason,
		Mode:   mode,
		TxHash: txHash,
		Wallet: wallet,
	}); err != nil {
		slog.Warn("falha ao registrar evento de custodia", "kind", kind, "error", err)
	}
}

func (g *CustodyGuard) verifyDelegateHash(delegate common.Address, expected common.Hash) error {
	for _, url := range g.cfg.RPCURLs {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		client, err := ethclient.DialContext(ctx, url)
		if err != nil {
			cancel()
			continue
		}
		code, err := client.CodeAt(ctx, delegate, nil)
		client.Close()
		cancel()
		if err != nil {
			continue
		}
		observed := crypto.Keccak256Hash(code)
		if observed != expected {
			return errors.New(delegate.Hex())
		}
		return nil
	}
	return errors.New("sem RPC para verificar delegate " + delegate.Hex())
}

func (g *CustodyGuard) loadTrustedDelegateHashes(ctx context.Context) error {
	for delegate := range g.trusted {
		code, err := g.codeAtAnyRPC(ctx, delegate)
		if err != nil {
			return err
		}
		if len(code) == 0 {
			return errors.New("trusted delegate sem bytecode: " + delegate.Hex())
		}
		g.trusted[delegate] = crypto.Keccak256Hash(code)
	}
	return nil
}

func (g *CustodyGuard) codeAtAnyRPC(ctx context.Context, address common.Address) ([]byte, error) {
	for _, url := range g.cfg.RPCURLs {
		callCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		client, err := ethclient.DialContext(callCtx, url)
		if err != nil {
			cancel()
			continue
		}
		code, err := client.CodeAt(callCtx, address, nil)
		client.Close()
		cancel()
		if err == nil {
			return code, nil
		}
	}
	return nil, errors.New("sem RPC para ler bytecode")
}

func ExtractEIP7702Delegate(code []byte) (common.Address, bool) {
	if len(code) < 23 || !strings.EqualFold(hexutil.Encode(code[:3]), eip7702DelegationPrefix) {
		return common.Address{}, false
	}
	return common.BytesToAddress(code[3:23]), true
}

func SignEIP7702Authorization(privateKey *ecdsa.PrivateKey, chainID *big.Int, delegate common.Address, nonce uint64) (types.SetCodeAuthorization, error) {
	auth := types.SetCodeAuthorization{
		ChainID: *uint256FromBig(chainID),
		Address: delegate,
		Nonce:   nonce,
	}
	return types.SignSetCode(privateKey, auth)
}

func uint256FromBig(value *big.Int) *uint256.Int {
	if value == nil {
		return uint256.NewInt(0)
	}
	out, overflow := uint256.FromBig(value)
	if overflow {
		return uint256.NewInt(0)
	}
	return out
}

func calldataSelector(data []byte) [4]byte {
	var selector [4]byte
	copy(selector[:], data)
	return selector
}

func parseAddressSet(raw string) map[common.Address]bool {
	out := map[common.Address]bool{}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if common.IsHexAddress(item) {
			out[common.HexToAddress(item)] = true
		}
	}
	return out
}

func parseSelectorSet(raw string) map[[4]byte]bool {
	out := map[[4]byte]bool{}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimPrefix(strings.TrimSpace(item), "0x")
		if len(item) != 8 {
			continue
		}
		bytes, err := hexutil.Decode("0x" + item)
		if err != nil || len(bytes) != 4 {
			continue
		}
		var selector [4]byte
		copy(selector[:], bytes)
		out[selector] = true
	}
	return out
}
