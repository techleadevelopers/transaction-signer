package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

type TransferRequest struct {
	To             string `json:"to"`
	Amount         string `json:"amount"`
	TokenContract  string `json:"tokenContract"`
	IdempotencyKey string `json:"idempotencyKey"`
}

type TransferResponse struct {
	TxHash string `json:"txHash"`
	From   string `json:"from"`
}

type replayCache struct {
	mu      sync.Mutex
	nonces  map[string]time.Time
	results map[string]TransferResponse
}

func newReplayCache() *replayCache {
	return &replayCache{nonces: make(map[string]time.Time), results: make(map[string]TransferResponse)}
}

func (c *replayCache) acceptNonce(nonce string, ttl time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for key, expires := range c.nonces {
		if now.After(expires) {
			delete(c.nonces, key)
		}
	}
	if _, exists := c.nonces[nonce]; exists {
		return false
	}
	c.nonces[nonce] = now.Add(ttl)
	return true
}

func (c *replayCache) getResult(key string) (TransferResponse, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	resp, ok := c.results[key]
	return resp, ok
}

func (c *replayCache) saveResult(key string, resp TransferResponse) {
	if key == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.results[key] = resp
}

func main() {
	cfg := LoadSignerConfig()
	if cfg.HMACSecret == "" || cfg.EVMPrivateKey == "" {
		slog.Error("HMAC_SECRET e EVM_PRIVATE_KEY sao obrigatorios")
		os.Exit(1)
	}

	cache := newReplayCache()
	http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeSignerJSON(w, map[string]any{"ok": true, "service": "signer"})
	})
	http.HandleFunc("/hd/transfer", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "metodo nao permitido", http.StatusMethodNotAllowed)
			return
		}
		ts := r.Header.Get("x-ts")
		nonce := r.Header.Get("x-nonce")
		hmacHeader := r.Header.Get("x-signer-hmac")
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "erro ao ler body", http.StatusBadRequest)
			return
		}
		if err := ValidateHMAC(cfg.HMACSecret, cfg.HMACMaxSkewSec, ts, nonce, hmacHeader, body); err != nil {
			slog.Warn("HMAC rejeitado", "error", err)
			http.Error(w, "nao autorizado", http.StatusUnauthorized)
			return
		}
		if !cache.acceptNonce(nonce, time.Duration(cfg.HMACMaxSkewSec)*time.Second) {
			http.Error(w, "nonce reutilizado", http.StatusUnauthorized)
			return
		}

		var req TransferRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "JSON invalido", http.StatusBadRequest)
			return
		}
		if req.IdempotencyKey != "" {
			if previous, ok := cache.getResult(req.IdempotencyKey); ok {
				writeSignerJSON(w, previous)
				return
			}
		}

		resp, err := executeTransfer(r.Context(), cfg, req)
		if err != nil {
			slog.Error("falha ao executar transferencia", "error", err, "to", req.To)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		cache.saveResult(req.IdempotencyKey, resp)
		writeSignerJSON(w, resp)
	})

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	slog.Info("signer EVM rodando", "port", cfg.Port)
	if err := server.ListenAndServe(); err != nil {
		slog.Error("erro ao rodar signer", "error", err)
	}
}

func executeTransfer(ctx context.Context, cfg *SignerConfig, req TransferRequest) (TransferResponse, error) {
	privateKey, err := crypto.HexToECDSA(strings.TrimPrefix(cfg.EVMPrivateKey, "0x"))
	if err != nil {
		return TransferResponse{}, fmt.Errorf("EVM_PRIVATE_KEY invalida: %w", err)
	}
	from := crypto.PubkeyToAddress(privateKey.PublicKey)
	if cfg.AllowSimulation {
		hash := crypto.Keccak256Hash([]byte(req.IdempotencyKey + req.To + req.Amount)).Hex()
		return TransferResponse{TxHash: hash, From: from.Hex()}, nil
	}
	if !common.IsHexAddress(req.To) {
		return TransferResponse{}, errors.New("destinatario nao EVM; use signer TRON dedicado ou SIGNER_ALLOW_SIMULATION=true")
	}
	to := common.HexToAddress(req.To)

	client, err := ethclient.DialContext(ctx, cfg.RPCURL)
	if err != nil {
		return TransferResponse{}, fmt.Errorf("RPC indisponivel: %w", err)
	}
	defer client.Close()
	chainID, err := client.ChainID(ctx)
	if err != nil {
		return TransferResponse{}, fmt.Errorf("falha ao obter chain id: %w", err)
	}
	nonce, err := client.PendingNonceAt(ctx, from)
	if err != nil {
		return TransferResponse{}, fmt.Errorf("falha ao obter nonce: %w", err)
	}
	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		return TransferResponse{}, fmt.Errorf("falha ao obter gas price: %w", err)
	}

	var tx *types.Transaction
	token := common.HexToAddress(req.TokenContract)
	if strings.TrimSpace(req.TokenContract) != "" && token != (common.Address{}) {
		amount, err := parseUnits(req.Amount, cfg.TokenDecimals)
		if err != nil {
			return TransferResponse{}, err
		}
		data := erc20TransferData(to, amount)
		gasLimit, err := client.EstimateGas(ctx, ethereum.CallMsg{From: from, To: &token, Data: data})
		if err != nil || gasLimit == 0 {
			gasLimit = 120000
		}
		tx = types.NewTransaction(nonce, token, big.NewInt(0), gasLimit, gasPrice, data)
	} else {
		amount, err := parseUnits(req.Amount, 18)
		if err != nil {
			return TransferResponse{}, err
		}
		gasLimit, err := client.EstimateGas(ctx, ethereum.CallMsg{From: from, To: &to, Value: amount})
		if err != nil || gasLimit == 0 {
			gasLimit = 21000
		}
		tx = types.NewTransaction(nonce, to, amount, gasLimit, gasPrice, nil)
	}

	signed, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), privateKey)
	if err != nil {
		return TransferResponse{}, fmt.Errorf("falha ao assinar tx: %w", err)
	}
	if err := client.SendTransaction(ctx, signed); err != nil {
		return TransferResponse{}, fmt.Errorf("falha ao transmitir tx: %w", err)
	}
	return TransferResponse{TxHash: signed.Hash().Hex(), From: from.Hex()}, nil
}

func parseUnits(value string, decimals int) (*big.Int, error) {
	if decimals < 0 || decimals > 30 {
		return nil, errors.New("decimais invalidos")
	}
	parts := strings.Split(strings.TrimSpace(value), ".")
	if len(parts) > 2 || parts[0] == "" {
		return nil, errors.New("amount invalido")
	}
	whole := new(big.Int)
	if _, ok := whole.SetString(parts[0], 10); !ok {
		return nil, errors.New("amount invalido")
	}
	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil)
	whole.Mul(whole, scale)
	if len(parts) == 1 {
		return whole, nil
	}
	fraction := parts[1]
	if len(fraction) > decimals {
		fraction = fraction[:decimals]
	}
	for len(fraction) < decimals {
		fraction += "0"
	}
	frac := new(big.Int)
	if fraction != "" {
		if _, ok := frac.SetString(fraction, 10); !ok {
			return nil, errors.New("amount invalido")
		}
	}
	return whole.Add(whole, frac), nil
}

func erc20TransferData(to common.Address, amount *big.Int) []byte {
	selector, _ := hex.DecodeString("a9059cbb")
	data := make([]byte, 4+32+32)
	copy(data[:4], selector)
	copy(data[4+12:36], to.Bytes())
	amountBytes := amount.Bytes()
	copy(data[68-len(amountBytes):], amountBytes)
	return data
}

func writeSignerJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}
