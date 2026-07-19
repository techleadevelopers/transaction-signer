package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"payment-gateway/internal/security"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

type TransferRequest struct {
	To              string `json:"to"`
	Amount          string `json:"amount"`
	TokenContract   string `json:"tokenContract"`
	Network         string `json:"network"`
	IdempotencyKey  string `json:"idempotencyKey"`
	DerivationIndex *int   `json:"derivationIndex,omitempty"`
}

type ContractCallRequest struct {
	To              string `json:"to"`
	Data            string `json:"data"`
	Network         string `json:"network"`
	IdempotencyKey  string `json:"idempotencyKey"`
	Amount          string `json:"amount,omitempty"`
	TokenContract   string `json:"tokenContract,omitempty"`
	DerivationIndex *int   `json:"derivationIndex,omitempty"`
}

type SettlementExecuteRequest struct {
	OperationID        string `json:"operationId"`
	SettlementIntentID string `json:"settlementIntentId"`
	OrderID            string `json:"orderId"`
	Side               string `json:"side"`
	Network            string `json:"network"`
	ChainID            uint64 `json:"chainId"`
	Vault              string `json:"vault"`
	Token              string `json:"token"`
	Recipient          string `json:"recipient"`
	AmountRaw          string `json:"amountRaw"`
	SourceChannel      string `json:"sourceChannel"`
	PolicyVersion      string `json:"policyVersion"`
	NetworkPolicy      string `json:"networkPolicy"`
	RiskPolicy         string `json:"riskPolicy"`
	ContractVersion    string `json:"contractVersion"`
	AuthorizedAt       string `json:"authorizedAt"`
	ExpiresAt          string `json:"expiresAt"`
	IdempotencyKey     string `json:"idempotencyKey"`
}

const settlementPolicyVersion = "settlement-policy-v1.0.0"

type TransferResponse struct {
	TxHash  string `json:"txHash"`
	From    string `json:"from"`
	Network string `json:"network"`
}

func main() {
	cfg := LoadSignerConfig()
	if err := cfg.ValidateProduction(); err != nil {
		slog.Error("configuracao insegura para producao", "error", err)
		os.Exit(1)
	}

	// ===== NOVO: Configurar Security =====
	_, middleware, closeSecurity, err := setupSecurity(cfg)
	if err != nil {
		slog.Error("falha ao configurar seguranca do signer", "error", err)
		os.Exit(1)
	}
	defer closeSecurity()

	// Validações existentes
	if cfg.Security.HMACSecret == "" {
		slog.Error("HMAC_SECRET obrigatorio")
		os.Exit(1)
	}
	if (cfg.DefaultNetwork == "BSC" || cfg.DefaultNetwork == "EVM") && cfg.EVMPrivateKey == "" {
		slog.Error("EVM_PRIVATE_KEY obrigatorio para BSC/EVM")
		os.Exit(1)
	}

	storeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	store, err := openSignerStore(storeCtx, cfg)
	if err != nil {
		slog.Error("falha ao abrir storage do signer", "error", err)
		os.Exit(1)
	}
	defer store.Close()

	custodyGuard, err := NewCustodyGuard(cfg, store)
	if err != nil && cfg.CustodyGuardEnabled {
		slog.Error("falha ao inicializar custody guard", "error", err)
		os.Exit(1)
	}
	if custodyGuard != nil && custodyGuard.Enabled() {
		go custodyGuard.Start(context.Background())
	}
	if !cfg.AllowSimulation {
		go startTxLifecycleMonitor(context.Background(), cfg, store)
	}

	// ===== ROTAS =====
	mux := http.NewServeMux()

	// Rotas públicas (sem autenticação)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeSignerJSON(w, map[string]any{"ok": true, "service": "signer"})
	})

	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		locked, lockReason := custodyGuard.Locked()
		ready := map[string]any{
			"ok":           !locked,
			"service":      "signer",
			"network":      cfg.DefaultNetwork,
			"nonceStore":   cfg.Security.NonceStoreType,
			"custodyGuard": cfg.CustodyGuardEnabled,
			"custodyMode":  cfg.CustodyMode,
			"lockdown":     locked,
			"treasury": map[string]any{
				"minUSDT":              cfg.TreasuryMinUSDT,
				"targetUSDT":           cfg.TreasuryTargetUSDT,
				"maxUSDT":              cfg.TreasuryMaxUSDT,
				"maxDailyOutflow":      cfg.TreasuryMaxDailyOut,
				"lockdownDailyOutflow": cfg.TreasuryLockThreshold,
			},
			"settlementVaultConfigured": strings.TrimSpace(cfg.BSCTreasuryContract) != "",
		}
		if locked {
			ready["lockReason"] = lockReason
		}
		if err := store.Ready(ctx); err != nil {
			ready["ok"] = false
			ready["storage"] = err.Error()
		}
		if (cfg.DefaultNetwork == "BSC" || cfg.DefaultNetwork == "EVM") && (len(cfg.RPCURLs) == 0 || cfg.BSCUSDTContract == "") {
			ready["ok"] = false
			ready["bsc"] = "BSC_RPC_URLS e BSC_USDT_CONTRACT obrigatorios"
		}
		status := http.StatusOK
		if ready["ok"] == false {
			status = http.StatusServiceUnavailable
		}
		writeJSONStatus(w, status, ready)
	})

	// ===== ROTAS PROTEGIDAS (com middleware) =====
	mux.Handle("/custody/unlock", middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "metodo nao permitido", http.StatusMethodNotAllowed)
			return
		}

		// Recupera contexto da requisição (já validado pelo middleware)
		reqCtx := security.GetRequestContext(r.Context())
		if reqCtx == nil {
			http.Error(w, "contexto nao encontrado", http.StatusInternalServerError)
			return
		}

		// Lê body (já validado pelo middleware)
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "erro ao ler body", http.StatusBadRequest)
			return
		}

		// Nonce já foi validado pelo middleware, mas ainda precisamos verificar no store
		// O middleware já validou o HMAC e o Nonce, mas precisamos persistir o nonce no store
		// para anti-replay entre instâncias
		accepted, err := store.AcceptNonce(r.Context(), reqCtx.Nonce, cfg.GetNonceTTL())
		if err != nil {
			http.Error(w, "storage indisponivel", http.StatusServiceUnavailable)
			return
		}
		if !accepted {
			http.Error(w, "nonce ja utilizado", http.StatusUnauthorized)
			return
		}

		var payload struct {
			Note string `json:"note"`
		}
		_ = json.Unmarshal(body, &payload)
		if err := custodyGuard.Unlock(r.Context(), payload.Note); err != nil {
			http.Error(w, err.Error(), http.StatusLocked)
			return
		}
		writeSignerJSON(w, map[string]any{"ok": true, "lockdown": false, "requestId": reqCtx.RequestID})
	})))

	mux.Handle("/hd/transfer", middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "metodo nao permitido", http.StatusMethodNotAllowed)
			return
		}
		if locked, reason := custodyGuard.Locked(); locked {
			slog.Error("transferencia bloqueada por custody guard", "reason", reason)
			http.Error(w, "custody guard lockdown", http.StatusLocked)
			return
		}

		// Recupera contexto da requisição (já validado pelo middleware)
		reqCtx := security.GetRequestContext(r.Context())
		if reqCtx == nil {
			http.Error(w, "contexto nao encontrado", http.StatusInternalServerError)
			return
		}

		// Lê body (já validado pelo middleware)
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "erro ao ler body", http.StatusBadRequest)
			return
		}

		// Persiste nonce no store (anti-replay entre instâncias)
		accepted, err := store.AcceptNonce(r.Context(), reqCtx.Nonce, cfg.GetNonceTTL())
		if err != nil {
			slog.Error("falha ao persistir nonce", "error", err)
			http.Error(w, "storage indisponivel", http.StatusServiceUnavailable)
			return
		}
		if !accepted {
			http.Error(w, "nonce ja utilizado", http.StatusUnauthorized)
			return
		}

		var req TransferRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "JSON invalido", http.StatusBadRequest)
			return
		}

		// Log com RequestID
		slog.Info("transferencia recebida",
			"requestId", reqCtx.RequestID,
			"to", shortValue(req.To),
			"amount", req.Amount,
			"network", requestedNetwork(cfg, req),
		)

		previous, done, claimed, err := store.ClaimResult(r.Context(), req.IdempotencyKey)
		if err != nil {
			slog.Error("falha ao reservar idempotencia", "error", err)
			http.Error(w, "storage indisponivel", http.StatusServiceUnavailable)
			return
		}
		if done {
			writeSignerJSON(w, previous)
			return
		}
		if !claimed {
			http.Error(w, "idempotency key em processamento", http.StatusConflict)
			return
		}

		resp, err := executeTransfer(r.Context(), cfg, store, req)
		if err != nil {
			_ = store.ReleaseClaim(r.Context(), req.IdempotencyKey)
			slog.Error("falha ao executar transferencia",
				"error", err,
				"requestId", reqCtx.RequestID,
				"network", requestedNetwork(cfg, req),
				"to", shortValue(req.To),
			)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		if err := store.SaveResult(r.Context(), req.IdempotencyKey, resp); err != nil {
			slog.Error("falha ao salvar idempotencia", "error", err)
			http.Error(w, "storage indisponivel", http.StatusServiceUnavailable)
			return
		}
		writeSignerJSON(w, resp)
	})))

	mux.Handle("/settlements/execute", middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "metodo nao permitido", http.StatusMethodNotAllowed)
			return
		}

		if locked, reason := custodyGuard.Locked(); locked {
			slog.Error("settlement bloqueado por custody guard", "reason", reason)
			http.Error(w, "custody guard lockdown", http.StatusLocked)
			return
		}

		reqCtx := security.GetRequestContext(r.Context())
		if reqCtx == nil {
			http.Error(w, "contexto nao encontrado", http.StatusInternalServerError)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "erro ao ler body", http.StatusBadRequest)
			return
		}

		accepted, err := store.AcceptNonce(r.Context(), reqCtx.Nonce, cfg.GetNonceTTL())
		if err != nil {
			slog.Error("falha ao persistir nonce", "error", err)
			http.Error(w, "storage indisponivel", http.StatusServiceUnavailable)
			return
		}
		if !accepted {
			http.Error(w, "nonce ja utilizado", http.StatusUnauthorized)
			return
		}

		var req SettlementExecuteRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "JSON invalido", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.IdempotencyKey) == "" {
			req.IdempotencyKey = strings.TrimSpace(req.OperationID)
		}

		slog.Info("settlement recebido",
			"requestId", reqCtx.RequestID,
			"operationId", shortValue(req.OperationID),
			"orderId", req.OrderID,
			"network", req.Network,
			"recipient", shortValue(req.Recipient),
		)

		previous, done, claimed, err := store.ClaimResult(r.Context(), req.IdempotencyKey)
		if err != nil {
			slog.Error("falha ao reservar idempotencia", "error", err)
			http.Error(w, "storage indisponivel", http.StatusServiceUnavailable)
			return
		}
		if done {
			writeSignerJSON(w, previous)
			return
		}
		if !claimed {
			http.Error(w, "idempotency key em processamento", http.StatusConflict)
			return
		}

		resp, err := executeSettlement(r.Context(), cfg, store, req)
		if err != nil {
			_ = store.ReleaseClaim(r.Context(), req.IdempotencyKey)
			slog.Error("falha ao executar settlement",
				"error", err,
				"requestId", reqCtx.RequestID,
				"operationId", shortValue(req.OperationID),
			)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		if err := store.SaveResult(r.Context(), req.IdempotencyKey, resp); err != nil {
			slog.Error("falha ao salvar idempotencia", "error", err)
			http.Error(w, "storage indisponivel", http.StatusServiceUnavailable)
			return
		}
		writeSignerJSON(w, resp)
	})))

	mux.Handle("/hd/contract-call", middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "metodo nao permitido", http.StatusMethodNotAllowed)
			return
		}

		if locked, reason := custodyGuard.Locked(); locked {
			slog.Error("contract-call bloqueado por custody guard", "reason", reason)
			http.Error(w, "custody guard lockdown", http.StatusLocked)
			return
		}

		reqCtx := security.GetRequestContext(r.Context())
		if reqCtx == nil {
			http.Error(w, "contexto nao encontrado", http.StatusInternalServerError)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "erro ao ler body", http.StatusBadRequest)
			return
		}

		accepted, err := store.AcceptNonce(r.Context(), reqCtx.Nonce, cfg.GetNonceTTL())
		if err != nil {
			slog.Error("falha ao persistir nonce", "error", err)
			http.Error(w, "storage indisponivel", http.StatusServiceUnavailable)
			return
		}
		if !accepted {
			http.Error(w, "nonce ja utilizado", http.StatusUnauthorized)
			return
		}

		var req ContractCallRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "JSON invalido", http.StatusBadRequest)
			return
		}

		slog.Info("contract-call recebido",
			"requestId", reqCtx.RequestID,
			"to", shortValue(req.To),
			"network", requestedContractNetwork(cfg, req),
			"dataBytes", len(strings.TrimPrefix(req.Data, "0x"))/2,
		)

		previous, done, claimed, err := store.ClaimResult(r.Context(), req.IdempotencyKey)
		if err != nil {
			slog.Error("falha ao reservar idempotencia", "error", err)
			http.Error(w, "storage indisponivel", http.StatusServiceUnavailable)
			return
		}
		if done {
			writeSignerJSON(w, previous)
			return
		}
		if !claimed {
			http.Error(w, "idempotency key em processamento", http.StatusConflict)
			return
		}

		resp, err := executeContractCall(r.Context(), cfg, store, req)
		if err != nil {
			_ = store.ReleaseClaim(r.Context(), req.IdempotencyKey)
			slog.Error("falha ao executar contract-call",
				"error", err,
				"requestId", reqCtx.RequestID,
				"network", requestedContractNetwork(cfg, req),
				"to", shortValue(req.To),
			)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		if err := store.SaveResult(r.Context(), req.IdempotencyKey, resp); err != nil {
			slog.Error("falha ao salvar idempotencia", "error", err)
			http.Error(w, "storage indisponivel", http.StatusServiceUnavailable)
			return
		}
		writeSignerJSON(w, resp)
	})))

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	slog.Info("signer rodando",
		"port", cfg.Port,
		"network", cfg.DefaultNetwork,
		"storage", cfg.DatabaseURL != "",
		"hmac", cfg.Security.HMACSecret != "",
		"nonce", cfg.Security.NonceTTLSeconds,
		"rateLimit", cfg.Security.RateLimitPerMin,
	)

	if err := server.ListenAndServe(); err != nil {
		slog.Error("erro ao rodar signer", "error", err)
	}
}

// ===== NOVA FUNÇÃO: setupSecurity =====
func setupSecurity(cfg *SignerConfig) (*security.RequestValidator, *security.Middleware, func(), error) {
	// Configura Nonce Store
	var nonceStore security.NonceStore
	closeSecurity := func() {}
	switch cfg.Security.NonceStoreType {
	case "redis":
		if strings.TrimSpace(cfg.RedisURL) == "" {
			return nil, nil, nil, fmt.Errorf("REDIS_URL obrigatorio quando NONCE_STORE_TYPE=redis")
		}
		redisStore, err := security.NewRedisNonceStore(cfg.RedisURL)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("redis nonce store indisponivel: %w", err)
		}
		nonceStore = redisStore
		closeSecurity = func() {
			if err := redisStore.Close(); err != nil {
				slog.Warn("falha ao fechar redis nonce store", "error", err)
			}
		}
		slog.Info("Redis nonce store configurado", "storeType", cfg.Security.NonceStoreType)
	default:
		nonceStore = security.NewInMemoryNonceStore()
	}

	// Configura Validador
	validatorConfig := security.RequestValidatorConfig{
		HMACSecret:      cfg.Security.HMACSecret,
		HMACMaxSkew:     cfg.Security.HMACMaxSkewSec,
		NonceStore:      nonceStore,
		NonceTTL:        cfg.GetNonceTTL(),
		RateLimit:       cfg.GetRateLimit(),
		RateWindow:      cfg.GetRateWindow(),
		RateLimiterType: security.RateLimiterType(cfg.GetRateLimiterType()),
		MaxBodySize:     cfg.GetMaxBodySize(),
		OldSecret:       cfg.Security.HMACOldSecret,
	}

	validator := security.NewRequestValidator(validatorConfig)

	// Configura Middleware
	middleware := security.NewMiddleware(validator, security.SecurityOptions{
		Enabled:        true,
		RequireHMAC:    cfg.Security.RequireHMAC,
		RequireNonce:   cfg.Security.RequireNonce,
		RequireAPIKey:  cfg.Security.RequireAPIKey,
		ExcludePaths:   []string{"/healthz", "/readyz"},
		AllowedMethods: []string{"POST", "GET"},
	})

	return validator, middleware, closeSecurity, nil
}

// ===== Funções existentes (mantidas) =====

func executeSettlement(ctx context.Context, cfg *SignerConfig, store signerStore, req SettlementExecuteRequest) (TransferResponse, error) {
	network, amount, err := validateSettlementExecuteRequest(cfg, req)
	if err != nil {
		return TransferResponse{}, err
	}
	switch network {
	case "BSC", "EVM":
		return executeEVMSettlement(ctx, cfg, store, req, network, amount)
	default:
		return TransferResponse{}, fmt.Errorf("rede nao suportada: %s", network)
	}
}

func validateSettlementExecuteRequest(cfg *SignerConfig, req SettlementExecuteRequest) (string, *big.Int, error) {
	network := strings.ToUpper(strings.TrimSpace(req.Network))
	if network == "" {
		network = cfg.DefaultNetwork
	}
	if network == "BINANCE" || network == "BEP20" {
		network = "BSC"
	}
	if !cfg.AllowedNetworks[network] {
		return "", nil, fmt.Errorf("rede nao permitida: %s", network)
	}
	if network != "BSC" && network != "EVM" {
		return "", nil, fmt.Errorf("rede nao suportada: %s", network)
	}
	if req.ChainID == 0 {
		return "", nil, errors.New("chainId obrigatorio")
	}
	if network == "BSC" && cfg.BSCChainID > 0 && req.ChainID != uint64(cfg.BSCChainID) {
		return "", nil, fmt.Errorf("chainId divergente para BSC: %d", req.ChainID)
	}
	if strings.TrimSpace(req.OperationID) == "" {
		return "", nil, errors.New("operationId obrigatorio")
	}
	operationIDHex := strings.TrimPrefix(strings.TrimSpace(req.OperationID), "0x")
	if len(operationIDHex) != 64 {
		return "", nil, errors.New("operationId invalido")
	}
	if _, err := hex.DecodeString(operationIDHex); err != nil {
		return "", nil, errors.New("operationId invalido")
	}
	if strings.TrimSpace(req.SettlementIntentID) == "" {
		return "", nil, errors.New("settlementIntentId obrigatorio")
	}
	if strings.TrimSpace(req.OrderID) == "" {
		return "", nil, errors.New("orderId obrigatorio")
	}
	if !common.IsHexAddress(req.Vault) {
		return "", nil, errors.New("vault EVM invalido")
	}
	if strings.TrimSpace(cfg.BSCTreasuryContract) == "" {
		return "", nil, errors.New("BSC_TREASURY_CONTRACT obrigatorio")
	}
	if !strings.EqualFold(req.Vault, cfg.BSCTreasuryContract) {
		return "", nil, errors.New("vault nao autorizado")
	}
	if !common.IsHexAddress(req.Token) {
		return "", nil, errors.New("token EVM invalido")
	}
	if strings.TrimSpace(cfg.BSCUSDTContract) == "" {
		return "", nil, errors.New("BSC_USDT_CONTRACT obrigatorio")
	}
	if !strings.EqualFold(req.Token, cfg.BSCUSDTContract) {
		return "", nil, errors.New("token divergente do BSC_USDT_CONTRACT")
	}
	if len(cfg.AllowedTokenContracts) > 0 && !cfg.AllowedTokenContracts[strings.ToUpper(strings.TrimSpace(req.Token))] {
		return "", nil, errors.New("token contract nao permitido")
	}
	if !common.IsHexAddress(req.Recipient) {
		return "", nil, errors.New("recipient EVM invalido")
	}
	amount, ok := new(big.Int).SetString(strings.TrimSpace(req.AmountRaw), 10)
	if !ok || amount.Sign() <= 0 {
		return "", nil, errors.New("amountRaw invalido")
	}
	if strings.TrimSpace(req.PolicyVersion) != settlementPolicyVersion {
		return "", nil, errors.New("policyVersion invalida")
	}
	expiresAt, err := time.Parse(time.RFC3339, req.ExpiresAt)
	if err != nil {
		expiresAt, err = time.Parse(time.RFC3339Nano, req.ExpiresAt)
	}
	if err != nil {
		return "", nil, errors.New("expiresAt invalido")
	}
	if !time.Now().Before(expiresAt) {
		return "", nil, errors.New("SETTLEMENT_AUTHORIZATION_EXPIRED")
	}
	expected, err := settlementOperationID(int64(req.ChainID), req.Vault, req.SettlementIntentID, req.Token, req.Recipient, amount)
	if err != nil {
		return "", nil, err
	}
	if common.HexToHash(req.OperationID) != expected {
		return "", nil, errors.New("SETTLEMENT_OPERATION_ID_MISMATCH")
	}
	return network, amount, nil
}

func executeEVMSettlement(ctx context.Context, cfg *SignerConfig, store signerStore, req SettlementExecuteRequest, network string, amount *big.Int) (TransferResponse, error) {
	privateKey, err := crypto.HexToECDSA(strings.TrimPrefix(cfg.EVMPrivateKey, "0x"))
	if err != nil {
		return TransferResponse{}, fmt.Errorf("EVM_PRIVATE_KEY invalida: %w", err)
	}
	from := crypto.PubkeyToAddress(privateKey.PublicKey)
	if cfg.AllowSimulation {
		hash := crypto.Keccak256Hash([]byte(req.IdempotencyKey + req.OperationID + req.Vault)).Hex()
		return TransferResponse{TxHash: hash, From: from.Hex(), Network: network}, nil
	}
	fleet := cfg.RPCFleet
	if fleet == nil {
		fleet = newRPCFleet(cfg.RPCURLs)
	}
	var lastErr error
	for _, handle := range fleet.sendCandidates(len(cfg.RPCURLs)) {
		start := time.Now()
		client, err := ethclient.DialContext(ctx, handle.url)
		if err != nil {
			fleet.recordFailure(handle.id, classifyRPCFailure(err))
			lastErr = fmt.Errorf("%s indisponivel: %w", handle.name, err)
			continue
		}
		resp, err := executeEVMSettlementWithClient(ctx, cfg, store, req, network, client, privateKey, from, amount)
		client.Close()
		if err != nil {
			fleet.recordFailure(handle.id, classifyRPCFailure(err))
			lastErr = fmt.Errorf("%s falhou: %w", handle.name, err)
			continue
		}
		fleet.recordSuccess(handle.id, time.Since(start))
		return resp, nil
	}
	if lastErr == nil {
		lastErr = errors.New("nenhum RPC BSC disponivel")
	}
	return TransferResponse{}, lastErr
}

func executeEVMSettlementWithClient(ctx context.Context, cfg *SignerConfig, store signerStore, req SettlementExecuteRequest, network string, client *ethclient.Client, privateKey *ecdsa.PrivateKey, from common.Address, amount *big.Int) (TransferResponse, error) {
	chainID, err := client.ChainID(ctx)
	if err != nil {
		return TransferResponse{}, fmt.Errorf("falha ao obter chain id: %w", err)
	}
	if chainID.Cmp(new(big.Int).SetUint64(req.ChainID)) != 0 {
		return TransferResponse{}, fmt.Errorf("chain id inesperado para settlement: %s", chainID.String())
	}
	chainPending, err := client.PendingNonceAt(ctx, from)
	if err != nil {
		return TransferResponse{}, fmt.Errorf("falha ao obter nonce: %w", err)
	}
	nonce, err := store.ReserveChainNonce(ctx, from.Hex(), network, chainPending)
	if err != nil {
		return TransferResponse{}, fmt.Errorf("falha ao reservar nonce: %w", err)
	}
	_ = store.RecordCustodyEvent(ctx, CustodyEvent{Kind: "nonce_reserved", Mode: cfg.CustodyMode, Wallet: from.Hex(), Data: map[string]any{"nonce": nonce, "network": network, "type": "settlement", "operationId": req.OperationID}})
	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		return TransferResponse{}, fmt.Errorf("falha ao obter gas price: %w", err)
	}
	data, err := vaultPayoutData(common.HexToHash(req.OperationID), common.HexToAddress(req.Token), common.HexToAddress(req.Recipient), amount)
	if err != nil {
		return TransferResponse{}, err
	}
	vault := common.HexToAddress(req.Vault)
	gasLimit, err := client.EstimateGas(ctx, ethereum.CallMsg{From: from, To: &vault, Data: data})
	if err != nil || gasLimit == 0 {
		gasLimit = 350000
	}
	tx := types.NewTransaction(nonce, vault, big.NewInt(0), gasLimit, gasPrice, data)
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), privateKey)
	if err != nil {
		_ = store.MarkChainNonceFailed(ctx, from.Hex(), network, nonce, err.Error())
		return TransferResponse{}, fmt.Errorf("falha ao assinar tx: %w", err)
	}
	if err := client.SendTransaction(ctx, signed); err != nil {
		_ = store.MarkChainNonceFailed(ctx, from.Hex(), network, nonce, err.Error())
		_ = store.CreateSignerTransaction(ctx, SignerTransaction{
			IdempotencyKey: req.IdempotencyKey,
			WalletFrom:     from.Hex(),
			WalletTo:       req.Vault,
			Token:          req.Token,
			Amount:         req.AmountRaw,
			Network:        network,
			Nonce:          nonce,
			TxHash:         signed.Hash().Hex(),
			Status:         "failed",
			Reason:         err.Error(),
		})
		return TransferResponse{}, fmt.Errorf("falha ao transmitir tx: %w", err)
	}
	_ = store.MarkChainNonceSubmitted(ctx, from.Hex(), network, nonce, signed.Hash().Hex())
	_ = store.CreateSignerTransaction(ctx, SignerTransaction{
		IdempotencyKey: req.IdempotencyKey,
		WalletFrom:     from.Hex(),
		WalletTo:       req.Vault,
		Token:          req.Token,
		Amount:         req.AmountRaw,
		Network:        network,
		Nonce:          nonce,
		TxHash:         signed.Hash().Hex(),
		Status:         "submitted",
	})
	_ = store.RecordCustodyEvent(ctx, CustodyEvent{Kind: "tx_submitted", Mode: cfg.CustodyMode, TxHash: signed.Hash().Hex(), Wallet: from.Hex(), Data: map[string]any{"type": "settlement", "operationId": req.OperationID}})
	return TransferResponse{TxHash: signed.Hash().Hex(), From: from.Hex(), Network: network}, nil
}

func executeTransfer(ctx context.Context, cfg *SignerConfig, store signerStore, req TransferRequest) (TransferResponse, error) {
	network := requestedNetwork(cfg, req)
	if err := validateTransferPolicy(cfg, req, network); err != nil {
		return TransferResponse{}, err
	}
	if err := validateTreasuryPolicy(ctx, cfg, store, req, network); err != nil {
		return TransferResponse{}, err
	}
	if req.DerivationIndex != nil {
		return TransferResponse{}, errors.New("derivacao HD ainda nao habilitada para assinatura de hot wallet")
	}
	switch network {
	case "BSC", "EVM":
		return executeEVMTransfer(ctx, cfg, store, req, network)
	default:
		return TransferResponse{}, fmt.Errorf("rede nao suportada: %s", network)
	}
}

func executeContractCall(ctx context.Context, cfg *SignerConfig, store signerStore, req ContractCallRequest) (TransferResponse, error) {
	network := requestedContractNetwork(cfg, req)
	if err := validateContractCallPolicy(cfg, req, network); err != nil {
		return TransferResponse{}, err
	}
	if err := validateContractCallTreasuryPolicy(ctx, cfg, store, req, network); err != nil {
		return TransferResponse{}, err
	}
	if req.DerivationIndex != nil {
		return TransferResponse{}, errors.New("derivacao HD ainda nao habilitada para assinatura de hot wallet")
	}
	switch network {
	case "BSC", "EVM":
		return executeEVMContractCall(ctx, cfg, store, req, network)
	default:
		return TransferResponse{}, fmt.Errorf("rede nao suportada: %s", network)
	}
}

func executeEVMTransfer(ctx context.Context, cfg *SignerConfig, store signerStore, req TransferRequest, network string) (TransferResponse, error) {
	privateKey, err := crypto.HexToECDSA(strings.TrimPrefix(cfg.EVMPrivateKey, "0x"))
	if err != nil {
		return TransferResponse{}, fmt.Errorf("EVM_PRIVATE_KEY invalida: %w", err)
	}
	from := crypto.PubkeyToAddress(privateKey.PublicKey)
	if cfg.AllowSimulation {
		hash := crypto.Keccak256Hash([]byte(req.IdempotencyKey + req.To + req.Amount)).Hex()
		return TransferResponse{TxHash: hash, From: from.Hex(), Network: network}, nil
	}
	fleet := cfg.RPCFleet
	if fleet == nil {
		fleet = newRPCFleet(cfg.RPCURLs)
	}
	var lastErr error
	for _, handle := range fleet.sendCandidates(len(cfg.RPCURLs)) {
		start := time.Now()
		client, err := ethclient.DialContext(ctx, handle.url)
		if err != nil {
			fleet.recordFailure(handle.id, classifyRPCFailure(err))
			lastErr = fmt.Errorf("%s indisponivel: %w", handle.name, err)
			continue
		}
		resp, err := executeEVMTransferWithClient(ctx, cfg, store, req, network, client, privateKey, from)
		client.Close()
		if err != nil {
			fleet.recordFailure(handle.id, classifyRPCFailure(err))
			lastErr = fmt.Errorf("%s falhou: %w", handle.name, err)
			continue
		}
		fleet.recordSuccess(handle.id, time.Since(start))
		return resp, nil
	}
	if lastErr == nil {
		lastErr = errors.New("nenhum RPC BSC disponivel")
	}
	return TransferResponse{}, lastErr
}

func executeEVMTransferWithClient(ctx context.Context, cfg *SignerConfig, store signerStore, req TransferRequest, network string, client *ethclient.Client, privateKey *ecdsa.PrivateKey, from common.Address) (TransferResponse, error) {
	chainID, err := client.ChainID(ctx)
	if err != nil {
		return TransferResponse{}, fmt.Errorf("falha ao obter chain id: %w", err)
	}
	if network == "BSC" && chainID.Cmp(big.NewInt(56)) != 0 {
		return TransferResponse{}, fmt.Errorf("chain id inesperado para BSC: %s", chainID.String())
	}
	chainPending, err := client.PendingNonceAt(ctx, from)
	if err != nil {
		return TransferResponse{}, fmt.Errorf("falha ao obter nonce: %w", err)
	}
	nonce, err := store.ReserveChainNonce(ctx, from.Hex(), network, chainPending)
	if err != nil {
		return TransferResponse{}, fmt.Errorf("falha ao reservar nonce: %w", err)
	}
	_ = store.RecordCustodyEvent(ctx, CustodyEvent{Kind: "nonce_reserved", Mode: cfg.CustodyMode, Wallet: from.Hex(), Data: map[string]any{"nonce": nonce, "network": network}})
	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		return TransferResponse{}, fmt.Errorf("falha ao obter gas price: %w", err)
	}

	var tx *types.Transaction
	to := common.HexToAddress(req.To)
	tokenContract := normalizedTokenContract(cfg, req, network)
	token := common.HexToAddress(tokenContract)
	if strings.TrimSpace(tokenContract) != "" && token != (common.Address{}) {
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
		_ = store.MarkChainNonceFailed(ctx, from.Hex(), network, nonce, err.Error())
		return TransferResponse{}, fmt.Errorf("falha ao assinar tx: %w", err)
	}
	if err := client.SendTransaction(ctx, signed); err != nil {
		_ = store.MarkChainNonceFailed(ctx, from.Hex(), network, nonce, err.Error())
		_ = store.CreateSignerTransaction(ctx, SignerTransaction{
			IdempotencyKey: req.IdempotencyKey,
			WalletFrom:     from.Hex(),
			WalletTo:       req.To,
			Token:          normalizedTokenContract(cfg, req, network),
			Amount:         req.Amount,
			Network:        network,
			Nonce:          nonce,
			TxHash:         signed.Hash().Hex(),
			Status:         "failed",
			Reason:         err.Error(),
		})
		return TransferResponse{}, fmt.Errorf("falha ao transmitir tx: %w", err)
	}
	_ = store.MarkChainNonceSubmitted(ctx, from.Hex(), network, nonce, signed.Hash().Hex())
	_ = store.CreateSignerTransaction(ctx, SignerTransaction{
		IdempotencyKey: req.IdempotencyKey,
		WalletFrom:     from.Hex(),
		WalletTo:       req.To,
		Token:          normalizedTokenContract(cfg, req, network),
		Amount:         req.Amount,
		Network:        network,
		Nonce:          nonce,
		TxHash:         signed.Hash().Hex(),
		Status:         "submitted",
	})
	_ = store.RecordCustodyEvent(ctx, CustodyEvent{Kind: "tx_submitted", Mode: cfg.CustodyMode, TxHash: signed.Hash().Hex(), Wallet: from.Hex()})
	return TransferResponse{TxHash: signed.Hash().Hex(), From: from.Hex(), Network: network}, nil
}

func executeEVMContractCall(ctx context.Context, cfg *SignerConfig, store signerStore, req ContractCallRequest, network string) (TransferResponse, error) {
	privateKey, err := crypto.HexToECDSA(strings.TrimPrefix(cfg.EVMPrivateKey, "0x"))
	if err != nil {
		return TransferResponse{}, fmt.Errorf("EVM_PRIVATE_KEY invalida: %w", err)
	}
	from := crypto.PubkeyToAddress(privateKey.PublicKey)
	if cfg.AllowSimulation {
		hash := crypto.Keccak256Hash([]byte(req.IdempotencyKey + req.To + req.Data)).Hex()
		return TransferResponse{TxHash: hash, From: from.Hex(), Network: network}, nil
	}
	fleet := cfg.RPCFleet
	if fleet == nil {
		fleet = newRPCFleet(cfg.RPCURLs)
	}
	var lastErr error
	for _, handle := range fleet.sendCandidates(len(cfg.RPCURLs)) {
		start := time.Now()
		client, err := ethclient.DialContext(ctx, handle.url)
		if err != nil {
			fleet.recordFailure(handle.id, classifyRPCFailure(err))
			lastErr = fmt.Errorf("%s indisponivel: %w", handle.name, err)
			continue
		}
		resp, err := executeEVMContractCallWithClient(ctx, cfg, store, req, network, client, privateKey, from)
		client.Close()
		if err != nil {
			fleet.recordFailure(handle.id, classifyRPCFailure(err))
			lastErr = fmt.Errorf("%s falhou: %w", handle.name, err)
			continue
		}
		fleet.recordSuccess(handle.id, time.Since(start))
		return resp, nil
	}
	if lastErr == nil {
		lastErr = errors.New("nenhum RPC BSC disponivel")
	}
	return TransferResponse{}, lastErr
}

func executeEVMContractCallWithClient(ctx context.Context, cfg *SignerConfig, store signerStore, req ContractCallRequest, network string, client *ethclient.Client, privateKey *ecdsa.PrivateKey, from common.Address) (TransferResponse, error) {
	chainID, err := client.ChainID(ctx)
	if err != nil {
		return TransferResponse{}, fmt.Errorf("falha ao obter chain id: %w", err)
	}
	if network == "BSC" && chainID.Cmp(big.NewInt(56)) != 0 {
		return TransferResponse{}, fmt.Errorf("chain id inesperado para BSC: %s", chainID.String())
	}
	chainPending, err := client.PendingNonceAt(ctx, from)
	if err != nil {
		return TransferResponse{}, fmt.Errorf("falha ao obter nonce: %w", err)
	}
	nonce, err := store.ReserveChainNonce(ctx, from.Hex(), network, chainPending)
	if err != nil {
		return TransferResponse{}, fmt.Errorf("falha ao reservar nonce: %w", err)
	}
	_ = store.RecordCustodyEvent(ctx, CustodyEvent{Kind: "nonce_reserved", Mode: cfg.CustodyMode, Wallet: from.Hex(), Data: map[string]any{"nonce": nonce, "network": network, "type": "contract_call"}})
	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		return TransferResponse{}, fmt.Errorf("falha ao obter gas price: %w", err)
	}
	data, err := decodeHexData(req.Data)
	if err != nil {
		return TransferResponse{}, err
	}
	to := common.HexToAddress(req.To)
	gasLimit, err := client.EstimateGas(ctx, ethereum.CallMsg{From: from, To: &to, Data: data})
	if err != nil || gasLimit == 0 {
		gasLimit = 350000
	}
	tx := types.NewTransaction(nonce, to, big.NewInt(0), gasLimit, gasPrice, data)
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), privateKey)
	if err != nil {
		_ = store.MarkChainNonceFailed(ctx, from.Hex(), network, nonce, err.Error())
		return TransferResponse{}, fmt.Errorf("falha ao assinar tx: %w", err)
	}
	if err := client.SendTransaction(ctx, signed); err != nil {
		_ = store.MarkChainNonceFailed(ctx, from.Hex(), network, nonce, err.Error())
		_ = store.CreateSignerTransaction(ctx, SignerTransaction{
			IdempotencyKey: req.IdempotencyKey,
			WalletFrom:     from.Hex(),
			WalletTo:       req.To,
			Token:          strings.TrimSpace(req.TokenContract),
			Amount:         firstNonEmptySigner(req.Amount, "0"),
			Network:        network,
			Nonce:          nonce,
			TxHash:         signed.Hash().Hex(),
			Status:         "failed",
			Reason:         err.Error(),
		})
		return TransferResponse{}, fmt.Errorf("falha ao transmitir tx: %w", err)
	}
	_ = store.MarkChainNonceSubmitted(ctx, from.Hex(), network, nonce, signed.Hash().Hex())
	_ = store.CreateSignerTransaction(ctx, SignerTransaction{
		IdempotencyKey: req.IdempotencyKey,
		WalletFrom:     from.Hex(),
		WalletTo:       req.To,
		Token:          strings.TrimSpace(req.TokenContract),
		Amount:         firstNonEmptySigner(req.Amount, "0"),
		Network:        network,
		Nonce:          nonce,
		TxHash:         signed.Hash().Hex(),
		Status:         "submitted",
	})
	_ = store.RecordCustodyEvent(ctx, CustodyEvent{Kind: "tx_submitted", Mode: cfg.CustodyMode, TxHash: signed.Hash().Hex(), Wallet: from.Hex(), Data: map[string]any{"type": "contract_call"}})
	return TransferResponse{TxHash: signed.Hash().Hex(), From: from.Hex(), Network: network}, nil
}

func validateTreasuryPolicy(ctx context.Context, cfg *SignerConfig, store signerStore, req TransferRequest, network string) error {
	if store == nil {
		return nil
	}
	token := normalizedTokenContract(cfg, req, network)
	amount, err := parseFloatAmount(req.Amount)
	if err != nil {
		return err
	}
	outflow, err := store.DailySubmittedOutflow(ctx, token, network)
	if err != nil {
		return fmt.Errorf("falha ao consultar treasury outflow: %w", err)
	}
	next := outflow + amount
	if cfg.TreasuryLockThreshold > 0 && next > cfg.TreasuryLockThreshold {
		_ = store.RecordCustodyEvent(ctx, CustodyEvent{Kind: "treasury_lockdown_threshold", Reason: "limite de lockdown diario excedido", Mode: cfg.CustodyMode, Data: map[string]any{"nextOutflow": next}})
		return fmt.Errorf("treasury lockdown: saida diaria %.8f acima do limite %.8f", next, cfg.TreasuryLockThreshold)
	}
	if cfg.TreasuryMaxDailyOut > 0 && next > cfg.TreasuryMaxDailyOut {
		_ = store.RecordCustodyEvent(ctx, CustodyEvent{Kind: "treasury_daily_limit", Reason: "limite diario excedido", Mode: cfg.CustodyMode, Data: map[string]any{"nextOutflow": next}})
		return fmt.Errorf("limite diario de treasury excedido: %.8f > %.8f", next, cfg.TreasuryMaxDailyOut)
	}
	return nil
}

func validateContractCallTreasuryPolicy(ctx context.Context, cfg *SignerConfig, store signerStore, req ContractCallRequest, network string) error {
	if store == nil || strings.TrimSpace(req.Amount) == "" {
		return nil
	}
	amount, err := parseFloatAmount(req.Amount)
	if err != nil {
		return err
	}
	token := strings.TrimSpace(req.TokenContract)
	outflow, err := store.DailySubmittedOutflow(ctx, token, network)
	if err != nil {
		return fmt.Errorf("falha ao consultar treasury outflow: %w", err)
	}
	next := outflow + amount
	if cfg.TreasuryLockThreshold > 0 && next > cfg.TreasuryLockThreshold {
		_ = store.RecordCustodyEvent(ctx, CustodyEvent{Kind: "treasury_lockdown_threshold", Reason: "limite de lockdown diario excedido", Mode: cfg.CustodyMode, Data: map[string]any{"nextOutflow": next, "type": "contract_call"}})
		return fmt.Errorf("treasury lockdown: saida diaria %.8f acima do limite %.8f", next, cfg.TreasuryLockThreshold)
	}
	if cfg.TreasuryMaxDailyOut > 0 && next > cfg.TreasuryMaxDailyOut {
		_ = store.RecordCustodyEvent(ctx, CustodyEvent{Kind: "treasury_daily_limit", Reason: "limite diario excedido", Mode: cfg.CustodyMode, Data: map[string]any{"nextOutflow": next, "type": "contract_call"}})
		return fmt.Errorf("limite diario de treasury excedido: %.8f > %.8f", next, cfg.TreasuryMaxDailyOut)
	}
	return nil
}

func parseFloatAmount(value string) (float64, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, errors.New("amount invalido")
	}
	var out float64
	var err error
	out, err = strconv.ParseFloat(trimmed, 64)
	if err != nil {
		return 0, errors.New("amount invalido")
	}
	if out <= 0 {
		return 0, errors.New("amount invalido")
	}
	return out, nil
}

func startTxLifecycleMonitor(ctx context.Context, cfg *SignerConfig, store signerStore) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checkSignerTransactions(ctx, cfg, store)
		}
	}
}

func checkSignerTransactions(ctx context.Context, cfg *SignerConfig, store signerStore) {
	items, err := store.ListOpenSignerTransactions(ctx, 50)
	if err != nil {
		slog.Warn("falha ao listar txs abertas", "error", err)
		return
	}
	if len(items) == 0 {
		return
	}
	for _, url := range cfg.RPCURLs {
		client, err := ethclient.DialContext(ctx, url)
		if err != nil {
			continue
		}
		for _, item := range items {
			receipt, err := client.TransactionReceipt(ctx, common.HexToHash(item.TxHash))
			if err != nil || receipt == nil {
				continue
			}
			status := "confirmed"
			reason := ""
			if receipt.Status == types.ReceiptStatusFailed {
				status = "reverted"
				reason = "receipt status failed"
			}
			_ = store.MarkSignerTransactionStatus(ctx, item.TxHash, status, reason, 1)
			_ = store.RecordCustodyEvent(ctx, CustodyEvent{Kind: "tx_" + status, Mode: cfg.CustodyMode, TxHash: item.TxHash, Wallet: item.WalletFrom})
		}
		client.Close()
		return
	}
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

func settlementOperationID(chainID int64, vaultAddress, settlementIntentID, tokenAddress, recipientAddress string, amountRaw *big.Int) (common.Hash, error) {
	if chainID <= 0 {
		return common.Hash{}, errors.New("chainId invalido")
	}
	if !common.IsHexAddress(vaultAddress) {
		return common.Hash{}, errors.New("vault EVM invalido")
	}
	if !common.IsHexAddress(tokenAddress) {
		return common.Hash{}, errors.New("token EVM invalido")
	}
	if !common.IsHexAddress(recipientAddress) {
		return common.Hash{}, errors.New("recipient EVM invalido")
	}
	if amountRaw == nil || amountRaw.Sign() <= 0 {
		return common.Hash{}, errors.New("amountRaw invalido")
	}
	uint256Type, err := abi.NewType("uint256", "", nil)
	if err != nil {
		return common.Hash{}, err
	}
	addressType, err := abi.NewType("address", "", nil)
	if err != nil {
		return common.Hash{}, err
	}
	bytes32Type, err := abi.NewType("bytes32", "", nil)
	if err != nil {
		return common.Hash{}, err
	}
	args := abi.Arguments{
		{Type: uint256Type},
		{Type: addressType},
		{Type: bytes32Type},
		{Type: addressType},
		{Type: addressType},
		{Type: uint256Type},
	}
	encoded, err := args.Pack(
		new(big.Int).SetInt64(chainID),
		common.HexToAddress(vaultAddress),
		crypto.Keccak256Hash([]byte(settlementIntentID)),
		common.HexToAddress(tokenAddress),
		common.HexToAddress(recipientAddress),
		amountRaw,
	)
	if err != nil {
		return common.Hash{}, err
	}
	return crypto.Keccak256Hash(encoded), nil
}

func vaultPayoutData(operationID common.Hash, token, recipient common.Address, amount *big.Int) ([]byte, error) {
	bytes32Type, err := abi.NewType("bytes32", "", nil)
	if err != nil {
		return nil, err
	}
	addressType, err := abi.NewType("address", "", nil)
	if err != nil {
		return nil, err
	}
	uint256Type, err := abi.NewType("uint256", "", nil)
	if err != nil {
		return nil, err
	}
	args := abi.Arguments{
		{Type: bytes32Type},
		{Type: addressType},
		{Type: addressType},
		{Type: uint256Type},
	}
	encoded, err := args.Pack(operationID, token, recipient, amount)
	if err != nil {
		return nil, err
	}
	selector := crypto.Keccak256([]byte("payout(bytes32,address,address,uint256)"))[:4]
	data := make([]byte, 0, len(selector)+len(encoded))
	data = append(data, selector...)
	data = append(data, encoded...)
	return data, nil
}

func decodeHexData(value string) ([]byte, error) {
	trimmed := strings.TrimPrefix(strings.TrimSpace(value), "0x")
	if trimmed == "" || len(trimmed)%2 != 0 {
		return nil, errors.New("data hex invalido")
	}
	data, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, errors.New("data hex invalido")
	}
	return data, nil
}

func requestedContractNetwork(cfg *SignerConfig, req ContractCallRequest) string {
	return requestedNetwork(cfg, TransferRequest{Network: req.Network})
}

func firstNonEmptySigner(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func writeSignerJSON(w http.ResponseWriter, payload any) {
	writeJSONStatus(w, http.StatusOK, payload)
}

func writeJSONStatus(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func shortValue(value string) string {
	if len(value) <= 12 {
		return value
	}
	return value[:6] + "..." + value[len(value)-4:]
}
