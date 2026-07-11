package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// SecurityConfig agrupa configurações de segurança
type SecurityConfig struct {
	// HMAC
	HMACSecret     string
	HMACMaxSkewSec int64
	HMACOldSecret  string // Para rotação de segredos

	// Nonce
	NonceTTLSeconds int64
	NonceStoreType  string // "memory" ou "redis"

	// Rate Limit
	RateLimitPerMin int
	RateLimitBurst  int
	RateLimiterType string // "token_bucket" ou "sliding_window"

	// Request
	MaxBodySizeMB int64
	RequireHMAC   bool
	RequireNonce  bool
	RequireAPIKey bool
}

// SignerConfig contém toda a configuração do signer
type SignerConfig struct {
	// ===== Configurações Gerais =====
	AppEnv                string
	Port                  string
	DatabaseURL           string
	AllowSimulation       bool
	DefaultNetwork        string
	AllowedNetworks       map[string]bool
	AllowedTokenContracts map[string]bool
	MaxTransferAmount     float64
	TokenDecimals         int

	// ===== Blockchain =====
	EVMPrivateKey   string
	RPCURL          string
	RPCURLs         []string
	RPCFleet        *rpcFleet
	BSCUSDTContract string

	// ===== Segurança =====
	Security SecurityConfig

	// ===== Custódia =====
	CustodyGuardEnabled   bool
	CustodyGuardPollMs    int
	CustodyMode           string
	CustodyUnlockCooldown int
	CustodyProtectedRaw   string
	CustodyTrustedRaw     string
	CustodySelectorsRaw   string

	// ===== Treasury =====
	TreasuryMinUSDT       float64
	TreasuryTargetUSDT    float64
	TreasuryMaxUSDT       float64
	TreasuryMaxDailyOut   float64
	TreasuryLockThreshold float64
}

func (c *SignerConfig) IsProduction() bool {
	env := strings.ToLower(strings.TrimSpace(c.AppEnv))
	return env == "production" || env == "prod"
}

func (c *SignerConfig) ValidateProduction() error {
	if !c.IsProduction() {
		return nil
	}

	if c.AllowSimulation {
		return fmt.Errorf("SIGNER_ALLOW_SIMULATION deve ser false em producao")
	}

	if strings.TrimSpace(c.DatabaseURL) == "" {
		return fmt.Errorf("SIGNER_DATABASE_URL ou DATABASE_URL obrigatorio em producao")
	}

	if len(c.AllowedTokenContracts) == 0 {
		return fmt.Errorf("SIGNER_ALLOWED_TOKEN_CONTRACTS deve fixar contratos permitidos em producao")
	}

	if len(strings.TrimSpace(c.Security.HMACSecret)) < 32 {
		return fmt.Errorf("HMAC_SECRET deve ter pelo menos 32 caracteres em producao")
	}

	if c.Security.RequireHMAC && c.Security.HMACSecret == "" {
		return fmt.Errorf("HMAC_SECRET obrigatorio quando RequireHMAC=true")
	}

	if c.Security.RequireNonce && c.Security.NonceTTLSeconds <= 0 {
		return fmt.Errorf("NONCE_TTL_SECONDS deve ser > 0 quando RequireNonce=true")
	}

	return nil
}

// LoadSignerConfig carrega todas as configurações do ambiente
func LoadSignerConfig() *SignerConfig {
	_ = godotenv.Load()

	rpcURLs := parseRPCURLs()

	return &SignerConfig{
		// ===== Gerais =====
		AppEnv:                strings.ToLower(getEnv("APP_ENV", getEnv("ENV", "development"))),
		Port:                  getEnv("PORT", "4010"),
		DatabaseURL:           getEnv("SIGNER_DATABASE_URL", getEnv("DATABASE_URL", "")),
		AllowSimulation:       getEnvAsBool("SIGNER_ALLOW_SIMULATION", false),
		DefaultNetwork:        strings.ToUpper(getEnv("SIGNER_NETWORK", "BSC")),
		AllowedNetworks:       parseSet(getEnv("SIGNER_ALLOWED_NETWORKS", "BSC,EVM")),
		AllowedTokenContracts: parseSet(getEnv("SIGNER_ALLOWED_TOKEN_CONTRACTS", "")),
		MaxTransferAmount:     getEnvAsFloat("SIGNER_MAX_TRANSFER_AMOUNT", 10000),
		TokenDecimals:         getEnvAsInt("SIGNER_TOKEN_DECIMALS", 18),

		// ===== Blockchain =====
		EVMPrivateKey:   getEnv("EVM_PRIVATE_KEY", ""),
		RPCURL:          getEnv("RPC_URL", "https://bsc-dataseed.binance.org/"),
		RPCURLs:         rpcURLs,
		RPCFleet:        newRPCFleet(rpcURLs),
		BSCUSDTContract: getEnv("BSC_USDT_CONTRACT", getEnv("BSC_TOKEN_CONTRACT", "")),

		// ===== Segurança =====
		Security: SecurityConfig{
			// HMAC
			HMACSecret:     firstNonEmptyEnv("HMAC_SECRET", "SIGNER_HMAC_SECRET"),
			HMACMaxSkewSec: getEnvAsInt64("HMAC_MAX_SKEW_SEC", 300),
			HMACOldSecret:  getEnv("HMAC_OLD_SECRET", ""), // Para rotação

			// Nonce
			NonceTTLSeconds: getEnvAsInt64("NONCE_TTL_SECONDS", 300), // 5 minutos
			NonceStoreType:  getEnv("NONCE_STORE_TYPE", "memory"),    // "memory" ou "redis"

			// Rate Limit
			RateLimitPerMin: getEnvAsInt("RATE_LIMIT_PER_MIN", 100),
			RateLimitBurst:  getEnvAsInt("RATE_LIMIT_BURST", 20),
			RateLimiterType: getEnv("RATE_LIMITER_TYPE", "token_bucket"),

			// Request
			MaxBodySizeMB: getEnvAsInt64("MAX_BODY_SIZE_MB", 1), // 1MB
			RequireHMAC:   getEnvAsBool("REQUIRE_HMAC", true),
			RequireNonce:  getEnvAsBool("REQUIRE_NONCE", true),
			RequireAPIKey: getEnvAsBool("REQUIRE_API_KEY", false),
		},

		// ===== Custódia =====
		CustodyGuardEnabled:   getEnvAsBool("CUSTODY_GUARD_ENABLED", false),
		CustodyGuardPollMs:    getEnvAsInt("CUSTODY_GUARD_POLL_MS", 1500),
		CustodyMode:           normalizeCustodyMode(getEnv("CUSTODY_MODE", "paper")),
		CustodyUnlockCooldown: getEnvAsInt("CUSTODY_UNLOCK_COOLDOWN_SEC", 900),
		CustodyProtectedRaw:   getEnv("CUSTODY_PROTECTED_WALLETS", ""),
		CustodyTrustedRaw:     getEnv("CUSTODY_TRUSTED_DELEGATES", ""),
		CustodySelectorsRaw:   getEnv("CUSTODY_ALLOWED_SELECTORS", ""),

		// ===== Treasury =====
		TreasuryMinUSDT:       getEnvAsFloat("TREASURY_MIN_USDT", 0),
		TreasuryTargetUSDT:    getEnvAsFloat("TREASURY_TARGET_USDT", 0),
		TreasuryMaxUSDT:       getEnvAsFloat("TREASURY_MAX_USDT", 0),
		TreasuryMaxDailyOut:   getEnvAsFloat("TREASURY_MAX_DAILY_OUTFLOW", 0),
		TreasuryLockThreshold: getEnvAsFloat("TREASURY_LOCKDOWN_THRESHOLD", 0),
	}
}

// ===== Helpers =====

func normalizeCustodyMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "shadow", "paper", "live":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "paper"
	}
}

func parseRPCURLs() []string {
	raw := firstNonEmptyEnv("BSC_RPC_URLS", "RPC_URLS", "RPC_URL")
	var urls []string
	for _, item := range strings.Split(raw, ",") {
		url := strings.TrimSpace(item)
		if url != "" {
			urls = append(urls, url)
		}
	}
	for _, key := range []string{"ALCHEMY_BSC_RPC_URL_1", "ALCHEMY_BSC_RPC_URL_2", "ALCHEMY_BSC_RPC_URL", "ALCHEMY_BSC_FALLBACK_RPC_URL"} {
		if url := strings.TrimSpace(getEnv(key, "")); url != "" {
			urls = append(urls, url)
		}
	}
	if len(urls) == 0 {
		urls = append(urls, "https://bsc-dataseed.binance.org/")
	}
	return urls
}

func firstNonEmptyEnv(keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(getEnv(key, "")); value != "" {
			return value
		}
	}
	return ""
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	valueStr := getEnv(key, "")
	if value, err := strconv.Atoi(valueStr); err == nil {
		return value
	}
	return defaultValue
}

func getEnvAsInt64(key string, defaultValue int64) int64 {
	valueStr := getEnv(key, "")
	if value, err := strconv.ParseInt(valueStr, 10, 64); err == nil {
		return value
	}
	return defaultValue
}

func getEnvAsFloat(key string, defaultValue float64) float64 {
	valueStr := getEnv(key, "")
	if value, err := strconv.ParseFloat(valueStr, 64); err == nil {
		return value
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return defaultValue
	}
	value, err := strconv.ParseBool(valueStr)
	if err != nil {
		return defaultValue
	}
	return value
}

func parseSet(raw string) map[string]bool {
	out := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		item := strings.ToUpper(strings.TrimSpace(part))
		if item != "" {
			out[item] = true
		}
	}
	return out
}

// ===== Métodos auxiliares para o Security =====

// GetNonceTTL retorna o TTL como time.Duration
func (c *SignerConfig) GetNonceTTL() time.Duration {
	if c.Security.NonceTTLSeconds <= 0 {
		return 5 * time.Minute
	}
	return time.Duration(c.Security.NonceTTLSeconds) * time.Second
}

// GetRateWindow retorna a janela de rate limit
func (c *SignerConfig) GetRateWindow() time.Duration {
	return time.Minute // Fixo em 1 minuto para "por minuto"
}

// GetRateLimit retorna o limite por janela
func (c *SignerConfig) GetRateLimit() int {
	if c.Security.RateLimitPerMin <= 0 {
		return 100
	}
	return c.Security.RateLimitPerMin
}

// GetMaxBodySize retorna o tamanho máximo do body em bytes
func (c *SignerConfig) GetMaxBodySize() int64 {
	if c.Security.MaxBodySizeMB <= 0 {
		return 1024 * 1024 // 1MB
	}
	return c.Security.MaxBodySizeMB * 1024 * 1024
}

// GetRateLimiterType retorna o tipo de rate limiter
func (c *SignerConfig) GetRateLimiterType() string {
	switch strings.ToLower(c.Security.RateLimiterType) {
	case "sliding_window", "sliding":
		return "sliding_window"
	default:
		return "token_bucket"
	}
}
