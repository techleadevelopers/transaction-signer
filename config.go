package main

import (
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

type SignerConfig struct {
	AppEnv                string
	EVMPrivateKey         string
	TronPrivateKey        string
	RPCURL                string
	TronFullNodeURL       string
	TronUSDTContract      string
	TronFeeLimitSun       int64
	DefaultNetwork        string
	AllowedNetworks       map[string]bool
	AllowedTokenContracts map[string]bool
	MaxTransferAmount     float64
	DatabaseURL           string
	HMACSecret            string
	HMACMaxSkewSec        int
	TokenDecimals         int
	TronTokenDecimals     int
	AllowSimulation       bool
	Port                  string
}

func LoadSignerConfig() *SignerConfig {
	_ = godotenv.Load()

	return &SignerConfig{
		AppEnv:                strings.ToLower(getEnv("APP_ENV", getEnv("ENV", "development"))),
		EVMPrivateKey:         getEnv("EVM_PRIVATE_KEY", ""),
		TronPrivateKey:        getEnv("TRON_PRIVATE_KEY", getEnv("EVM_PRIVATE_KEY", "")),
		RPCURL:                getEnv("RPC_URL", "https://bsc-dataseed.binance.org/"),
		TronFullNodeURL:       strings.TrimRight(getEnv("TRON_FULLNODE_URL", "https://api.trongrid.io"), "/"),
		TronUSDTContract:      getEnv("TRON_USDT_CONTRACT", ""),
		TronFeeLimitSun:       int64(getEnvAsInt("TRON_FEE_LIMIT_SUN", 30_000_000)),
		DefaultNetwork:        strings.ToUpper(getEnv("SIGNER_NETWORK", "TRON")),
		AllowedNetworks:       parseSet(getEnv("SIGNER_ALLOWED_NETWORKS", "TRON,BSC,EVM")),
		AllowedTokenContracts: parseSet(getEnv("SIGNER_ALLOWED_TOKEN_CONTRACTS", "")),
		MaxTransferAmount:     getEnvAsFloat("SIGNER_MAX_TRANSFER_AMOUNT", 10000),
		DatabaseURL:           getEnv("SIGNER_DATABASE_URL", getEnv("DATABASE_URL", "")),
		HMACSecret:            getEnv("HMAC_SECRET", ""),
		HMACMaxSkewSec:        getEnvAsInt("HMAC_MAX_SKEW_SEC", 60),
		TokenDecimals:         getEnvAsInt("SIGNER_TOKEN_DECIMALS", 18),
		TronTokenDecimals:     getEnvAsInt("TRON_USDT_DECIMALS", 6),
		AllowSimulation:       getEnvAsBool("SIGNER_ALLOW_SIMULATION", false),
		Port:                  getEnv("PORT", "4010"),
	}
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
