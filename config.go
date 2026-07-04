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
	RPCURL                string
	RPCURLs               []string
	RPCFleet              *rpcFleet
	BSCUSDTContract       string
	DefaultNetwork        string
	AllowedNetworks       map[string]bool
	AllowedTokenContracts map[string]bool
	MaxTransferAmount     float64
	DatabaseURL           string
	HMACSecret            string
	HMACMaxSkewSec        int
	TokenDecimals         int
	AllowSimulation       bool
	Port                  string
}

func LoadSignerConfig() *SignerConfig {
	_ = godotenv.Load()

	rpcURLs := parseRPCURLs()
	return &SignerConfig{
		AppEnv:                strings.ToLower(getEnv("APP_ENV", getEnv("ENV", "development"))),
		EVMPrivateKey:         getEnv("EVM_PRIVATE_KEY", ""),
		RPCURL:                getEnv("RPC_URL", "https://bsc-dataseed.binance.org/"),
		RPCURLs:               rpcURLs,
		RPCFleet:              newRPCFleet(rpcURLs),
		BSCUSDTContract:       getEnv("BSC_USDT_CONTRACT", getEnv("BSC_TOKEN_CONTRACT", "")),
		DefaultNetwork:        strings.ToUpper(getEnv("SIGNER_NETWORK", "BSC")),
		AllowedNetworks:       parseSet(getEnv("SIGNER_ALLOWED_NETWORKS", "BSC,EVM")),
		AllowedTokenContracts: parseSet(getEnv("SIGNER_ALLOWED_TOKEN_CONTRACTS", "")),
		MaxTransferAmount:     getEnvAsFloat("SIGNER_MAX_TRANSFER_AMOUNT", 10000),
		DatabaseURL:           getEnv("SIGNER_DATABASE_URL", getEnv("DATABASE_URL", "")),
		HMACSecret:            getEnv("HMAC_SECRET", ""),
		HMACMaxSkewSec:        getEnvAsInt("HMAC_MAX_SKEW_SEC", 60),
		TokenDecimals:         getEnvAsInt("SIGNER_TOKEN_DECIMALS", 18),
		AllowSimulation:       getEnvAsBool("SIGNER_ALLOW_SIMULATION", false),
		Port:                  getEnv("PORT", "4010"),
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
