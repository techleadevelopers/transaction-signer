package main

import (
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type SignerConfig struct {
	EVMPrivateKey   string
	RPCURL          string
	HMACSecret      string
	HMACMaxSkewSec  int
	TokenDecimals   int
	AllowSimulation bool
	Port            string
}

func LoadSignerConfig() *SignerConfig {
	// Carrega um .env específico se existir na pasta do signer
	_ = godotenv.Load()

	return &SignerConfig{
		EVMPrivateKey:   getEnv("EVM_PRIVATE_KEY", ""),
		RPCURL:          getEnv("RPC_URL", "https://bsc-dataseed.binance.org/"),
		HMACSecret:      getEnv("HMAC_SECRET", ""),
		HMACMaxSkewSec:  getEnvAsInt("HMAC_MAX_SKEW_SEC", 60),
		TokenDecimals:   getEnvAsInt("SIGNER_TOKEN_DECIMALS", 18),
		AllowSimulation: getEnvAsBool("SIGNER_ALLOW_SIMULATION", false),
		Port:            getEnv("PORT", "4010"),
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
