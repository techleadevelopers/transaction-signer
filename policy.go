package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

func requestedNetwork(cfg *SignerConfig, req TransferRequest) string {
	network := strings.ToUpper(strings.TrimSpace(req.Network))
	if network == "" {
		network = cfg.DefaultNetwork
	}
	if network == "BINANCE" || network == "BEP20" {
		return "BSC"
	}
	if network == "ETHEREUM" {
		return "EVM"
	}
	return network
}

func validateTransferPolicy(cfg *SignerConfig, req TransferRequest, network string) error {
	if !cfg.AllowedNetworks[network] {
		return fmt.Errorf("rede nao permitida: %s", network)
	}
	amount, err := strconv.ParseFloat(strings.TrimSpace(req.Amount), 64)
	if err != nil || amount <= 0 {
		return errors.New("amount invalido")
	}
	if cfg.MaxTransferAmount > 0 && amount > cfg.MaxTransferAmount {
		return fmt.Errorf("amount acima do limite: %.8f > %.8f", amount, cfg.MaxTransferAmount)
	}
	token := normalizedTokenContract(cfg, req, network)
	if len(cfg.AllowedTokenContracts) > 0 && token != "" && !cfg.AllowedTokenContracts[strings.ToUpper(token)] {
		return errors.New("token contract nao permitido")
	}
	switch network {
	case "TRON":
		if !isValidTronAddress(req.To) {
			return errors.New("destinatario TRON invalido")
		}
		if token == "" {
			return errors.New("TRON_USDT_CONTRACT ou tokenContract obrigatorio")
		}
	case "BSC", "EVM":
		if !common.IsHexAddress(req.To) {
			return errors.New("destinatario EVM invalido")
		}
		if token != "" && !common.IsHexAddress(token) {
			return errors.New("token contract EVM invalido")
		}
	default:
		return fmt.Errorf("rede nao suportada: %s", network)
	}
	return nil
}

func normalizedTokenContract(cfg *SignerConfig, req TransferRequest, network string) string {
	token := strings.TrimSpace(req.TokenContract)
	if network == "TRON" && token == "" {
		token = cfg.TronUSDTContract
	}
	return token
}
