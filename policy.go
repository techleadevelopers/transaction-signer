package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

const multicall3Aggregate3Selector = "82ad56cb"

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

func validateContractCallPolicy(cfg *SignerConfig, req ContractCallRequest, network string) error {
	if !cfg.AllowedNetworks[network] {
		return fmt.Errorf("rede nao permitida: %s", network)
	}
	if !common.IsHexAddress(req.To) {
		return errors.New("contrato EVM invalido")
	}
	to := strings.ToUpper(strings.TrimSpace(req.To))
	if len(cfg.AllowedContractCalls) > 0 && !cfg.AllowedContractCalls[to] {
		return errors.New("contract-call target nao permitido")
	}
	data := strings.TrimPrefix(strings.TrimSpace(req.Data), "0x")
	if len(data) < 8 {
		return errors.New("data hex invalido")
	}
	if strings.ToLower(data[:8]) != multicall3Aggregate3Selector {
		return errors.New("contract-call permitido apenas para Multicall3 aggregate3")
	}
	if strings.TrimSpace(req.Amount) != "" {
		amount, err := strconv.ParseFloat(strings.TrimSpace(req.Amount), 64)
		if err != nil || amount <= 0 {
			return errors.New("amount invalido")
		}
		if cfg.MaxTransferAmount > 0 && amount > cfg.MaxTransferAmount {
			return fmt.Errorf("amount acima do limite: %.8f > %.8f", amount, cfg.MaxTransferAmount)
		}
	}
	token := strings.TrimSpace(req.TokenContract)
	if len(cfg.AllowedTokenContracts) > 0 && token != "" && !cfg.AllowedTokenContracts[strings.ToUpper(token)] {
		return errors.New("token contract nao permitido")
	}
	if token != "" && !common.IsHexAddress(token) {
		return errors.New("token contract EVM invalido")
	}
	switch network {
	case "BSC", "EVM":
		return nil
	default:
		return fmt.Errorf("rede nao suportada: %s", network)
	}
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
	if (network == "BSC" || network == "EVM") && token == "" {
		token = cfg.BSCUSDTContract
	}
	return token
}
