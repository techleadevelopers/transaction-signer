package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

const tronAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func executeTronTransfer(ctx context.Context, cfg *SignerConfig, req TransferRequest) (TransferResponse, error) {
	privateKey, err := crypto.HexToECDSA(strings.TrimPrefix(cfg.TronPrivateKey, "0x"))
	if err != nil {
		return TransferResponse{}, fmt.Errorf("TRON_PRIVATE_KEY invalida: %w", err)
	}
	from := tronAddressFromPrivateKey(privateKey)
	token := normalizedTokenContract(cfg, req, "TRON")
	if cfg.AllowSimulation {
		hash := crypto.Keccak256Hash([]byte("TRON:" + req.IdempotencyKey + req.To + req.Amount)).Hex()
		return TransferResponse{TxHash: hash, From: from, Network: "TRON"}, nil
	}
	amount, err := parseUnits(req.Amount, cfg.TronTokenDecimals)
	if err != nil {
		return TransferResponse{}, err
	}
	ownerHex, err := tronAddressHex(from)
	if err != nil {
		return TransferResponse{}, err
	}
	contractHex, err := tronAddressHex(token)
	if err != nil {
		return TransferResponse{}, err
	}
	parameter, err := tronTRC20TransferParameter(req.To, amount)
	if err != nil {
		return TransferResponse{}, err
	}

	tx, txID, err := triggerTronContract(ctx, cfg, ownerHex, contractHex, parameter)
	if err != nil {
		return TransferResponse{}, err
	}
	hashBytes, err := hex.DecodeString(txID)
	if err != nil || len(hashBytes) != 32 {
		return TransferResponse{}, errors.New("txID TRON invalido")
	}
	signature, err := crypto.Sign(hashBytes, privateKey)
	if err != nil {
		return TransferResponse{}, fmt.Errorf("falha ao assinar TRON tx: %w", err)
	}
	tx["signature"] = []string{hex.EncodeToString(signature)}
	broadcastTxID, err := broadcastTronTransaction(ctx, cfg, tx, txID)
	if err != nil {
		return TransferResponse{}, err
	}
	return TransferResponse{TxHash: broadcastTxID, From: from, Network: "TRON"}, nil
}

func triggerTronContract(ctx context.Context, cfg *SignerConfig, ownerHex, contractHex, parameter string) (map[string]any, string, error) {
	payload := map[string]any{
		"owner_address":     ownerHex,
		"contract_address":  contractHex,
		"function_selector": "transfer(address,uint256)",
		"parameter":         parameter,
		"fee_limit":         cfg.TronFeeLimitSun,
		"call_value":        0,
		"visible":           false,
	}
	var out struct {
		Result struct {
			Result  bool   `json:"result"`
			Message string `json:"message"`
		} `json:"result"`
		Transaction map[string]any `json:"transaction"`
		TxID        string         `json:"txID"`
	}
	if err := tronPOST(ctx, cfg.TronFullNodeURL+"/wallet/triggersmartcontract", payload, &out); err != nil {
		return nil, "", err
	}
	if !out.Result.Result {
		msg := out.Result.Message
		if decoded, err := hex.DecodeString(msg); err == nil && len(decoded) > 0 {
			msg = string(decoded)
		}
		if msg == "" {
			msg = "triggerSmartContract rejeitado"
		}
		return nil, "", errors.New(msg)
	}
	if out.Transaction == nil || out.TxID == "" {
		return nil, "", errors.New("TRON node nao retornou transaction/txID")
	}
	return out.Transaction, out.TxID, nil
}

func broadcastTronTransaction(ctx context.Context, cfg *SignerConfig, tx map[string]any, fallbackTxID string) (string, error) {
	var out struct {
		Result  bool   `json:"result"`
		Code    string `json:"code"`
		Message string `json:"message"`
		TxID    string `json:"txid"`
	}
	if err := tronPOST(ctx, cfg.TronFullNodeURL+"/wallet/broadcasttransaction", tx, &out); err != nil {
		return "", err
	}
	if !out.Result {
		msg := out.Message
		if decoded, err := hex.DecodeString(msg); err == nil && len(decoded) > 0 {
			msg = string(decoded)
		}
		if msg == "" {
			msg = out.Code
		}
		return "", fmt.Errorf("broadcast TRON rejeitado: %s", msg)
	}
	if out.TxID != "" {
		return out.TxID, nil
	}
	return fallbackTxID, nil
}

func tronPOST(ctx context.Context, url string, payload any, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 20 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("TRON RPC indisponivel: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("TRON RPC status %d: %s", resp.StatusCode, string(raw))
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("TRON RPC JSON invalido: %w", err)
	}
	return nil
}

func tronTRC20TransferParameter(to string, amount *big.Int) (string, error) {
	addr, err := tronAddressBytes(to)
	if err != nil {
		return "", err
	}
	data := make([]byte, 64)
	copy(data[12:32], addr[1:])
	amountBytes := amount.Bytes()
	if len(amountBytes) > 32 {
		return "", errors.New("amount TRON excede 256 bits")
	}
	copy(data[64-len(amountBytes):], amountBytes)
	return hex.EncodeToString(data), nil
}

func isValidTronAddress(address string) bool {
	raw, err := tronAddressBytes(address)
	return err == nil && len(raw) == 21 && raw[0] == 0x41
}

func tronAddressHex(address string) (string, error) {
	raw, err := tronAddressBytes(address)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func tronAddressBytes(address string) ([]byte, error) {
	if strings.HasPrefix(strings.ToLower(address), "41") && len(address) == 42 {
		raw, err := hex.DecodeString(address)
		if err == nil && len(raw) == 21 && raw[0] == 0x41 {
			return raw, nil
		}
	}
	raw, err := base58CheckDecode(address)
	if err != nil {
		return nil, err
	}
	if len(raw) != 21 || raw[0] != 0x41 {
		return nil, errors.New("endereco TRON invalido")
	}
	return raw, nil
}

func tronAddressFromPrivateKey(privateKey *ecdsa.PrivateKey) string {
	pubBytes := crypto.FromECDSAPub(&privateKey.PublicKey)
	hash := crypto.Keccak256(pubBytes[1:])
	payload := append([]byte{0x41}, hash[12:]...)
	return base58CheckEncode(payload)
}

func base58CheckEncode(payload []byte) string {
	first := sha256.Sum256(payload)
	second := sha256.Sum256(first[:])
	return base58Encode(append(payload, second[:4]...))
}

func base58CheckDecode(value string) ([]byte, error) {
	raw, err := base58Decode(value)
	if err != nil {
		return nil, err
	}
	if len(raw) < 5 {
		return nil, errors.New("base58check curto")
	}
	payload := raw[:len(raw)-4]
	checksum := raw[len(raw)-4:]
	first := sha256.Sum256(payload)
	second := sha256.Sum256(first[:])
	if !bytes.Equal(checksum, second[:4]) {
		return nil, errors.New("checksum TRON invalido")
	}
	return payload, nil
}

func base58Encode(input []byte) string {
	x := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)
	var result []byte
	for x.Cmp(zero) > 0 {
		x.DivMod(x, base, mod)
		result = append(result, tronAlphabet[mod.Int64()])
	}
	for _, b := range input {
		if b != 0 {
			break
		}
		result = append(result, tronAlphabet[0])
	}
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return string(result)
}

func base58Decode(input string) ([]byte, error) {
	result := big.NewInt(0)
	base := big.NewInt(58)
	for _, r := range input {
		index := strings.IndexRune(tronAlphabet, r)
		if index < 0 {
			return nil, errors.New("base58 invalido")
		}
		result.Mul(result, base)
		result.Add(result, big.NewInt(int64(index)))
	}
	out := result.Bytes()
	for _, r := range input {
		if r != rune(tronAlphabet[0]) {
			break
		}
		out = append([]byte{0x00}, out...)
	}
	return out, nil
}
