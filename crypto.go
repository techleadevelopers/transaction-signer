package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

// ValidateHMAC intercepta a requisição e valida a assinatura anti-replay igual ao Node
func ValidateHMAC(secret string, maxSkew int, tsStr, nonce, hmacHeader string, body []byte) error {
	if secret == "" || hmacHeader == "" || tsStr == "" || nonce == "" {
		return fmt.Errorf("credenciais de assinatura ausentes")
	}

	// 1. Valida se o timestamp não expirou (Anti-Replay por tempo)
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return fmt.Errorf("timestamp inválido")
	}

	now := time.Now().Unix()
	diff := now - ts
	if diff < 0 {
		diff = -diff
	}
	if int(diff) > maxSkew {
		return fmt.Errorf("requisição expirada (timestamp skew detectado)")
	}

	// 2. Monta o payload de assinatura idêntico ao Buffer.concat do seu Node
	// Formato: ts + "." + nonce + "." + rawBody
	signatureRaw := fmt.Sprintf("%s.%s.%s", tsStr, nonce, string(body))

	// 3. Calcula o HMAC-SHA256 localmente
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signatureRaw))
	expectedMac := hex.EncodeToString(mac.Sum(nil))

	// 4. Compara de forma segura (evitando ataques de timing)
	if !hmac.Equal([]byte(hmacHeader), []byte(expectedMac)) {
		return fmt.Errorf("assinatura HMAC inválida")
	}

	return nil
}

func validateHMAC(secret string, maxSkew int64, tsStr, nonce, hmacHeader string, body []byte) error {
	return ValidateHMAC(secret, int(maxSkew), tsStr, nonce, hmacHeader, body)
}
