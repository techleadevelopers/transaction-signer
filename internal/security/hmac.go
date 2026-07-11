package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

type HMACValidator struct {
	activeSecret string
	oldSecret    string
	maxSkew      int64
}

func NewHMACValidator(activeSecret string, maxSkew int64) *HMACValidator {
	return &HMACValidator{
		activeSecret: activeSecret,
		maxSkew:      maxSkew,
	}
}

func (h *HMACValidator) SetOldSecret(oldSecret string) {
	h.oldSecret = oldSecret
}

func (h *HMACValidator) RotateSecret(newSecret string) {
	h.oldSecret = h.activeSecret
	h.activeSecret = newSecret
}

func (h *HMACValidator) ValidateHMAC(tsStr, nonce, hmacHeader string, body []byte) error {
	if err := h.validateTimestampInputs(tsStr, nonce, hmacHeader); err != nil {
		return err
	}
	bodyHash := sha256.Sum256(body)
	bodyHashHex := hex.EncodeToString(bodyHash[:])
	if h.validateWithSecret(h.activeSecret, tsStr, nonce, bodyHashHex, hmacHeader) {
		return nil
	}
	if h.oldSecret != "" && h.validateWithSecret(h.oldSecret, tsStr, nonce, bodyHashHex, hmacHeader) {
		return nil
	}
	return fmt.Errorf("assinatura HMAC invalida")
}

func (h *HMACValidator) ValidateRawBodyHMAC(tsStr, nonce, hmacHeader string, body []byte) error {
	if err := h.validateTimestampInputs(tsStr, nonce, hmacHeader); err != nil {
		return err
	}
	if h.validateRawWithSecret(h.activeSecret, tsStr, nonce, body, hmacHeader) {
		return nil
	}
	if h.oldSecret != "" && h.validateRawWithSecret(h.oldSecret, tsStr, nonce, body, hmacHeader) {
		return nil
	}
	return fmt.Errorf("assinatura HMAC invalida")
}

func (h *HMACValidator) validateTimestampInputs(tsStr, nonce, hmacHeader string) error {
	if h.activeSecret == "" || hmacHeader == "" || tsStr == "" || nonce == "" {
		return fmt.Errorf("credenciais de assinatura ausentes")
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return fmt.Errorf("timestamp invalido: %w", err)
	}
	now := time.Now().Unix()
	diff := now - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > h.maxSkew {
		return fmt.Errorf("requisicao expirada (timestamp skew: %d segundos)", diff)
	}
	return nil
}

func (h *HMACValidator) validateWithSecret(secret, tsStr, nonce, bodyHashHex, hmacHeader string) bool {
	signatureRaw := fmt.Sprintf("%s.%s.%s", tsStr, nonce, bodyHashHex)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signatureRaw))
	expectedMac := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(hmacHeader), []byte(expectedMac))
}

func (h *HMACValidator) validateRawWithSecret(secret, tsStr, nonce string, body []byte, hmacHeader string) bool {
	signatureRaw := fmt.Sprintf("%s.%s.%s", tsStr, nonce, string(body))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signatureRaw))
	expectedMac := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(hmacHeader), []byte(expectedMac))
}

func GenerateHMAC(secret, tsStr, nonce string, body []byte) string {
	bodyHash := sha256.Sum256(body)
	bodyHashHex := hex.EncodeToString(bodyHash[:])
	signatureRaw := fmt.Sprintf("%s.%s.%s", tsStr, nonce, bodyHashHex)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signatureRaw))
	return hex.EncodeToString(mac.Sum(nil))
}

func CanonicalRequest(method, path string, body []byte) string {
	bodyHash := sha256.Sum256(body)
	return fmt.Sprintf("%s %s %s", method, path, hex.EncodeToString(bodyHash[:]))
}

func GenerateRawBodyHMAC(secret, tsStr, nonce string, body []byte) string {
	signatureRaw := fmt.Sprintf("%s.%s.%s", tsStr, nonce, string(body))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signatureRaw))
	return hex.EncodeToString(mac.Sum(nil))
}

func SignRawBodyHeaders(req *http.Request, secret string, body []byte) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := GenerateNonce()
	req.Header.Set("x-ts", ts)
	req.Header.Set("x-nonce", nonce)
	req.Header.Set("x-signer-hmac", GenerateRawBodyHMAC(secret, ts, nonce, body))
}
