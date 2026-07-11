package main

import "payment-gateway/internal/security"

func ValidateHMACWrapper(secret string, maxSkew int, tsStr, nonce, hmacHeader string, body []byte) error {
	validator := security.NewHMACValidator(secret, int64(maxSkew))
	return validator.ValidateRawBodyHMAC(tsStr, nonce, hmacHeader, body)
}

func validateHMAC(secret string, maxSkew int64, tsStr, nonce, hmacHeader string, body []byte) error {
	validator := security.NewHMACValidator(secret, maxSkew)
	return validator.ValidateRawBodyHMAC(tsStr, nonce, hmacHeader, body)
}
