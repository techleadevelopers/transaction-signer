package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

// TestValidateHMAC_Sucesso garante que uma requisição legítima vinda do Core do Gateway
// seja aceita com sucesso pelo Signer.
func TestValidateHMAC_Sucesso(t *testing.T) {
	secret := "69ddb9dcc8bb00afa2406ca2b945fda01934c8310669f3486128ae020ed2088c" // Exemplo do seu .env
	maxSkew := int64(60)                                                         // Janela de 60 segundos

	// Captura o timestamp atualizado do sistema
	tsStr := fmt.Sprintf("%d", time.Now().Unix())
	nonce := "42a3f9e1b2c3d4e5"
	body := []byte(`{"to":"0x829829508824f81d939F8CFFdCac71dE47a808bE","amount":"150.50","tokenContract":"0xtoken1","idempotencyKey":"sweep-123"}`)

	// RECONSTRÓI O PAYLOAD EXATAMENTE IGUAL AO MONTAGEM DO CORE (ts.nonce.body)
	signatureRaw := fmt.Sprintf("%s.%s.%s", tsStr, nonce, string(body))

	// Calcula o HMAC-SHA256
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signatureRaw))
	validHmacHeader := hex.EncodeToString(mac.Sum(nil))

	// EXECUTA A VALIDAÇÃO DO SEU COFRE SIGNER
	err := validateHMAC(secret, maxSkew, tsStr, nonce, validHmacHeader, body)
	if err != nil {
		t.Fatalf("ERRO: Um payload válido e íntegro foi rejeitado pelo Signer: %v", err)
	}
}

// TestValidateHMAC_ReplayAttack garante que se um hacker interceptar uma transação antiga
// e tentar reenviar para o Signer assinar novamente, o validador bloqueie por causa do tempo expirado.
func TestValidateHMAC_ReplayAttack(t *testing.T) {
	secret := "69ddb9dcc8bb00afa2406ca2b945fda01934c8310669f3486128ae020ed2088c"
	maxSkew := int64(60)

	// SIMULA UM REPLAY: Cria um timestamp antigo (ex: 5 minutos atrás)
	antigoTS := fmt.Sprintf("%d", time.Now().Add(-5*time.Minute).Unix())
	nonce := "42a3f9e1b2c3d4e5"
	body := []byte(`{"to":"0x829829508824f81d939F8CFFdCac71dE47a808bE","amount":"150.50","tokenContract":"0xtoken1","idempotencyKey":"sweep-123"}`)

	// O hash bate perfeitamente com os dados enviados pelo hacker
	signatureRaw := fmt.Sprintf("%s.%s.%s", antigoTS, nonce, string(body))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signatureRaw))
	hackerHmacHeader := hex.EncodeToString(mac.Sum(nil))

	// EXECUTA A VALIDAÇÃO
	err := validateHMAC(secret, maxSkew, antigoTS, nonce, hackerHmacHeader, body)

	// O teste PASSARÁ se ele RETORNAR UM ERRO (Bloqueio correto)
	if err == nil {
		t.Fatal("FALHA CRÍTICA DE SEGURANÇA: O Signer aceitou uma requisição expirada (Janela Skew furada)")
	}
}

// TestValidateHMAC_PayloadAlterado garante que se alguém tentar alterar o endereço de destino (To)
// ou o valor (Amount) no meio do caminho, a assinatura quebre imediatamente.
func TestValidateHMAC_PayloadAlterado(t *testing.T) {
	secret := "69ddb9dcc8bb00afa2406ca2b945fda01934c8310669f3486128ae020ed2088c"
	maxSkew := int64(60)
	tsStr := fmt.Sprintf("%d", time.Now().Unix())
	nonce := "42a3f9e1b2c3d4e5"

	bodyOriginal := []byte(`{"to":"0x829829508824f81d939F8CFFdCac71dE47a808bE","amount":"10.00"}`)
	bodyAlteradoPeloHacker := []byte(`{"to":"0xHackerAddressAquiDestinoFalso","amount":"10.00"}`)

	// Assina o original
	signatureRaw := fmt.Sprintf("%s.%s.%s", tsStr, nonce, string(bodyOriginal))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signatureRaw))
	hmacOriginal := hex.EncodeToString(mac.Sum(nil))

	// Tenta validar injetando o body modificado do hacker mantendo o cabeçalho hmac original
	err := validateHMAC(secret, maxSkew, tsStr, nonce, hmacOriginal, bodyAlteradoPeloHacker)

	if err == nil {
		t.Fatal("FALHA CRÍTICA DE SEGURANÇA: O Signer aceitou dados adulterados no body")
	}
}
