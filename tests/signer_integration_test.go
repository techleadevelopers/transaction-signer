package tests

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
)

// TransferRequestBody espelha o [ordered]@{} do teu script PowerShell anexado
type TransferRequestBody struct {
	DerivationIndex int    `json:"derivationIndex"`
	To              string `json:"to"`
	Amount          string `json:"amount"`
	TokenContract   string `json:"tokenContract"`
	IdempotencyKey  string `json:"idempotencyKey"`
}

func TestSigner_HDTransfer_IdenticoAoAnexo(t *testing.T) {
	// Configurações baseadas no teu .env e script de teste anexado
	signerURL := "http://localhost:4010" 
	signerHmacSecret := "69ddb9dcc8bb00afa2406ca2b945fda01934c8310669f3486128ae020ed2088c"

	// 1. Monta o Payload exatamente como o script do PowerShell
	bodyObj := TransferRequestBody{
		DerivationIndex: 0,
		To:              "0x829829508824f81d939F8CFFdCac71dE47a808bE",
		Amount:          "12.34",
		TokenContract:   "0xtoken1",
		IdempotencyKey:  "test-idempotency-123",
	}

	rawBody, err := json.Marshal(bodyObj)
	if err != nil {
		t.Fatalf("Erro ao serializar JSON: %v", err)
	}

	// 2. Gera o Unix Timestamp e o Nonce idênticos à lógica do anexo
	ts := fmt.Sprintf("%d", time.Now().Unix())
	nonce := "42a3f9e1b2c3d4e5" // Fixo para o teste ou gerado via UUID de 16 caracteres

	// 3. LOGICA CRÍTICA DO ANEXO: $prefix = "$ts.$nonce." + rawBody
	// No script: [System.Text.Encoding]::UTF8.GetBytes($prefix) + GetBytes($rawBody)
	var dataToSign bytes.Buffer
	dataToSign.WriteString(fmt.Sprintf("%s.%s.", ts, nonce))
	dataToSign.Write(rawBody)

	// 4. Calcula o HMAC-SHA256 idêntico ao "New-Object System.Security.Cryptography.HMACSHA256"
	keyBytes, err := hex.DecodeString(signerHmacSecret)
	if err != nil {
		// Se o teu segredo for string pura em vez de HEX, use: keyBytes := []byte(signerHmacSecret)
		keyBytes = []byte(signerHmacSecret)
	}
	
	mac := hmac.New(sha256.New, keyBytes)
	mac.Write(dataToSign.Bytes())
	sigHex := hex.EncodeToString(mac.Sum(nil))

	// 5. Dispara a requisição HTTP Real contra o bsc-signer em Go
	req, err := http.NewRequest("POST", signerURL+"/hd/transfer", bytes.NewBuffer(rawBody))
	if err != nil {
		t.Fatalf("Erro ao criar requisição: %v", err)
	}

	// Injeta os cabeçalhos exatos exigidos pelo validador do Signer
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-ts", ts)
	req.Header.Set("x-nonce", nonce)
	req.Header.Set("x-signer-hmac", sigHex)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Skip("Signer não está rodando localmente no momento. Pulando envio HTTP real.")
		return
	}
	defer resp.Body.Close()

	// 6. Valida a resposta do servidor
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("O Signer rejeitou a lógica idêntica ao anexo! Status: %d, Erro: %s", resp.StatusCode, string(respBody))
	} else {
		t.Logf("Sucesso! Resposta do Signer em Go: %s", string(respBody))
	}
}