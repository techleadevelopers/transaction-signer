package tests

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

// CreateOrderRequest espelha a estrutura da tabela hash @{} do anexo
type CreateOrderRequest struct {
	AmountBRL float64 `json:"amountBRL"`
	PixPhone  string  `json:"pixPhone"`
	PixCpf    string  `json:"pixCpf"`
}

// CreateOrderResponse espelha o retorno esperado da sua API principal
type CreateOrderResponse struct {
	ID        string  `json:"id"`
	Status    string  `json:"status"` // ex: "aguardando_deposito"
	Address   string  `json:"address"`
	AmountBRL float64 `json:"amountBRL"`
}

func TestAPI_CreateOrder_IdenticoAoAnexo(t *testing.T) {
	// Definições baseadas nos parâmetros do script PowerShell anexado
	backendURL := "http://localhost:3000" // Altere para a porta real da sua API Core em Go

	// 1. Monta o payload idêntico ao bloco do anexo:
	// amountBRL = [double]$AmountBRL, pixPhone = $PixPhone, pixCpf = $PixCpf
	bodyObj := CreateOrderRequest{
		AmountBRL: 150.00, // Equivalente ao $AmountBRL
		PixPhone:  "11999999999",
		PixCpf:    "12345678901",
	}

	rawBody, err := json.Marshal(bodyObj)
	if err != nil {
		t.Fatalf("Erro ao serializar JSON para a ordem: %v", err)
	}

	t.Logf("Efetuando POST %s/api/order", backendURL)

	// 2. Dispara a requisição HTTP POST identicamente ao Invoke-RestMethod
	req, err := http.NewRequest("POST", backendURL+"/api/order", bytes.NewBuffer(rawBody))
	if err != nil {
		t.Fatalf("Erro ao estruturar requisição HTTP: %v", err)
	}

	// Define os cabeçalhos padrão do anexo (-ContentType "application/json")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		// Se a API não estiver rodando no ambiente local (como em um CI parcial),
		// o teste avisa e pula em vez de quebrar a build de forma dura.
		t.Skip("A API Core principal não está rodando localmente. Pulando teste E2E.")
		return
	}
	defer resp.Body.Close()

	// 3. Captura e valida o resultado retornado pelo backend
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Erro ao ler corpo da resposta: %v", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		t.Errorf("A API rejeitou a criação da ordem! Status: %d, Erro: %s", resp.StatusCode, string(respBytes))
		return
	}

	// 4. Valida se o formato do JSON recebido possui estrutura financeira correta
	var orderResp CreateOrderResponse
	if err := json.Unmarshal(respBytes, &orderResp); err != nil {
		t.Fatalf("O backend respondeu um JSON inválido ou corrompido: %v", err)
	}

	// Garante que o status inicial da ordem é obrigatoriamente "aguardando_deposito" como manda a regra
	if orderResp.Status != "aguardando_deposito" {
		t.Errorf("A ordem foi criada com status incorreto! Esperado: 'aguardando_deposito', Recebido: '%s'", orderResp.Status)
	}

	t.Logf("Sucesso! Ordem criada ID: %s | Status: %s | Endereço Gerado: %s", orderResp.ID, orderResp.Status, orderResp.Address)
}
