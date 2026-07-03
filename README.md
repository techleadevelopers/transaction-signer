# Deploy separado

Este servico pode subir como um segundo service no Railway usando:

- `signer/Dockerfile`
- `signer/railway.json`

No Railway, crie um service separado para o signer e aponte o Dockerfile para:

```text
signer/Dockerfile
```

Healthcheck:

```http
GET /healthz
```

Variaveis obrigatorias:

```env
PORT=4010
HMAC_SECRET=mesmo-valor-usado-no-core-como-SIGNER_HMAC_SECRET
EVM_PRIVATE_KEY=0x...
RPC_URL=https://...
SIGNER_TOKEN_DECIMALS=18
SIGNER_ALLOW_SIMULATION=false
```

Para staging sem envio real:

```env
SIGNER_ALLOW_SIMULATION=true
```

No service da API principal, configure:

```env
SIGNER_URL=https://url-privada-ou-publica-do-signer
SIGNER_HMAC_SECRET=mesmo-valor-do-HMAC_SECRET
```

Nota: o signer atual implementa assinatura EVM e modo de simulacao. Para producao TRON real, usar signer TRON dedicado ou manter `SIGNER_ALLOW_SIMULATION=true` apenas em staging.

# Swappy BSC/TRON Core Signer 🛡️
### Motor de Assinatura Criptográfica de Alta Performance e Isolamento de Chaves em Go

O `signer` é um microsserviço isolado de infraestrutura crítica (isolado do Core público da API) responsável unicamente por gerenciar chaves privadas, derivar carteiras e assinar transações on-chain (EVM/TRON) para liquidação de ordens de compra (*Buy/Send*) e varreduras automáticas de depósitos (*Sweeping*).

---

## 🚀 1. Visão Geral e Engenharia de Produção

Em sistemas financeiros de criptoativos, expor chaves privadas no mesmo processo que escuta rotas HTTP públicas é um risco inaceitável. O `signer` atua como um **Vault/Cofre de Aplicação**, rodando em uma sub-rede privada, totalmente inacessível pela internet externa. 

### O que mudou na migração para Go?
* **Gerenciamento de Memória Pura:** O Go não possui buffers de strings mutáveis expostos na mesma intensidade que o ecossistema V8/Node, reduzindo drasticamente riscos de *memory dumping* (vazamento de chaves privadas em logs de erro ou travamentos).
* **Concorrência Nativa e CPU-Bound:** A validação matemática de hashes HMAC e criptografia elíptica (ECDSA) consome muita CPU. No Node, isso competia com o Event Loop de I/O. Em Go, o escalonador distribui essas assinaturas entre múltiplos cores de CPU via Goroutines nativas.

---

## 🛠️ 2. Arquitetura Tecnológica e Stack

O ecossistema do Signer foi estruturado com as bibliotecas mais resilientes do ecossistema Go:

* **Runtime:** Go 1.21+ (otimizado para alocação efêmera de memória).
* **EVM Engine:** `github.com/ethereum/go-ethereum` (Geth oficial) para manipulação de transações BEP20/ERC20, RLP encoding e criptografia ECDSA.
* **Criptografia Simétrica:** Pacotes nativos `crypto/hmac` e `crypto/sha256`.
* **Database Driver:** `github.com/lib/pq` conectado a uma pool persistente e otimizada.
* **Otimização de Logs:** Estruturados em formato JSON nativo para auditorias financeiras e tracing de transações.

---

## 🔐 3. Blindagem Criptográfica: Os Porquês Matemáticos

O Signer implementa o padrão industrial de autenticação simétrica por payload para garantir integridade ponta a ponta e repelir vetores clássicos de ataque a gateways financeiros.

### A Equação do HMAC-SHA256
Cada requisição recebida pelo Signer deve conter no cabeçalho a assinatura digital calculada sobre a regra simétrica:

$$\text{Digest} = \text{HMAC-SHA256}\Big(\text{HMAC\_SECRET}, \; \text{Timestamp} \parallel \text{"."} \parallel \text{Nonce} \parallel \text{"."} \parallel \text{RawBody}\Big)$$

Onde $\parallel$ representa a concatenação exata de bytes.

### 🛡️ Defesa Contra Vetores de Ataque Real

1. **Ataques de Replay (Janela Skew Temporal):**
   * **O Risco:** Um invasor intercepta uma requisição legítima de transferência de fundos e a reenvia repetidamente para o Signer esvaziar a carteira.
   * **A Solução:** O Signer extrai o cabeçalho `x-ts` (Unix Timestamp) e executa a verificação matemática de delta temporal: 
     $$| \text{Tempo\_Atual} - \text{x-ts} | > \text{HMAC\_MAX\_SKEW\_SEC}$$
     Se a diferença for superior a $60$ segundos (configurável), a requisição é descartada instantaneamente antes mesmo de validar o hash, mitigando ataques baseados em pacotes antigos.

2. **Ataques de Força Bruta ou Replay no mesmo minuto (Nonce Check):**
   * **O Risco:** Reenviar a transação interceptada exatamente 2 segundos após a original, driblando o bloqueio de tempo.
   * **A Solução:** O cabeçalho `x-nonce` (uma string aleatória única gerada pelo Core de no mínimo 16 caracteres) é persistido temporariamente no banco de dados com uma constraint de unicidade (`UNIQUE`). Se o mesmo `nonce` entrar duas vezes na janela válida de tempo, o banco de dados causa um *abort* na transação HTTP.

3. **Ataques de Adulteração de Payload (Tampering):**
   * **O Risco:** O atacante altera o campo `"to"` (endereço de destino) ou o `"amount"` de uma transação interceptada no meio da rede interna.
   * **A Solução:** Como o corpo bruto da mensagem (`RawBody`) faz parte do cálculo do HMAC, qualquer alteração em um único bit do JSON quebrará a igualdade matemática do Hash calculado pelo Signer, invalidando o pedido.

---

## 🔄 4. Fluxo e Idempotência de Liquidação Financeira

O Signer gerencia dois modos críticos de operação financeira:

1. **Dual Mode Executivo:**
   * **`/sign/hd/transfer` (Modo Varredura/Sweeping):** Deriva carteiras determinísticas baseadas na chave mestra privada (`m/44'/195'/0'/0/{index}`) para recolher os USDTs depositados pelos usuários em seus endereços temporários de depósito e transferi-los para a conta central da tesouraria.
   * **`/sign/transfer` (Modo Compra/Payout):** Utiliza uma Hot Wallet principal fixa com fundos dedicados para enviar os ativos diretamente para a carteira de destino do cliente que realizou uma ordem de compra (*Buy*).

### Mecanismo de Idempotência Célula-Mãe

Para garantir que instabilidades de rede na comunicação entre o Core e o Signer não provoquem um **duplo envio de criptoativos** para a blockchain (causando falência ou quebra de balanço), implementamos uma tabela de idempotência transacional no Postgres:

```sql
CREATE TABLE IF NOT EXISTS signer_idempotency (
    idempotency_key VARCHAR(128) PRIMARY KEY,
    tx_hash VARCHAR(128) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
