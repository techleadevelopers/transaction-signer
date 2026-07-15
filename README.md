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
GET /readyz
```

Variaveis obrigatorias:

```env
PORT_SIGNER=4010
APP_ENV=production
HMAC_SECRET=mesmo-valor-usado-no-core-como-SIGNER_HMAC_SECRET
SIGNER_DATABASE_URL=postgres://...
SIGNER_NETWORK=BSC
SIGNER_ALLOWED_NETWORKS=BSC,BSC
SIGNER_ALLOWED_TOKEN_CONTRACTS=0x55d398326f99059fF775485246999027B3197955,0x55d398326f99059fF775485246999027B3197955
SIGNER_MAX_TRANSFER_AMOUNT=10000
BSC_PRIVATE_KEY=0x...
BSC_FULLNODE_URL=https://api.BSCgrid.io
BSC_USDT_CONTRACT=0x55d398326f99059fF775485246999027B3197955
BSC_USDT_DECIMALS=6
EVM_PRIVATE_KEY=0x...
RPC_URL=https://...
SIGNER_TOKEN_DECIMALS=18
SIGNER_ALLOW_SIMULATION=false
```

Custody guard opcional para EIP-7702:

```env
CUSTODY_GUARD_ENABLED=true
CUSTODY_GUARD_POLL_MS=1500
CUSTODY_MODE=paper
CUSTODY_UNLOCK_COOLDOWN_SEC=900
CUSTODY_TRUSTED_DELEGATES=
CUSTODY_ALLOWED_SELECTORS=
CUSTODY_PROTECTED_WALLETS=
TREASURY_MIN_USDT=0
TREASURY_TARGET_USDT=0
TREASURY_MAX_USDT=0
TREASURY_MAX_DAILY_OUTFLOW=0
TREASURY_LOCKDOWN_THRESHOLD=0
```

Quando ligado, o signer monitora transacoes EIP-7702 (`SET_CODE`, type `0x04`) em `pending` e `latest`. A hot wallet derivada de `EVM_PRIVATE_KEY` e as wallets em `CUSTODY_PROTECTED_WALLETS` entram na lista protegida. Se uma autorizacao 7702 apontar uma wallet protegida para delegate fora de `CUSTODY_TRUSTED_DELEGATES`, ou se o bytecode de um delegate confiavel mudar, o signer registra evento de custodia.

Modos de custodia:

- `CUSTODY_MODE=shadow`: registra evento, mas nao trava transferencia.
- `CUSTODY_MODE=paper`: registra incidente persistente e bloqueia `/hd/transfer`.
- `CUSTODY_MODE=live`: mesmo comportamento de bloqueio; reservado para futuras acoes automaticas de resposta.

O destrave operacional usa `POST /custody/unlock` com o mesmo HMAC do signer (`x-ts`, `x-nonce`, `x-signer-hmac`) e respeita `CUSTODY_UNLOCK_COOLDOWN_SEC`. O incidente fica persistido no Postgres para sobreviver a restart.

O signer tambem persiste:

- `custody_events`: eventos de seguranca e auditoria.
- `custody_incidents`: incidente ativo/resolvido.
- `signer_chain_nonces`: reserva atomica de nonce por wallet/rede.
- `signer_transactions`: lifecycle da transacao enviada (`submitted`, `confirmed`, `reverted`, `failed`).

`TREASURY_MAX_DAILY_OUTFLOW` e `TREASURY_LOCKDOWN_THRESHOLD` bloqueiam novas assinaturas quando a saida diaria ultrapassa o limite configurado. `TREASURY_MIN_USDT`, `TREASURY_TARGET_USDT` e `TREASURY_MAX_USDT` aparecem no `/readyz` como politica operacional de caixa.

Para staging sem envio real:

```env
SIGNER_ALLOW_SIMULATION=true
```

No service da API principal, configure:

```env
SIGNER_URL=http://signer.railway.internal:4010
SIGNER_HMAC_SECRET=mesmo-valor-do-HMAC_SECRET
```

## Relação com Gas Station / Paymaster

O Paymaster/Gas Station roda no core (`internal/paymaster`) e orquestra quote, relay, idempotencia, retry, batching e DLQ. Ele **nao guarda chave privada**.

Responsabilidades separadas:

| Camada | Responsabilidade |
| --- | --- |
| `internal/paymaster` | quote de gas, `sig_hash`, relay request, batching, retry/DLQ e persistencia em `gas_relay_requests` |
| `internal/rpc` | pool RPC e health checks usados por oracle/estimator/AutoSweeper |
| `signer` | assinatura isolada, HMAC interno, nonce atomico, custody guard e broadcast |
| `auto_sweeper_runs` | auditoria de sweeps/idempotencia operacional |

O fluxo de relay deve sempre passar por API core -> signer privado. Nunca exponha o signer diretamente como endpoint publico de Gas Station.

Teste de carga recomendado no core:

```bash
k6 run tests/paymaster_stress.js -e BASE_URL=https://api.chainfx.store -e API_KEY_LIVE=sk_live_... -e API_KEY_TEST=sk_test_...
```

Em producao, a API principal deve chamar o signer pela rede privada do Railway. Nao use `https://...up.railway.app` em `SIGNER_URL`; esse dominio e publico e a API bloqueia o boot por seguranca. Se o service do signer tiver outro nome no Railway, troque `signer` pelo nome real do service:

```env
SIGNER_URL=http://NOME_DO_SERVICE.railway.internal:4010
```

Use `PORT_SIGNER=4010` no service do signer para nao confundir com `PORT=8080` da API/gateway. O signer ainda aceita `PORT` como fallback por compatibilidade.

Nota: o signer atual assina BSC/BEP20 e BSC/EVM no endpoint `POST /hd/transfer`, com `network` no payload. O campo `derivationIndex` fica bloqueado por padrão na hot wallet; sweep HD deve usar signer dedicado e política própria.

# ChainFX BSC/BSC Core Signer 🛡️
### Motor de Assinatura Criptográfica de Alta Performance e Isolamento de Chaves em Go

O `signer` é um microsserviço isolado de infraestrutura crítica (isolado do Core público da API) responsável unicamente por gerenciar chaves privadas, derivar carteiras e assinar transações on-chain (EVM/BSC) para liquidação de ordens de compra (*Buy/Send*) e varreduras automáticas de depósitos (*Sweeping*).

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
