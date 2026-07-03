//go:build integration

package tests

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/lib/pq" // Driver do PostgreSQL
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// SetupTestDatabase levanta um banco de dados PostgreSQL real dentro do Docker,
// aplica a estrutura de tabelas e retorna a conexão ativa junto com uma função de limpeza (Teardown).
func SetupTestDatabase(ctx context.Context) (*sql.DB, func(), error) {
	log.Println("[TEST SETUP] Iniciando container temporário do PostgreSQL via Testcontainers...")

	// 1. Configura a requisição do container PostgreSQL idêntico ao de produção
	req := testcontainers.ContainerRequest{
		Image:        "postgres:15-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "gateway_user",
			"POSTGRES_PASSWORD": "super_secret_test_password",
			"POSTGRES_DB":       "gateway_integration_tests",
		},
		// Garante que o container só será liberado para o teste quando o Postgres estiver pronto para aceitar conexões
		WaitingFor: wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(30 * time.Second),
	}

	postgresContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("falha ao iniciar o container do postgres: %w", err)
	}

	// 2. Descobre a porta dinâmica que o Docker mapeou na máquina host (evita conflitos de portas)
	hostIP, err := postgresContainer.Host(ctx)
	if err != nil {
		_ = postgresContainer.Terminate(ctx)
		return nil, nil, fmt.Errorf("falha ao obter host do container: %w", err)
	}

	mappedPort, err := postgresContainer.MappedPort(ctx, "5432")
	if err != nil {
		_ = postgresContainer.Terminate(ctx)
		return nil, nil, fmt.Errorf("falha ao obter porta mapeada: %w", err)
	}

	// 3. Monta a String de Conexão (DSN) real
	dsn := fmt.Sprintf("postgres://gateway_user:super_secret_test_password@%s:%s/gateway_integration_tests?sslmode=disable",
		hostIP, mappedPort.Port())

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		_ = postgresContainer.Terminate(ctx)
		return nil, nil, fmt.Errorf("falha ao abrir conexão com o banco de testes: %w", err)
	}

	// Garante que a conexão está operando
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		_ = postgresContainer.Terminate(ctx)
		return nil, nil, fmt.Errorf("falha ao pingar o banco de testes: %w", err)
	}

	// 4. Executa as Migrações / Criação de Tabelas
	// Em produção real, tu lerias os teus arquivos .sql da pasta de migrations.
	// Aqui aplicamos o DDL idêntico ao schema esperado do teu projeto:
	if err := runMigrations(ctx, db); err != nil {
		_ = db.Close()
		_ = postgresContainer.Terminate(ctx)
		return nil, nil, fmt.Errorf("falha ao rodar as migrações de teste: %w", err)
	}

	log.Println("[TEST SETUP] Banco de dados temporário inicializado e migrado com sucesso.")

	// 5. Retorna a função de Teardown Célula-Mãe. Quando o teste acabar, ele chama esta função
	// para fechar a pool de conexões e deletar o container do Docker sem deixar lixo na máquina.
	teardown := func() {
		log.Println("[TEST TEARDOWN] Fechando conexões e destruindo container de teste...")
		if db != nil {
			_ = db.Close()
		}
		if postgresContainer != nil {
			// Contexto curto para garantir o encerramento rápido no fim da pipeline
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = postgresContainer.Terminate(cleanupCtx)
		}
		log.Println("[TEST TEARDOWN] Infraestrutura destruída e limpa.")
	}

	return db, teardown, nil
}

// runMigrations injeta o DDL das tabelas financeiras necessárias para os teus Workers e API
func runMigrations(ctx context.Context, db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS orders (
		id VARCHAR(64) PRIMARY KEY,
		status VARCHAR(32) NOT NULL,
		amount_brl NUMERIC(18, 2) NOT NULL,
		address VARCHAR(128) NOT NULL,
		pix_phone VARCHAR(32),
		pix_cpf VARCHAR(14),
		created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS order_events (
		id SERIAL PRIMARY KEY,
		order_id VARCHAR(64) REFERENCES orders(id),
		event_type VARCHAR(64) NOT NULL,
		payload JSONB,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS sweeps (
		id VARCHAR(64) PRIMARY KEY,
		order_id VARCHAR(64) REFERENCES orders(id),
		status VARCHAR(32) NOT NULL,
		amount NUMERIC(36, 18) NOT NULL,
		tx_hash VARCHAR(128),
		child_index INT NOT NULL,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
	);
	`
	_, err := db.ExecContext(ctx, schema)
	return err
}
