//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/sentiae/vigil/service/internal/infrastructure/migrate"
)

// testPostgresImage carries pgvector, which 004_pgvector.sql needs; the stock
// postgres image would fail that migration.
const testPostgresImage = "pgvector/pgvector:pg16"

// requiredExtensions mirrors what infrastructure/docker/init-databases.sql
// creates in code_analysis_service before vigil boots: 001 assumes pg_trgm
// (the title trigram index) and the deployed database has all four.
var requiredExtensions = []string{"uuid-ossp", "pg_trgm", "pgcrypto", "vector"}

// startPostgres starts a throwaway Postgres container and returns a pool
// connected as its superuser — the same posture vigil runs under in
// production (a named D-490 exception), so RLS is bypassed exactly as there.
// It never consults TEST_POSTGRES_DSN and never skips: a container, connection
// or extension failure fails the test, because a skipped integration test
// asserts nothing and still reports ok.
func startPostgres(t *testing.T) *pgxpool.Pool {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ctr, err := tcpostgres.Run(ctx, testPostgresImage,
		tcpostgres.WithDatabase("code_analysis_service"),
		tcpostgres.WithUsername("postgres"),
		tcpostgres.WithPassword("postgres"),
		tcpostgres.BasicWaitStrategies(),
	)
	if ctr != nil {
		t.Cleanup(func() {
			if err := ctr.Terminate(context.Background()); err != nil {
				t.Logf("terminate postgres container: %v", err)
			}
		})
	}
	if err != nil {
		t.Fatalf("start postgres container %s: %v", testPostgresImage, err)
	}

	connStr, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("postgres connection string: %v", err)
	}

	pool, err := pgxpool.New(context.Background(), connStr)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)

	for _, ext := range requiredExtensions {
		if _, err := pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS "`+ext+`"`); err != nil {
			t.Fatalf("create extension %s: %v", ext, err)
		}
	}
	return pool
}

// newMigratedPool is startPostgres plus vigil's real boot-time migration
// runner over the embedded migrations — the exact code path production runs.
func newMigratedPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := startPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := migrate.Apply(ctx, pool); err != nil {
		t.Fatalf("apply embedded migrations: %v", err)
	}
	return pool
}
