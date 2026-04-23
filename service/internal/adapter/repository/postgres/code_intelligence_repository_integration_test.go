//go:build integration

package postgres

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	pgvector "github.com/pgvector/pgvector-go"

	"github.com/sentiae/vigil/service/internal/usecase"
)

// TestEmbeddingRepository_PgVectorSearch exercises the real pgvector
// path end-to-end: it runs the service's own migrations (003 + 004)
// against a throwaway test database, inserts three 1536-dimensional
// embeddings with one clearly closer to the query vector, and asserts
// that the top hit is the expected one.
//
// Skipped when the environment lacks Postgres + pgvector. In CI we rely
// on the compose-backed Postgres 16 image with the pgvector extension
// enabled via infrastructure/docker/init-databases.sql.
func TestEmbeddingRepository_PgVectorSearch(t *testing.T) {
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		dsn = "host=localhost port=5432 user=postgres password=postgres dbname=code_analysis_service_test sslmode=disable"
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Skipf("pgxpool.New failed (set TEST_POSTGRES_DSN for a reachable cluster): %v", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		t.Skipf("Postgres unreachable: %v", err)
	}

	// pgvector extension must exist for the 004 migration; attempt
	// creation and skip gracefully if the cluster lacks the lib.
	if _, err := pool.Exec(ctx, "CREATE EXTENSION IF NOT EXISTS vector"); err != nil {
		t.Skipf("pgvector extension not installable on this cluster: %v", err)
	}

	// Ensure we are on a clean schema for this test. The repo is pgx-
	// backed and does not own migrations, so we copy the SQL in directly.
	if _, err := pool.Exec(ctx, "DROP TABLE IF EXISTS code_embeddings CASCADE"); err != nil {
		t.Fatalf("drop table: %v", err)
	}
	if err := applyMigration(ctx, pool, findMigration(t, "003_code_intelligence.sql")); err != nil {
		t.Fatalf("apply 003: %v", err)
	}
	if err := applyMigration(ctx, pool, findMigration(t, "004_pgvector.sql")); err != nil {
		t.Fatalf("apply 004: %v", err)
	}

	repo := NewEmbeddingRepository(pool).(*embeddingRepository)
	tenantID, repoID := uuid.New(), uuid.New()

	// Three chunks: the first two are aligned; the third points in an
	// orthogonal direction. The query vector is aligned with the first,
	// so pgvector must return chunk A as the top hit.
	chunks := []usecase.EmbeddingChunk{
		{
			ID:          uuid.New(),
			TenantID:    tenantID,
			RepoID:      repoID,
			SymbolID:    "A",
			SymbolName:  "charge_customer",
			FilePath:    "billing.go",
			StartLine:   1,
			ChunkIndex:  0,
			ContentHash: "hash-A",
			Embedding:   unitVector(1536, 0),
			ModelName:   "test",
		},
		{
			ID:          uuid.New(),
			TenantID:    tenantID,
			RepoID:      repoID,
			SymbolID:    "B",
			SymbolName:  "charge_customer_alt",
			FilePath:    "billing_alt.go",
			StartLine:   2,
			ChunkIndex:  0,
			ContentHash: "hash-B",
			Embedding:   tiltedVector(1536, 0, 7, 0.4),
			ModelName:   "test",
		},
		{
			ID:          uuid.New(),
			TenantID:    tenantID,
			RepoID:      repoID,
			SymbolID:    "C",
			SymbolName:  "healthcheck",
			FilePath:    "health.go",
			StartLine:   3,
			ChunkIndex:  0,
			ContentHash: "hash-C",
			Embedding:   unitVector(1536, 500),
			ModelName:   "test",
		},
	}

	if err := repo.SaveBatch(ctx, chunks); err != nil {
		t.Fatalf("SaveBatch: %v", err)
	}

	// Sanity check: a direct pgvector distance query should see 3 rows.
	var count int
	if err := pool.QueryRow(ctx, "SELECT COUNT(*) FROM code_embeddings WHERE repo_id = $1", repoID).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected 3 rows, got %d", count)
	}

	// Query vector aligned with chunk A => A must rank first.
	hits, err := repo.Search(ctx, repoID, unitVector(1536, 0), 3)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(hits) != 3 {
		t.Fatalf("expected 3 hits, got %d", len(hits))
	}
	if hits[0].SymbolID != "A" {
		t.Fatalf("expected A at rank 0, got %q", hits[0].SymbolID)
	}
	if hits[2].SymbolID != "C" {
		t.Fatalf("expected C at rank 2, got %q", hits[2].SymbolID)
	}
	// A's score should be essentially 1.0 (cosine similarity with itself).
	if hits[0].Score < 0.999 {
		t.Errorf("A score = %v, want ~1.0", hits[0].Score)
	}
	// C is orthogonal to A, so its score should be ~0.
	if hits[2].Score > 0.05 {
		t.Errorf("C score = %v, want ~0", hits[2].Score)
	}

	// Verify the pgvector driver round-trips: fetch raw embedding and
	// confirm dimension. This guards against a silent dimension mismatch
	// that would make the IVFFlat index unusable.
	var raw pgvector.Vector
	if err := pool.QueryRow(ctx, "SELECT embedding FROM code_embeddings WHERE symbol_id = 'A' AND repo_id = $1", repoID).Scan(&raw); err != nil {
		t.Fatalf("scan embedding: %v", err)
	}
	if got := len(raw.Slice()); got != 1536 {
		t.Errorf("embedding dimension = %d, want 1536", got)
	}
}

// applyMigration runs the SQL from path against pool. Splits on top-
// level semicolons is not needed because pgx's Exec can handle the
// whole file when sent as a single simple query.
func applyMigration(ctx context.Context, pool *pgxpool.Pool, path string) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if _, err := pool.Exec(ctx, string(body)); err != nil {
		return fmt.Errorf("exec %s: %w", path, err)
	}
	return nil
}

// findMigration resolves the migrations directory relative to this
// test file so the test runs from any working directory (go test
// ./... changes CWD per-package).
func findMigration(t *testing.T, name string) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	// vigil-service/internal/adapter/repository/postgres/<this file>
	root := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..", "migrations", name)
	abs, err := filepath.Abs(root)
	if err != nil {
		t.Fatalf("abs migration path: %v", err)
	}
	return abs
}

// unitVector returns a 1536-dim unit vector with 1.0 at index idx.
func unitVector(dim, idx int) []float32 {
	v := make([]float32, dim)
	v[idx] = 1
	return v
}

// tiltedVector returns a normalized vector with weight on primary and
// secondary indices, so the angle with unitVector(primary) is small.
func tiltedVector(dim, primary, secondary int, secondaryWeight float32) []float32 {
	v := make([]float32, dim)
	v[primary] = 1
	v[secondary] = secondaryWeight
	// normalize
	var sq float32
	for _, x := range v {
		sq += x * x
	}
	norm := float32(1.0)
	if sq > 0 {
		norm = 1.0 / sqrt32(sq)
	}
	for i := range v {
		v[i] *= norm
	}
	return v
}

// sqrt32 avoids the math import inside test helpers.
func sqrt32(x float32) float32 {
	z := float32(1)
	for i := 0; i < 20; i++ {
		z -= (z*z - x) / (2 * z)
	}
	return z
}
