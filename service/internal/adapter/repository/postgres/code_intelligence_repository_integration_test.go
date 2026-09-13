//go:build integration

package postgres

import (
	"context"
	"testing"

	"github.com/google/uuid"
	pgvector "github.com/pgvector/pgvector-go"

	"github.com/sentiae/vigil/service/internal/usecase"
)

// TestEmbeddingRepository_PgVectorSearch exercises the real pgvector
// path end-to-end: a throwaway pgvector Postgres with vigil's own embedded
// migrations applied by the boot-time runner, three 1536-dimensional
// embeddings with one clearly closer to the query vector, and an assertion
// that the top hit is the expected one.
func TestEmbeddingRepository_PgVectorSearch(t *testing.T) {
	pool := newMigratedPool(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
