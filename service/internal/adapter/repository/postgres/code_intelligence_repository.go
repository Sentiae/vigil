// Package postgres — pgx-backed repositories for the §11.2 code
// intelligence stack: code_embeddings, entry_points, module_semantics,
// scip_indexes. Each repository satisfies the in-package usecase port
// so the DI container can wire it without depending on usecase types.
package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	pgvector "github.com/pgvector/pgvector-go"

	"github.com/sentiae/vigil/service/internal/usecase"
)

// =============================================================================
// code_embeddings
// =============================================================================

type embeddingRepository struct{ pool *pgxpool.Pool }

// NewEmbeddingRepository wires the pgx-backed EmbeddingStore.
func NewEmbeddingRepository(pool *pgxpool.Pool) usecase.EmbeddingStore {
	return &embeddingRepository{pool: pool}
}

func (r *embeddingRepository) ExistingHashes(ctx context.Context, repoID uuid.UUID, hashes []string) (map[string]bool, error) {
	out := map[string]bool{}
	if len(hashes) == 0 {
		return out, nil
	}
	rows, err := r.pool.Query(ctx, `
		SELECT content_hash FROM code_embeddings
		WHERE repo_id = $1 AND content_hash = ANY($2)
	`, repoID, hashes)
	if err != nil {
		return nil, fmt.Errorf("existing-hashes: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out[h] = true
	}
	return out, rows.Err()
}

func (r *embeddingRepository) SaveBatch(ctx context.Context, chunks []usecase.EmbeddingChunk) error {
	if len(chunks) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, c := range chunks {
		// pgvector driver value is the canonical way to write into a
		// vector(N) column. The cast in the INSERT column list is the
		// belt-and-braces pattern recommended by pgvector-go docs so
		// the driver can still serialize over either the text or
		// binary protocol.
		batch.Queue(`
			INSERT INTO code_embeddings (
				id, tenant_id, repo_id, commit_sha, symbol_id, symbol_name,
				file_path, start_line, chunk_index, content_hash,
				content_preview, embedding, model_name
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
			ON CONFLICT DO NOTHING
		`, c.ID, c.TenantID, c.RepoID, c.CommitSHA, c.SymbolID, c.SymbolName,
			c.FilePath, c.StartLine, c.ChunkIndex, c.ContentHash,
			c.ContentPreview, pgvector.NewVector(c.Embedding), c.ModelName)
	}
	br := r.pool.SendBatch(ctx, batch)
	defer br.Close()
	for range chunks {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("insert embedding: %w", err)
		}
	}
	return nil
}

// Search delegates cosine-distance ranking to pgvector via the `<=>`
// operator + the IVFFlat index created in migration 004. Score is
// returned as (1 - distance) so 1.0 == exact match, matching the
// contract callers used under the Go-side fallback.
func (r *embeddingRepository) Search(ctx context.Context, repoID uuid.UUID, vec []float32, limit int) ([]usecase.EmbeddingSearchHit, error) {
	if limit <= 0 {
		limit = 20
	}
	qVec := pgvector.NewVector(vec)
	rows, err := r.pool.Query(ctx, `
		SELECT symbol_id, symbol_name, file_path, start_line,
		       chunk_index, content_preview,
		       1 - (embedding <=> $1) AS score
		FROM code_embeddings
		WHERE repo_id = $2
		ORDER BY embedding <=> $1
		LIMIT $3
	`, qVec, repoID, limit)
	if err != nil {
		return nil, fmt.Errorf("embedding search: %w", err)
	}
	defer rows.Close()

	out := make([]usecase.EmbeddingSearchHit, 0, limit)
	for rows.Next() {
		var hit usecase.EmbeddingSearchHit
		var score float64
		if err := rows.Scan(&hit.SymbolID, &hit.SymbolName, &hit.FilePath,
			&hit.StartLine, &hit.ChunkIndex, &hit.Preview, &score); err != nil {
			return nil, err
		}
		hit.Score = float32(score)
		out = append(out, hit)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// =============================================================================
// entry_points
// =============================================================================

// EntryPointRepository is the pgx-backed implementation of both the
// usecase.EntryPointStore (write side) and the http.EntryPointLister
// (read side). Exposed as a concrete type so the DI container can
// register the same instance in two roles without a wrapper.
type EntryPointRepository struct{ pool *pgxpool.Pool }

// NewEntryPointRepository wires the pgx-backed repository.
func NewEntryPointRepository(pool *pgxpool.Pool) *EntryPointRepository {
	return &EntryPointRepository{pool: pool}
}

// Save implements usecase.EntryPointStore.
func (r *EntryPointRepository) Save(ctx context.Context, tenantID, repoID uuid.UUID, eps []usecase.EntryPoint) error {
	if len(eps) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, ep := range eps {
		metaJSON, _ := json.Marshal(ep.Metadata)
		if string(metaJSON) == "null" {
			metaJSON = []byte("{}")
		}
		batch.Queue(`
			INSERT INTO entry_points (
				id, tenant_id, repo_id, kind, name, symbol_id,
				file_path, line_number, language, framework, metadata
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
			ON CONFLICT (repo_id, kind, file_path, line_number, name) DO UPDATE SET
				symbol_id = EXCLUDED.symbol_id,
				language  = EXCLUDED.language,
				framework = EXCLUDED.framework,
				metadata  = EXCLUDED.metadata,
				detected_at = NOW()
		`, ep.ID, tenantID, repoID, ep.Kind, ep.Name, ep.SymbolID,
			ep.FilePath, ep.LineNumber, ep.Language, ep.Framework, string(metaJSON))
	}
	br := r.pool.SendBatch(ctx, batch)
	defer br.Close()
	for range eps {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("insert entry_point: %w", err)
		}
	}
	return nil
}

// List implements the read port used by the HTTP handler.
// Filters by tenant + repo, with an optional kind filter.
func (r *EntryPointRepository) List(ctx context.Context, tenantID, repoID uuid.UUID, kind string) ([]usecase.EntryPoint, error) {
	q := `
		SELECT id, kind, name, symbol_id, file_path, line_number, language, framework, metadata
		FROM entry_points
		WHERE tenant_id = $1 AND repo_id = $2
	`
	args := []any{tenantID, repoID}
	if kind != "" {
		q += " AND kind = $3"
		args = append(args, kind)
	}
	q += " ORDER BY file_path, line_number"

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list entry_points: %w", err)
	}
	defer rows.Close()

	var out []usecase.EntryPoint
	for rows.Next() {
		var ep usecase.EntryPoint
		var metaRaw string
		if err := rows.Scan(&ep.ID, &ep.Kind, &ep.Name, &ep.SymbolID, &ep.FilePath, &ep.LineNumber, &ep.Language, &ep.Framework, &metaRaw); err != nil {
			return nil, err
		}
		if metaRaw != "" {
			_ = json.Unmarshal([]byte(metaRaw), &ep.Metadata)
		}
		out = append(out, ep)
	}
	return out, rows.Err()
}

// =============================================================================
// module_semantics
// =============================================================================

type semanticsRepository struct{ pool *pgxpool.Pool }

// NewSemanticsRepository wires the pgx-backed SemanticsStore.
func NewSemanticsRepository(pool *pgxpool.Pool) usecase.SemanticsStore {
	return &semanticsRepository{pool: pool}
}

func (r *semanticsRepository) ExistingHash(ctx context.Context, repoID uuid.UUID, moduleID string) (string, error) {
	var hash string
	err := r.pool.QueryRow(ctx, `
		SELECT module_hash FROM module_semantics WHERE repo_id = $1 AND module_id = $2
	`, repoID, moduleID).Scan(&hash)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return "", nil
		}
		return "", err
	}
	return hash, nil
}

func (r *semanticsRepository) Save(ctx context.Context, tenantID, repoID uuid.UUID, sem usecase.ModuleSemantics) error {
	respJSON, _ := json.Marshal(sem.Responsibilities)
	domJSON, _ := json.Marshal(sem.DomainConcepts)
	if string(respJSON) == "null" {
		respJSON = []byte("[]")
	}
	if string(domJSON) == "null" {
		domJSON = []byte("[]")
	}
	_, err := r.pool.Exec(ctx, `
		INSERT INTO module_semantics (
			id, tenant_id, repo_id, module_id, module_hash,
			purpose, responsibilities_json, domain_concepts_json,
			confidence, model_name
		) VALUES (gen_random_uuid(), $1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (repo_id, module_id) DO UPDATE SET
			module_hash           = EXCLUDED.module_hash,
			purpose               = EXCLUDED.purpose,
			responsibilities_json = EXCLUDED.responsibilities_json,
			domain_concepts_json  = EXCLUDED.domain_concepts_json,
			confidence            = EXCLUDED.confidence,
			model_name            = EXCLUDED.model_name,
			computed_at           = NOW()
	`, tenantID, repoID, sem.ModuleID, sem.ModuleHash,
		sem.Purpose, string(respJSON), string(domJSON),
		sem.Confidence, sem.ModelName)
	if err != nil {
		return fmt.Errorf("save module_semantics: %w", err)
	}
	return nil
}

// =============================================================================
// scip_indexes
// =============================================================================

// SCIPIndexRepository persists raw SCIP protobuf bytes keyed by
// (repo, commit, language) so the ingest worker can replay edges
// without re-invoking the CLI.
type SCIPIndexRepository struct{ pool *pgxpool.Pool }

// NewSCIPIndexRepository wires the pgx-backed index store.
func NewSCIPIndexRepository(pool *pgxpool.Pool) *SCIPIndexRepository {
	return &SCIPIndexRepository{pool: pool}
}

// Save upserts the SCIP index bytes for the (repo, commit, language) tuple.
func (r *SCIPIndexRepository) Save(ctx context.Context, tenantID, repoID uuid.UUID, commitSHA, language string, proto []byte) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO scip_indexes (id, tenant_id, repo_id, commit_sha, language, byte_size, raw_proto)
		VALUES (gen_random_uuid(), $1,$2,$3,$4,$5,$6)
		ON CONFLICT (repo_id, commit_sha, language) DO UPDATE SET
			byte_size = EXCLUDED.byte_size,
			raw_proto = EXCLUDED.raw_proto,
			created_at = NOW()
	`, tenantID, repoID, commitSHA, language, len(proto), proto)
	if err != nil {
		return fmt.Errorf("save scip_index: %w", err)
	}
	return nil
}

// Load returns the stored SCIP bytes for (repo, commit, language), or
// nil when no row exists.
func (r *SCIPIndexRepository) Load(ctx context.Context, repoID uuid.UUID, commitSHA, language string) ([]byte, error) {
	var body []byte
	err := r.pool.QueryRow(ctx, `
		SELECT raw_proto FROM scip_indexes
		WHERE repo_id = $1 AND commit_sha = $2 AND language = $3
	`, repoID, commitSHA, language).Scan(&body)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return nil, nil
		}
		return nil, err
	}
	return body, nil
}
