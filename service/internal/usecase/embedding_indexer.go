// Package usecase — Code embedding indexer (§11.2).
//
// For every symbol surfaced by the tree-sitter / SCIP pipeline we
// compute an embedding over the symbol's source so consumers can run
// semantic search ("the place that validates subscription seats") or
// find-like ranking without reading every file.
//
// Pipeline:
//
//  1. List symbols for a (repo, commit).
//  2. Load each symbol's source, split into <= 2k-token chunks.
//  3. Compute a content_hash per chunk; skip chunks already persisted.
//  4. Call foundry-service /embed in batches of 100 texts.
//  5. Persist rows to code_embeddings.
//
// Storage: pgvector powers the similarity search path. Migration
// 004_pgvector.sql ALTERs the embedding column to vector(1536) and
// adds an IVFFlat index on cosine distance, so the production query
// path (see postgres/code_intelligence_repository.go::Search) does
// `ORDER BY embedding <=> $1`. The Go-side CosineSimilarity helper
// below is retained only as a unit-test shim for the in-memory fake
// store — it is never reached when the pgx pool is wired in.
package usecase

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/google/uuid"
)

// SymbolSource describes a symbol the embedder should index. Callers
// supply these from the tree-sitter / SCIP output so this usecase stays
// free of git-service HTTP client wiring.
type SymbolSource struct {
	SymbolID   string
	SymbolName string
	FilePath   string
	StartLine  int
	Language   string
	Content    string // raw source snippet the embedder should encode
}

// EmbeddingChunk is a single persisted embedding row.
type EmbeddingChunk struct {
	ID             uuid.UUID `json:"id"`
	TenantID       uuid.UUID `json:"tenant_id"`
	RepoID         uuid.UUID `json:"repo_id"`
	CommitSHA      string    `json:"commit_sha,omitempty"`
	SymbolID       string    `json:"symbol_id"`
	SymbolName     string    `json:"symbol_name,omitempty"`
	FilePath       string    `json:"file_path"`
	StartLine      int       `json:"start_line"`
	ChunkIndex     int       `json:"chunk_index"`
	ContentHash    string    `json:"content_hash"`
	ContentPreview string    `json:"content_preview"`
	Embedding      []float32 `json:"embedding"`
	ModelName      string    `json:"model_name,omitempty"`
}

// SymbolSourceLister returns the indexable symbols for a repo+commit.
type SymbolSourceLister interface {
	ListSymbols(ctx context.Context, repoID uuid.UUID, commitSHA string) ([]SymbolSource, error)
}

// Embedder returns embedding vectors for the given texts. Mirrors
// foundry.Client's Embed shape so callers can inject the real client
// or a fake in tests.
type Embedder interface {
	Embed(ctx context.Context, texts []string) ([][]float32, error)
}

// EmbeddingStore persists + queries chunks.
type EmbeddingStore interface {
	ExistingHashes(ctx context.Context, repoID uuid.UUID, hashes []string) (map[string]bool, error)
	SaveBatch(ctx context.Context, chunks []EmbeddingChunk) error
	Search(ctx context.Context, repoID uuid.UUID, vec []float32, limit int) ([]EmbeddingSearchHit, error)
}

// EmbeddingSearchHit is the shape returned by the search HTTP endpoint.
type EmbeddingSearchHit struct {
	SymbolID   string  `json:"symbol_id"`
	SymbolName string  `json:"symbol_name"`
	FilePath   string  `json:"file_path"`
	StartLine  int     `json:"start_line"`
	ChunkIndex int     `json:"chunk_index"`
	Preview    string  `json:"preview"`
	Score      float32 `json:"score"`
}

// EmbeddingIndexer orchestrates chunking, embedding, and persistence.
type EmbeddingIndexer struct {
	lister     SymbolSourceLister
	embedder   Embedder
	store      EmbeddingStore
	modelName  string
	batchSize  int
	maxChunkCh int // characters (~4 chars/token); 2k tokens ≈ 8k chars
}

// NewEmbeddingIndexer constructs the indexer. All three deps are required.
func NewEmbeddingIndexer(lister SymbolSourceLister, embedder Embedder, store EmbeddingStore) *EmbeddingIndexer {
	return &EmbeddingIndexer{
		lister:     lister,
		embedder:   embedder,
		store:      store,
		modelName:  "foundry-default",
		batchSize:  100,
		maxChunkCh: 8 * 1024,
	}
}

// IndexRepository walks symbols + persists embeddings. Idempotent:
// chunks whose content_hash already exists are skipped.
func (i *EmbeddingIndexer) IndexRepository(ctx context.Context, tenantID, repoID uuid.UUID, commitSHA string) error {
	if i.lister == nil || i.embedder == nil || i.store == nil {
		return fmt.Errorf("embedding indexer: missing dependency")
	}

	symbols, err := i.lister.ListSymbols(ctx, repoID, commitSHA)
	if err != nil {
		return fmt.Errorf("list symbols: %w", err)
	}
	if len(symbols) == 0 {
		return nil
	}

	// Build the full set of candidate chunks up-front so we can batch-
	// dedupe against already-stored hashes in a single DB round-trip.
	type pending struct {
		symbol SymbolSource
		index  int
		text   string
		hash   string
	}
	var queue []pending
	for _, s := range symbols {
		if strings.TrimSpace(s.Content) == "" {
			continue
		}
		for idx, chunk := range splitIntoChunks(s.Content, i.maxChunkCh) {
			queue = append(queue, pending{
				symbol: s,
				index:  idx,
				text:   chunk,
				hash:   contentHash(s.SymbolID, chunk),
			})
		}
	}
	if len(queue) == 0 {
		return nil
	}

	hashes := make([]string, 0, len(queue))
	for _, q := range queue {
		hashes = append(hashes, q.hash)
	}
	existing, err := i.store.ExistingHashes(ctx, repoID, hashes)
	if err != nil {
		return fmt.Errorf("existing hashes: %w", err)
	}

	// Filter out already-indexed chunks.
	fresh := make([]pending, 0, len(queue))
	for _, q := range queue {
		if existing[q.hash] {
			continue
		}
		fresh = append(fresh, q)
	}
	if len(fresh) == 0 {
		return nil
	}

	// Embed + persist in batches.
	for start := 0; start < len(fresh); start += i.batchSize {
		end := start + i.batchSize
		if end > len(fresh) {
			end = len(fresh)
		}
		batch := fresh[start:end]
		texts := make([]string, len(batch))
		for j, q := range batch {
			texts[j] = q.text
		}
		vecs, err := i.embedder.Embed(ctx, texts)
		if err != nil {
			return fmt.Errorf("embed batch: %w", err)
		}
		if len(vecs) != len(batch) {
			return fmt.Errorf("embed batch: returned %d vecs for %d texts", len(vecs), len(batch))
		}
		chunks := make([]EmbeddingChunk, len(batch))
		for j, q := range batch {
			chunks[j] = EmbeddingChunk{
				ID:             uuid.New(),
				TenantID:       tenantID,
				RepoID:         repoID,
				CommitSHA:      commitSHA,
				SymbolID:       q.symbol.SymbolID,
				SymbolName:     q.symbol.SymbolName,
				FilePath:       q.symbol.FilePath,
				StartLine:      q.symbol.StartLine,
				ChunkIndex:     q.index,
				ContentHash:    q.hash,
				ContentPreview: preview(q.text, 240),
				Embedding:      vecs[j],
				ModelName:      i.modelName,
			}
		}
		if err := i.store.SaveBatch(ctx, chunks); err != nil {
			return fmt.Errorf("save batch: %w", err)
		}
	}
	return nil
}

// SearchInput carries query parameters.
type SearchInput struct {
	TenantID uuid.UUID
	RepoID   uuid.UUID
	Query    string
	Limit    int
}

// Search embeds the query and returns top-k similar chunks.
func (i *EmbeddingIndexer) Search(ctx context.Context, in SearchInput) ([]EmbeddingSearchHit, error) {
	if strings.TrimSpace(in.Query) == "" {
		return nil, fmt.Errorf("embedding search: empty query")
	}
	vecs, err := i.embedder.Embed(ctx, []string{in.Query})
	if err != nil {
		return nil, fmt.Errorf("embed query: %w", err)
	}
	if len(vecs) != 1 {
		return nil, fmt.Errorf("embed query: expected 1 vec, got %d", len(vecs))
	}
	limit := in.Limit
	if limit <= 0 {
		limit = 20
	}
	hits, err := i.store.Search(ctx, in.RepoID, vecs[0], limit)
	if err != nil {
		return nil, fmt.Errorf("search store: %w", err)
	}
	// Defense-in-depth: sort by score desc in case the store didn't.
	sort.Slice(hits, func(a, b int) bool { return hits[a].Score > hits[b].Score })
	return hits, nil
}

// splitIntoChunks breaks a blob into roughly maxBytes-sized pieces at
// line boundaries so context isn't split mid-statement.
func splitIntoChunks(s string, maxBytes int) []string {
	if len(s) <= maxBytes {
		return []string{s}
	}
	var out []string
	lines := strings.SplitAfter(s, "\n")
	var buf strings.Builder
	for _, line := range lines {
		if buf.Len()+len(line) > maxBytes && buf.Len() > 0 {
			out = append(out, buf.String())
			buf.Reset()
		}
		buf.WriteString(line)
	}
	if buf.Len() > 0 {
		out = append(out, buf.String())
	}
	return out
}

func contentHash(symbolID, content string) string {
	h := sha256.New()
	h.Write([]byte(symbolID))
	h.Write([]byte{0})
	h.Write([]byte(content))
	return hex.EncodeToString(h.Sum(nil))
}

func preview(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// CosineSimilarity is exposed here so both the in-memory fallback
// store and tests can share a single implementation.
func CosineSimilarity(a, b []float32) float32 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	var dot, an, bn float64
	for i := range a {
		af := float64(a[i])
		bf := float64(b[i])
		dot += af * bf
		an += af * af
		bn += bf * bf
	}
	if an == 0 || bn == 0 {
		return 0
	}
	return float32(dot / (math.Sqrt(an) * math.Sqrt(bn)))
}
