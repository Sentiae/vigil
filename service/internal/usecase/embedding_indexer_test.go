package usecase

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

type fakeLister struct{ symbols []SymbolSource }

func (f *fakeLister) ListSymbols(_ context.Context, _ uuid.UUID, _ string) ([]SymbolSource, error) {
	return f.symbols, nil
}

type fakeEmbedder struct {
	dim  int
	seen []string
}

func (f *fakeEmbedder) Embed(_ context.Context, texts []string) ([][]float32, error) {
	f.seen = append(f.seen, texts...)
	out := make([][]float32, len(texts))
	for i, t := range texts {
		v := make([]float32, f.dim)
		for j := 0; j < f.dim && j < len(t); j++ {
			v[j] = float32(t[j]) / 255.0
		}
		out[i] = v
	}
	return out, nil
}

type fakeStore struct {
	mu     sync.Mutex
	chunks []EmbeddingChunk
}

func (f *fakeStore) ExistingHashes(_ context.Context, _ uuid.UUID, hashes []string) (map[string]bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]bool{}
	have := map[string]bool{}
	for _, c := range f.chunks {
		have[c.ContentHash] = true
	}
	for _, h := range hashes {
		if have[h] {
			out[h] = true
		}
	}
	return out, nil
}

func (f *fakeStore) SaveBatch(_ context.Context, chunks []EmbeddingChunk) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.chunks = append(f.chunks, chunks...)
	return nil
}

func (f *fakeStore) Search(_ context.Context, _ uuid.UUID, vec []float32, limit int) ([]EmbeddingSearchHit, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	type scored struct {
		hit   EmbeddingSearchHit
		score float32
	}
	scoredList := make([]scored, 0, len(f.chunks))
	for _, c := range f.chunks {
		s := CosineSimilarity(c.Embedding, vec)
		scoredList = append(scoredList, scored{
			hit: EmbeddingSearchHit{
				SymbolID:   c.SymbolID,
				SymbolName: c.SymbolName,
				FilePath:   c.FilePath,
				StartLine:  c.StartLine,
				ChunkIndex: c.ChunkIndex,
				Preview:    c.ContentPreview,
				Score:      s,
			},
			score: s,
		})
	}
	// Sort desc.
	for i := 0; i < len(scoredList); i++ {
		for j := i + 1; j < len(scoredList); j++ {
			if scoredList[j].score > scoredList[i].score {
				scoredList[i], scoredList[j] = scoredList[j], scoredList[i]
			}
		}
	}
	if limit > len(scoredList) {
		limit = len(scoredList)
	}
	out := make([]EmbeddingSearchHit, limit)
	for i := 0; i < limit; i++ {
		out[i] = scoredList[i].hit
	}
	return out, nil
}

func TestEmbeddingIndexerHappyPath(t *testing.T) {
	lister := &fakeLister{symbols: []SymbolSource{
		{SymbolID: "s1", SymbolName: "foo", FilePath: "a.go", StartLine: 10, Content: "func foo() { validateSubscription() }"},
		{SymbolID: "s2", SymbolName: "bar", FilePath: "b.go", StartLine: 20, Content: "func bar() { chargeCustomer() }"},
	}}
	embedder := &fakeEmbedder{dim: 16}
	store := &fakeStore{}
	idx := NewEmbeddingIndexer(lister, embedder, store)

	ctx := context.Background()
	tenant, repo := uuid.New(), uuid.New()
	if err := idx.IndexRepository(ctx, tenant, repo, "abc"); err != nil {
		t.Fatalf("index: %v", err)
	}
	if len(store.chunks) != 2 {
		t.Fatalf("want 2 chunks, got %d", len(store.chunks))
	}

	// Second run is a no-op (hashes already exist).
	before := len(embedder.seen)
	if err := idx.IndexRepository(ctx, tenant, repo, "abc"); err != nil {
		t.Fatal(err)
	}
	if len(embedder.seen) != before {
		t.Errorf("re-run should be cache-hit, but embedder was called %d→%d", before, len(embedder.seen))
	}

	// Search surfaces the most similar chunk.
	hits, err := idx.Search(ctx, SearchInput{RepoID: repo, Query: "validateSubscription", Limit: 1})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("want 1 hit, got %d", len(hits))
	}
	if !strings.Contains(hits[0].Preview, "validateSubscription") {
		t.Errorf("top hit should be the validateSubscription chunk, got %q", hits[0].Preview)
	}
}

func TestSplitIntoChunks(t *testing.T) {
	body := strings.Repeat("line a\n", 2000)
	chunks := splitIntoChunks(body, 256)
	if len(chunks) < 2 {
		t.Errorf("expected multiple chunks, got %d", len(chunks))
	}
	for _, c := range chunks {
		if len(c) > 256+16 { // small tolerance: we flush at line boundary
			t.Errorf("chunk length %d exceeds budget", len(c))
		}
	}
}

func TestCosineSimilarity(t *testing.T) {
	a := []float32{1, 0, 0}
	b := []float32{1, 0, 0}
	if s := CosineSimilarity(a, b); s < 0.999 {
		t.Errorf("identical vectors want ~1, got %v", s)
	}
	if s := CosineSimilarity([]float32{1, 0}, []float32{0, 1}); s != 0 {
		t.Errorf("orthogonal vectors want 0, got %v", s)
	}
	if s := CosineSimilarity(nil, nil); s != 0 {
		t.Errorf("nil want 0, got %v", s)
	}
}
