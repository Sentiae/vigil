-- §11.2 — Migrate code_embeddings.embedding from JSONB → pgvector(1536).
--
-- Rationale: prior migration (003_code_intelligence.sql) stored the
-- foundry-service /embed output as a JSONB float array and computed
-- cosine similarity in Go. That path scales linearly with corpus size;
-- once the embeddings table crosses ~50k rows the query becomes a
-- bottleneck. pgvector moves the distance computation into the engine
-- and adds an approximate-nearest-neighbor index.
--
-- The foundry-service default embedding model is text-embedding-3-small
-- which emits 1536-dim vectors (see foundry-service/pkg/config/config.go
-- `llm.embedding.dimension: 1536`). If the org overrides the model to
-- one with a different dimensionality the ALTER COLUMN line below will
-- fail safely at migration time rather than truncating vectors at write.

-- pgvector extension must be present. init-databases.sql creates it on
-- cluster init; this line is idempotent for clusters that pre-date that
-- change and is a no-op when the extension already exists.
CREATE EXTENSION IF NOT EXISTS vector;

-- Text JSONB -> vector coercion: pgvector accepts the standard
-- `[x,y,z]` literal form which JSONB arrays serialize to verbatim. The
-- double-cast goes through text because JSONB has no direct cast to
-- vector.
ALTER TABLE code_embeddings
    ALTER COLUMN embedding
    TYPE vector(1536)
    USING embedding::text::vector;

-- IVFFlat index for approximate nearest-neighbor search under cosine
-- distance. `lists = 100` is a good starting point for up to ~1M rows
-- per repository; tune with `SET ivfflat.probes` at query time if recall
-- drops. HNSW would also work but IVFFlat is friendlier to bulk inserts
-- which is the dominant write pattern for the code-embedding indexer.
CREATE INDEX IF NOT EXISTS code_embeddings_ivfflat
    ON code_embeddings
    USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 100);
