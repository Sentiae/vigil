-- Code Intelligence — §11.2 / §5.8
--
-- Adds four tables backing the multi-language code intelligence stack:
--
-- * code_embeddings — per-symbol embedding chunks used for semantic
--   search over source code. Created here as JSONB so fresh databases
--   running against a cluster without pgvector still initialize; the
--   004_pgvector.sql migration flips the column to vector(1536) and
--   adds the IVFFlat index once pgvector is available.
--
-- * entry_points — main functions, HTTP routes, CLI commands, worker
--   entry points and event handlers. Consumed by canvas-service to
--   seed the architecture map with execution-origin nodes.
--
-- * module_semantics — LLM-produced summaries of module purpose and
--   responsibilities. Re-run only when module_hash changes.
--
-- * scip_indexes — raw SCIP protobuf bytes per (repo_id, commit_sha,
--   language) so downstream edge converters don't re-run the CLI.

CREATE TABLE IF NOT EXISTS code_embeddings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    repo_id         UUID NOT NULL,
    commit_sha      TEXT NOT NULL DEFAULT '',
    symbol_id       TEXT NOT NULL,
    symbol_name     TEXT NOT NULL DEFAULT '',
    file_path       TEXT NOT NULL DEFAULT '',
    start_line      INTEGER NOT NULL DEFAULT 0,
    chunk_index     INTEGER NOT NULL DEFAULT 0,
    content_hash    TEXT NOT NULL,
    content_preview TEXT NOT NULL DEFAULT '',
    embedding       JSONB NOT NULL,
    model_name      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_code_embeddings_repo
    ON code_embeddings (tenant_id, repo_id, commit_sha);
CREATE INDEX IF NOT EXISTS idx_code_embeddings_hash
    ON code_embeddings (repo_id, content_hash);
CREATE INDEX IF NOT EXISTS idx_code_embeddings_symbol
    ON code_embeddings (repo_id, symbol_id);

CREATE TABLE IF NOT EXISTS entry_points (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL,
    repo_id       UUID NOT NULL,
    kind          TEXT NOT NULL CHECK (kind IN ('main','http_route','event_handler','cli_command','worker')),
    name          TEXT NOT NULL,
    symbol_id     TEXT NOT NULL DEFAULT '',
    file_path     TEXT NOT NULL,
    line_number   INTEGER NOT NULL DEFAULT 0,
    language      TEXT NOT NULL DEFAULT '',
    framework     TEXT NOT NULL DEFAULT '',
    metadata      JSONB NOT NULL DEFAULT '{}',
    detected_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_entry_points_repo
    ON entry_points (tenant_id, repo_id);
CREATE INDEX IF NOT EXISTS idx_entry_points_kind
    ON entry_points (repo_id, kind);
CREATE UNIQUE INDEX IF NOT EXISTS ux_entry_points_dedupe
    ON entry_points (repo_id, kind, file_path, line_number, name);

CREATE TABLE IF NOT EXISTS module_semantics (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID NOT NULL,
    repo_id               UUID NOT NULL,
    module_id             TEXT NOT NULL,
    module_hash           TEXT NOT NULL DEFAULT '',
    purpose               TEXT NOT NULL DEFAULT '',
    responsibilities_json JSONB NOT NULL DEFAULT '[]',
    domain_concepts_json  JSONB NOT NULL DEFAULT '[]',
    confidence            NUMERIC(3,2) NOT NULL DEFAULT 0,
    model_name            TEXT NOT NULL DEFAULT '',
    computed_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (repo_id, module_id)
);

CREATE INDEX IF NOT EXISTS idx_module_semantics_tenant_repo
    ON module_semantics (tenant_id, repo_id);

CREATE TABLE IF NOT EXISTS scip_indexes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL,
    repo_id     UUID NOT NULL,
    commit_sha  TEXT NOT NULL DEFAULT '',
    language    TEXT NOT NULL,
    byte_size   INTEGER NOT NULL DEFAULT 0,
    raw_proto   BYTEA,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (repo_id, commit_sha, language)
);

CREATE INDEX IF NOT EXISTS idx_scip_indexes_repo
    ON scip_indexes (tenant_id, repo_id);
