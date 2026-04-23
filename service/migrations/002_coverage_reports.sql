-- Phase 8: Coverage reports.
--
-- Stores per-file coverage uploads. Only the latest report for a
-- (tenant_id, repo_id) pair is strictly needed by the risk-zone
-- pipeline, but we keep history so the portal can show trend lines
-- and CI can detect coverage regressions.

CREATE TABLE IF NOT EXISTS coverage_reports (
    id           UUID PRIMARY KEY,
    tenant_id    UUID NOT NULL,
    repo_id      TEXT NOT NULL,
    commit_sha   TEXT NOT NULL DEFAULT '',
    branch       TEXT NOT NULL DEFAULT '',
    format       TEXT NOT NULL,
    files        JSONB NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_coverage_reports_tenant_repo
    ON coverage_reports (tenant_id, repo_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_coverage_reports_created
    ON coverage_reports (created_at DESC);
