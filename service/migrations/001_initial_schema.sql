-- Code Analysis Service (Vigil) — Initial Schema
-- Requires extensions: uuid-ossp, pg_trgm, pgcrypto (created in init-databases.sql)

-- =============================================================================
-- Row-Level Security helper
-- =============================================================================
-- All tenant-scoped queries should SET app.tenant_id = '<uuid>' on the connection.

-- =============================================================================
-- FINDINGS — Universal security finding model
-- =============================================================================
CREATE TABLE IF NOT EXISTS findings (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID NOT NULL,
    fingerprint      TEXT NOT NULL,
    correlation_id   UUID,

    -- Classification
    title            TEXT NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    severity         TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    normalized_score NUMERIC(5,2) DEFAULT 0,
    status           TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'confirmed', 'in_progress', 'resolved', 'false_positive', 'risk_accepted')),
    analysis_type    TEXT NOT NULL CHECK (analysis_type IN ('sast', 'sca', 'secret_detection', 'iac', 'container', 'cloud', 'network', 'runtime', 'cicd', 'database', 'compliance', 'dast')),
    category         TEXT NOT NULL DEFAULT '',

    -- Source
    source_scanner   TEXT NOT NULL,
    source_rule_id   TEXT NOT NULL DEFAULT '',
    found_by         TEXT[] DEFAULT '{}',

    -- Vulnerability references
    cves             TEXT[] DEFAULT '{}',
    cwes             INTEGER[] DEFAULT '{}',
    cvss_score       NUMERIC(4,2),
    cvss_vector      TEXT DEFAULT '',
    epss_score       NUMERIC(6,5),

    -- Polymorphic location (JSONB for flexible schema)
    location         JSONB NOT NULL DEFAULT '{}',

    -- Remediation
    remediation      TEXT NOT NULL DEFAULT '',
    "references"     TEXT[] DEFAULT '{}',

    -- Compliance mappings (JSONB array)
    compliance_mappings JSONB DEFAULT '[]',

    -- Lifecycle
    first_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sla_deadline     TIMESTAMPTZ,
    vex_state        TEXT CHECK (vex_state IS NULL OR vex_state IN ('exploitable', 'not_affected', 'resolved', 'false_positive')),

    -- Extensibility
    metadata         JSONB DEFAULT '{}',
    tags             TEXT[] DEFAULT '{}',

    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Deduplication: unique per tenant + fingerprint
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_tenant_fingerprint ON findings(tenant_id, fingerprint);

-- Query indexes
CREATE INDEX IF NOT EXISTS idx_findings_tenant_severity_status ON findings(tenant_id, severity, status);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_analysis_type ON findings(tenant_id, analysis_type);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_status ON findings(tenant_id, status) WHERE status NOT IN ('resolved', 'false_positive', 'risk_accepted');
CREATE INDEX IF NOT EXISTS idx_findings_sla_deadline ON findings(tenant_id, sla_deadline) WHERE status NOT IN ('resolved', 'false_positive', 'risk_accepted') AND sla_deadline IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_findings_location ON findings USING GIN (location jsonb_path_ops);
CREATE INDEX IF NOT EXISTS idx_findings_title_trgm ON findings USING GIN (title gin_trgm_ops);

-- =============================================================================
-- SCANS — Security scan jobs
-- =============================================================================
CREATE TABLE IF NOT EXISTS scans (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL,
    scan_type     TEXT NOT NULL CHECK (scan_type IN ('sast', 'sca', 'secret_detection', 'iac', 'container', 'cloud', 'network', 'cicd', 'database', 'dast', 'endpoint_discovery', 'api_test', 'full')),
    target        TEXT NOT NULL,
    branch        TEXT DEFAULT '',
    commit_sha    TEXT DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'completed', 'failed')),
    priority      TEXT DEFAULT 'default',
    findings_new  INTEGER DEFAULT 0,
    findings_total INTEGER DEFAULT 0,
    duration_ms   BIGINT DEFAULT 0,
    error         TEXT DEFAULT '',
    triggered_by  TEXT NOT NULL DEFAULT 'system',
    started_at    TIMESTAMPTZ,
    completed_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scans_tenant_status ON scans(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_scans_tenant_created ON scans(tenant_id, created_at DESC);

-- =============================================================================
-- ASSETS — Discoverable entities in customer environments
-- =============================================================================
CREATE TABLE IF NOT EXISTS assets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    asset_type      TEXT NOT NULL CHECK (asset_type IN ('repository', 'container', 'service', 'cloud_resource', 'database', 'network', 'host')),
    name            TEXT NOT NULL,
    cloud_provider  TEXT DEFAULT '',
    cloud_account_id TEXT DEFAULT '',
    cloud_region    TEXT DEFAULT '',
    arn             TEXT DEFAULT '',
    criticality     TEXT NOT NULL DEFAULT 'medium' CHECK (criticality IN ('very_high', 'high', 'medium', 'low', 'very_low')),
    environment     TEXT DEFAULT '',
    internet_facing BOOLEAN DEFAULT FALSE,
    pii_handling    BOOLEAN DEFAULT FALSE,
    tags            JSONB DEFAULT '{}',
    last_scanned_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_tenant_arn ON assets(tenant_id, arn) WHERE arn != '';
CREATE INDEX IF NOT EXISTS idx_assets_tenant_type ON assets(tenant_id, asset_type);

-- =============================================================================
-- SLA POLICIES — Per-tenant SLA deadline configuration
-- =============================================================================
CREATE TABLE IF NOT EXISTS sla_policies (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id              UUID NOT NULL,
    severity               TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    production_hours       INTEGER NOT NULL,
    non_production_hours   INTEGER NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, severity)
);

-- =============================================================================
-- SCORING WEIGHTS — Per-tenant scoring configuration
-- =============================================================================
CREATE TABLE IF NOT EXISTS scoring_weights (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL UNIQUE,
    cvss        NUMERIC(4,3) NOT NULL DEFAULT 0.20,
    epss        NUMERIC(4,3) NOT NULL DEFAULT 0.25,
    asset       NUMERIC(4,3) NOT NULL DEFAULT 0.20,
    exposure    NUMERIC(4,3) NOT NULL DEFAULT 0.15,
    kev         NUMERIC(4,3) NOT NULL DEFAULT 0.10,
    age         NUMERIC(4,3) NOT NULL DEFAULT 0.10,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- AGENTS — Registered remote agents
-- =============================================================================
CREATE TABLE IF NOT EXISTS agents (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL,
    name          TEXT NOT NULL,
    agent_type    TEXT NOT NULL CHECK (agent_type IN ('cluster', 'cicd', 'cloud', 'network')),
    status        TEXT NOT NULL DEFAULT 'online' CHECK (status IN ('online', 'offline', 'degraded')),
    hostname      TEXT NOT NULL DEFAULT '',
    version       TEXT NOT NULL DEFAULT '',
    cert_serial   TEXT DEFAULT '',
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agents_tenant ON agents(tenant_id);

-- =============================================================================
-- OUTBOX — Transactional outbox for Kafka events
-- =============================================================================
CREATE TABLE IF NOT EXISTS outbox_events (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type   TEXT NOT NULL,
    payload      JSONB NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_outbox_undelivered ON outbox_events(created_at) WHERE delivered_at IS NULL;

-- =============================================================================
-- ROW-LEVEL SECURITY
-- =============================================================================
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE sla_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE scoring_weights ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents ENABLE ROW LEVEL SECURITY;

-- RLS policies: rows visible only when current_setting('app.tenant_id') matches
CREATE POLICY findings_tenant_isolation ON findings
    USING (tenant_id::text = current_setting('app.tenant_id', true));

CREATE POLICY scans_tenant_isolation ON scans
    USING (tenant_id::text = current_setting('app.tenant_id', true));

CREATE POLICY assets_tenant_isolation ON assets
    USING (tenant_id::text = current_setting('app.tenant_id', true));

CREATE POLICY sla_policies_tenant_isolation ON sla_policies
    USING (tenant_id::text = current_setting('app.tenant_id', true));

CREATE POLICY scoring_weights_tenant_isolation ON scoring_weights
    USING (tenant_id::text = current_setting('app.tenant_id', true));

CREATE POLICY agents_tenant_isolation ON agents
    USING (tenant_id::text = current_setting('app.tenant_id', true));

-- =============================================================================
-- UPDATED_AT TRIGGER
-- =============================================================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER findings_updated_at BEFORE UPDATE ON findings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER scans_updated_at BEFORE UPDATE ON scans
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER assets_updated_at BEFORE UPDATE ON assets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
