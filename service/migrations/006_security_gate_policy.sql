-- Rationale: the configurable deploy gate (docs/designs/security-gate-policy.md §4).
-- Org policy + per-user preference for the delivery security gate.
-- tenant_id anchors both tables so the future vigil RLS flip (deferred at
-- T-SEC-FND) covers them with the standard D-070..078 pattern, zero rework.

CREATE TABLE IF NOT EXISTS security_gate_policies (
    tenant_id          UUID PRIMARY KEY,
    mode               TEXT NOT NULL CHECK (mode IN ('enforce','warn','off')),
    severity_threshold TEXT NOT NULL DEFAULT 'critical'
                       CHECK (severity_threshold IN ('critical','high','medium','low')),
    locked             BOOLEAN NOT NULL DEFAULT true,
    updated_by         UUID NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS security_gate_user_prefs (
    tenant_id          UUID NOT NULL,
    user_id            UUID NOT NULL,
    mode               TEXT NOT NULL CHECK (mode IN ('enforce','warn','off')),
    severity_threshold TEXT NOT NULL DEFAULT 'critical'
                       CHECK (severity_threshold IN ('critical','high','medium','low')),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id)
);

-- Match 001_initial_schema.sql:188-212 posture: RLS enabled per table (decorative
-- until the vigil flip — no code sets app.tenant_id yet; isolation is enforced by
-- the tenant-anchored WHERE clauses below).
ALTER TABLE security_gate_policies ENABLE ROW LEVEL SECURITY;
CREATE POLICY security_gate_policies_tenant_isolation ON security_gate_policies
    USING (tenant_id::text = current_setting('app.tenant_id', true));
ALTER TABLE security_gate_user_prefs ENABLE ROW LEVEL SECURITY;
CREATE POLICY security_gate_user_prefs_tenant_isolation ON security_gate_user_prefs
    USING (tenant_id::text = current_setting('app.tenant_id', true));
