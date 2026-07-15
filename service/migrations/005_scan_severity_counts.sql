-- Per-severity finding counts stored on the scan row.
--
-- Rationale: findings are a tenant-global pool deduped by fingerprint and are
-- NOT linked to a scan (no scan_id column). That makes it impossible to answer
-- "how many CRITICAL findings did THIS scan of THIS target produce" — the
-- signal the delivery deploy gate needs. The worker's RunScan returns exactly
-- the findings THIS scan produced, so we count them by severity there and
-- persist the counts onto the scan row for GetSecurityBaseline to serve.
ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS findings_critical INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS findings_high     INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS findings_medium   INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS findings_low      INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS findings_info     INT NOT NULL DEFAULT 0;
