-- Rationale: an SLA breach is a TRANSITION, emitted once per (finding, deadline)
-- through the transactional outbox — not a heartbeat republished by every
-- five-minute scan (D-512 R9). The SLA scan claims a breach by setting
-- sla_breach_emitted_deadline = sla_deadline in the same transaction that writes
-- its outbox row; a changed deadline is a new transition.
--
-- Backfill: every finding already open and overdue when this ships was eligible
-- for repeated publication by the former scan; it is marked emitted for its
-- current deadline, so those breaches are intentionally not replayed during the
-- migration. The runner applies this file and its schema_migrations row in one
-- transaction. No index: the claim is served by idx_findings_sla_deadline (001).

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS sla_breach_emitted_deadline TIMESTAMPTZ NULL;

UPDATE findings
SET sla_breach_emitted_deadline = sla_deadline
WHERE sla_deadline IS NOT NULL
  AND sla_deadline < NOW()
  AND status NOT IN ('resolved', 'false_positive', 'risk_accepted');
