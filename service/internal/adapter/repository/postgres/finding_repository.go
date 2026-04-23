package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	pkdbm "github.com/sentiae/platform-kit/dbmetrics"
	"github.com/sentiae/vigil/service/internal/domain"
	"github.com/sentiae/vigil/service/internal/port/repository"
)

// slowFindingQueryThreshold catches slow writes — findings writes get
// called in tight loops during SARIF ingest, so 250ms is the point
// where we want a warning to surface.
const slowFindingQueryThreshold = 250 * time.Millisecond

type findingRepository struct {
	pool *pgxpool.Pool
}

func NewFindingRepository(pool *pgxpool.Pool) repository.FindingRepository {
	return &findingRepository{pool: pool}
}

func (r *findingRepository) Create(ctx context.Context, f *domain.Finding) error {
	start := pkdbm.Start()
	defer pkdbm.Observe(ctx, start, slowFindingQueryThreshold, "FindingRepo.Create")
	if f.ID == uuid.Nil {
		f.ID = uuid.New()
	}

	locationJSON, err := json.Marshal(f.Location)
	if err != nil {
		return fmt.Errorf("marshal location: %w", err)
	}

	complianceJSON, err := json.Marshal(f.ComplianceMappings)
	if err != nil {
		return fmt.Errorf("marshal compliance: %w", err)
	}

	metadataJSON, err := json.Marshal(f.Metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	_, err = r.pool.Exec(ctx, `
		INSERT INTO findings (
			id, tenant_id, fingerprint, correlation_id,
			title, description, severity, normalized_score, status, analysis_type, category,
			source_scanner, source_rule_id, found_by,
			cves, cwes, cvss_score, cvss_vector, epss_score,
			location, remediation, "references", compliance_mappings,
			first_seen_at, last_seen_at, sla_deadline, vex_state,
			metadata, tags
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7, $8, $9, $10, $11,
			$12, $13, $14,
			$15, $16, $17, $18, $19,
			$20, $21, $22, $23,
			$24, $25, $26, $27,
			$28, $29
		)`,
		f.ID, f.TenantID, f.Fingerprint, f.CorrelationID,
		f.Title, f.Description, f.Severity, f.NormalizedScore, f.Status, f.AnalysisType, f.Category,
		f.SourceScanner, f.SourceRuleID, f.FoundBy,
		f.CVEs, f.CWEs, f.CVSSScore, f.CVSSVector, f.EPSSScore,
		locationJSON, f.Remediation, f.References, complianceJSON,
		f.FirstSeenAt, f.LastSeenAt, f.SLADeadline, f.VEXState,
		metadataJSON, f.Tags,
	)
	if err != nil {
		return fmt.Errorf("insert finding: %w", err)
	}
	return nil
}

func (r *findingRepository) Update(ctx context.Context, f *domain.Finding) error {
	locationJSON, _ := json.Marshal(f.Location)
	complianceJSON, _ := json.Marshal(f.ComplianceMappings)
	metadataJSON, _ := json.Marshal(f.Metadata)

	_, err := r.pool.Exec(ctx, `
		UPDATE findings SET
			title = $3, description = $4, severity = $5, normalized_score = $6,
			status = $7, category = $8, source_scanner = $9, source_rule_id = $10,
			found_by = $11, cves = $12, cwes = $13, cvss_score = $14, epss_score = $15,
			location = $16, remediation = $17, compliance_mappings = $18,
			last_seen_at = $19, sla_deadline = $20, vex_state = $21,
			metadata = $22, tags = $23
		WHERE tenant_id = $1 AND id = $2`,
		f.TenantID, f.ID,
		f.Title, f.Description, f.Severity, f.NormalizedScore,
		f.Status, f.Category, f.SourceScanner, f.SourceRuleID,
		f.FoundBy, f.CVEs, f.CWEs, f.CVSSScore, f.EPSSScore,
		locationJSON, f.Remediation, complianceJSON,
		f.LastSeenAt, f.SLADeadline, f.VEXState,
		metadataJSON, f.Tags,
	)
	return err
}

func (r *findingRepository) FindByID(ctx context.Context, tenantID, id uuid.UUID) (*domain.Finding, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT id, tenant_id, fingerprint, correlation_id,
			title, description, severity, normalized_score, status, analysis_type, category,
			source_scanner, source_rule_id, found_by,
			cves, cwes, cvss_score, cvss_vector, epss_score,
			location, remediation, "references", compliance_mappings,
			first_seen_at, last_seen_at, sla_deadline, vex_state,
			metadata, tags
		FROM findings WHERE tenant_id = $1 AND id = $2`, tenantID, id)

	return scanFinding(row)
}

func (r *findingRepository) FindByFingerprint(ctx context.Context, tenantID uuid.UUID, fingerprint string) (*domain.Finding, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT id, tenant_id, fingerprint, correlation_id,
			title, description, severity, normalized_score, status, analysis_type, category,
			source_scanner, source_rule_id, found_by,
			cves, cwes, cvss_score, cvss_vector, epss_score,
			location, remediation, "references", compliance_mappings,
			first_seen_at, last_seen_at, sla_deadline, vex_state,
			metadata, tags
		FROM findings WHERE tenant_id = $1 AND fingerprint = $2`, tenantID, fingerprint)

	return scanFinding(row)
}

func (r *findingRepository) List(ctx context.Context, filter repository.FindingFilter) ([]*domain.Finding, int, error) {
	var conditions []string
	var args []any
	argN := 1

	conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argN))
	args = append(args, filter.TenantID)
	argN++

	if filter.Severity != nil {
		conditions = append(conditions, fmt.Sprintf("severity = $%d", argN))
		args = append(args, *filter.Severity)
		argN++
	}
	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argN))
		args = append(args, *filter.Status)
		argN++
	}
	if filter.AnalysisType != nil {
		conditions = append(conditions, fmt.Sprintf("analysis_type = $%d", argN))
		args = append(args, *filter.AnalysisType)
		argN++
	}

	where := strings.Join(conditions, " AND ")

	// Count total
	var total int
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM findings WHERE %s", where)
	if err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count findings: %w", err)
	}

	// Fetch page
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}

	query := fmt.Sprintf(`
		SELECT id, tenant_id, fingerprint, correlation_id,
			title, description, severity, normalized_score, status, analysis_type, category,
			source_scanner, source_rule_id, found_by,
			cves, cwes, cvss_score, cvss_vector, epss_score,
			location, remediation, "references", compliance_mappings,
			first_seen_at, last_seen_at, sla_deadline, vex_state,
			metadata, tags
		FROM findings WHERE %s
		ORDER BY normalized_score DESC, first_seen_at DESC
		LIMIT $%d OFFSET $%d`, where, argN, argN+1)
	args = append(args, limit, filter.Offset)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()

	var findings []*domain.Finding
	for rows.Next() {
		f, err := scanFindingFromRows(rows)
		if err != nil {
			return nil, 0, err
		}
		findings = append(findings, f)
	}

	return findings, total, nil
}

func (r *findingRepository) UpdateLastSeen(ctx context.Context, tenantID uuid.UUID, fingerprint string) error {
	_, err := r.pool.Exec(ctx,
		"UPDATE findings SET last_seen_at = NOW() WHERE tenant_id = $1 AND fingerprint = $2",
		tenantID, fingerprint)
	return err
}

func (r *findingRepository) BulkUpsert(ctx context.Context, findings []*domain.Finding) (int, int, error) {
	// Bulk writes get a more forgiving threshold because a SARIF
	// upload can easily carry hundreds of findings.
	start := pkdbm.Start()
	defer pkdbm.Observe(ctx, start, 2*time.Second, "FindingRepo.BulkUpsert")
	created, updated := 0, 0

	batch := &pgx.Batch{}
	for _, f := range findings {
		if f.Fingerprint == "" {
			f.Fingerprint = f.ComputeFingerprint()
		}
		if f.ID == uuid.Nil {
			f.ID = uuid.New()
		}

		locationJSON, _ := json.Marshal(f.Location)
		complianceJSON, _ := json.Marshal(f.ComplianceMappings)
		metadataJSON, _ := json.Marshal(f.Metadata)

		batch.Queue(`
			INSERT INTO findings (
				id, tenant_id, fingerprint, title, description, severity, normalized_score,
				status, analysis_type, category, source_scanner, source_rule_id, found_by,
				cves, cwes, cvss_score, cvss_vector, epss_score,
				location, remediation, "references", compliance_mappings,
				first_seen_at, last_seen_at, sla_deadline, metadata, tags
			) VALUES (
				$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
				$14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27
			)
			ON CONFLICT (tenant_id, fingerprint)
			DO UPDATE SET
				last_seen_at = NOW(),
				normalized_score = EXCLUDED.normalized_score,
				found_by = EXCLUDED.found_by,
				cvss_score = EXCLUDED.cvss_score,
				epss_score = EXCLUDED.epss_score
			RETURNING (xmax = 0) AS is_insert`,
			f.ID, f.TenantID, f.Fingerprint, f.Title, f.Description, f.Severity, f.NormalizedScore,
			f.Status, f.AnalysisType, f.Category, f.SourceScanner, f.SourceRuleID, f.FoundBy,
			f.CVEs, f.CWEs, f.CVSSScore, f.CVSSVector, f.EPSSScore,
			locationJSON, f.Remediation, f.References, complianceJSON,
			f.FirstSeenAt, f.LastSeenAt, f.SLADeadline, metadataJSON, f.Tags,
		)
	}

	br := r.pool.SendBatch(ctx, batch)
	defer br.Close()

	for range findings {
		var isInsert bool
		if err := br.QueryRow().Scan(&isInsert); err != nil {
			return created, updated, fmt.Errorf("bulk upsert: %w", err)
		}
		if isInsert {
			created++
		} else {
			updated++
		}
	}

	return created, updated, nil
}

func (r *findingRepository) CountBySeverity(ctx context.Context, tenantID uuid.UUID) (map[domain.Severity]int, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT severity, COUNT(*) FROM findings
		WHERE tenant_id = $1 AND status NOT IN ('resolved', 'false_positive', 'risk_accepted')
		GROUP BY severity`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := make(map[domain.Severity]int)
	for rows.Next() {
		var sev domain.Severity
		var count int
		if err := rows.Scan(&sev, &count); err != nil {
			return nil, err
		}
		counts[sev] = count
	}
	return counts, nil
}

func (r *findingRepository) UpdateStatus(ctx context.Context, tenantID, id uuid.UUID, status domain.FindingStatus) error {
	tag, err := r.pool.Exec(ctx,
		"UPDATE findings SET status = $3 WHERE tenant_id = $1 AND id = $2",
		tenantID, id, status)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrFindingNotFound
	}
	return nil
}

func (r *findingRepository) ListSLABreached(ctx context.Context, tenantID uuid.UUID) ([]*domain.Finding, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, tenant_id, fingerprint, correlation_id,
			title, description, severity, normalized_score, status, analysis_type, category,
			source_scanner, source_rule_id, found_by,
			cves, cwes, cvss_score, cvss_vector, epss_score,
			location, remediation, "references", compliance_mappings,
			first_seen_at, last_seen_at, sla_deadline, vex_state,
			metadata, tags
		FROM findings
		WHERE tenant_id = $1
			AND sla_deadline IS NOT NULL
			AND sla_deadline < NOW()
			AND status NOT IN ('resolved', 'false_positive', 'risk_accepted')
		ORDER BY sla_deadline ASC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []*domain.Finding
	for rows.Next() {
		f, err := scanFindingFromRows(rows)
		if err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func (r *findingRepository) ListAllSLABreached(ctx context.Context, limit int) ([]*domain.Finding, error) {
	if limit <= 0 {
		limit = 1000
	}

	rows, err := r.pool.Query(ctx, `
		SELECT id, tenant_id, fingerprint, correlation_id,
			title, description, severity, normalized_score, status, analysis_type, category,
			source_scanner, source_rule_id, found_by,
			cves, cwes, cvss_score, cvss_vector, epss_score,
			location, remediation, "references", compliance_mappings,
			first_seen_at, last_seen_at, sla_deadline, vex_state,
			metadata, tags
		FROM findings
		WHERE sla_deadline IS NOT NULL
			AND sla_deadline < NOW()
			AND status NOT IN ('resolved', 'false_positive', 'risk_accepted')
		ORDER BY sla_deadline ASC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []*domain.Finding
	for rows.Next() {
		f, err := scanFindingFromRows(rows)
		if err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func (r *findingRepository) ListActiveTenantIDs(ctx context.Context) ([]uuid.UUID, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT DISTINCT tenant_id FROM findings
		WHERE status NOT IN ('resolved', 'false_positive', 'risk_accepted')
		LIMIT 10000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// scanFinding scans a single row into a Finding.
func scanFinding(row pgx.Row) (*domain.Finding, error) {
	f := &domain.Finding{}
	var locationJSON, complianceJSON, metadataJSON []byte

	err := row.Scan(
		&f.ID, &f.TenantID, &f.Fingerprint, &f.CorrelationID,
		&f.Title, &f.Description, &f.Severity, &f.NormalizedScore, &f.Status, &f.AnalysisType, &f.Category,
		&f.SourceScanner, &f.SourceRuleID, &f.FoundBy,
		&f.CVEs, &f.CWEs, &f.CVSSScore, &f.CVSSVector, &f.EPSSScore,
		&locationJSON, &f.Remediation, &f.References, &complianceJSON,
		&f.FirstSeenAt, &f.LastSeenAt, &f.SLADeadline, &f.VEXState,
		&metadataJSON, &f.Tags,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrFindingNotFound
		}
		return nil, fmt.Errorf("scan finding: %w", err)
	}

	_ = json.Unmarshal(locationJSON, &f.Location)
	_ = json.Unmarshal(complianceJSON, &f.ComplianceMappings)
	_ = json.Unmarshal(metadataJSON, &f.Metadata)

	return f, nil
}

// scanFindingFromRows scans from pgx.Rows (used in List queries).
func scanFindingFromRows(rows pgx.Rows) (*domain.Finding, error) {
	f := &domain.Finding{}
	var locationJSON, complianceJSON, metadataJSON []byte

	err := rows.Scan(
		&f.ID, &f.TenantID, &f.Fingerprint, &f.CorrelationID,
		&f.Title, &f.Description, &f.Severity, &f.NormalizedScore, &f.Status, &f.AnalysisType, &f.Category,
		&f.SourceScanner, &f.SourceRuleID, &f.FoundBy,
		&f.CVEs, &f.CWEs, &f.CVSSScore, &f.CVSSVector, &f.EPSSScore,
		&locationJSON, &f.Remediation, &f.References, &complianceJSON,
		&f.FirstSeenAt, &f.LastSeenAt, &f.SLADeadline, &f.VEXState,
		&metadataJSON, &f.Tags,
	)
	if err != nil {
		return nil, fmt.Errorf("scan finding row: %w", err)
	}

	_ = json.Unmarshal(locationJSON, &f.Location)
	_ = json.Unmarshal(complianceJSON, &f.ComplianceMappings)
	_ = json.Unmarshal(metadataJSON, &f.Metadata)

	return f, nil
}
