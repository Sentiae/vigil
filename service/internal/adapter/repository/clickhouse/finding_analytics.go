package clickhouse

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sentiae/vigil/service/internal/domain"
	"github.com/sentiae/vigil/service/internal/port/repository"
	"github.com/sentiae/vigil/service/pkg/logger"
)

// AnalyticsRepository implements the ClickHouse analytics layer.
type AnalyticsRepository struct {
	db *sql.DB
}

// NewAnalyticsRepository creates a new ClickHouse analytics repository.
func NewAnalyticsRepository(db *sql.DB) repository.AnalyticsRepository {
	return &AnalyticsRepository{db: db}
}

func (r *AnalyticsRepository) InsertFinding(ctx context.Context, f *domain.Finding) error {
	return r.InsertFindings(ctx, []*domain.Finding{f})
}

func (r *AnalyticsRepository) InsertFindings(ctx context.Context, findings []*domain.Finding) error {
	if len(findings) == 0 {
		return nil
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO code_analysis.security_findings (
			id, tenant_id, scan_id, fingerprint, title, description,
			severity, normalized_score, status, analysis_type, category,
			source_scanner, source_rule_id, cves, cwes,
			cvss_score, epss_score, file_path, container_image,
			resource_arn, hostname, first_seen_at, last_seen_at,
			resolved_at, sla_deadline
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare: %w", err)
	}
	defer stmt.Close()

	for _, f := range findings {
		var cvssScore, epssScore float64
		if f.CVSSScore != nil {
			cvssScore = *f.CVSSScore
		}
		if f.EPSSScore != nil {
			epssScore = *f.EPSSScore
		}

		var resolvedAt *time.Time
		if f.Status.IsTerminal() {
			now := time.Now()
			resolvedAt = &now
		}

		scanID := uuid.Nil
		if f.ScanID != nil {
			scanID = *f.ScanID
		}

		_, err := stmt.ExecContext(ctx,
			f.ID, f.TenantID, scanID, f.Fingerprint, f.Title, f.Description,
			string(f.Severity), f.NormalizedScore, string(f.Status), string(f.AnalysisType), f.Category,
			f.SourceScanner, f.SourceRuleID, f.CVEs, f.CWEs,
			cvssScore, epssScore, f.Location.FilePath, f.Location.ContainerImage,
			f.Location.ResourceARN, f.Location.Hostname, f.FirstSeenAt, f.LastSeenAt,
			resolvedAt, f.SLADeadline,
		)
		if err != nil {
			logger.Warn(ctx, "Failed to insert finding to ClickHouse", "finding_id", f.ID, "error", err)
		}
	}

	return tx.Commit()
}

func (r *AnalyticsRepository) FindingTrends(ctx context.Context, tenantID uuid.UUID, from, to time.Time) ([]repository.FindingTrend, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT
			toDate(first_seen_at) AS day,
			severity,
			analysis_type,
			count() AS cnt
		FROM code_analysis.security_findings
		WHERE tenant_id = ?
			AND first_seen_at >= ?
			AND first_seen_at < ?
		GROUP BY day, severity, analysis_type
		ORDER BY day ASC, severity ASC
	`, tenantID, from, to)
	if err != nil {
		return nil, fmt.Errorf("finding trends query: %w", err)
	}
	defer rows.Close()

	var trends []repository.FindingTrend
	for rows.Next() {
		var t repository.FindingTrend
		var sev, at string
		if err := rows.Scan(&t.Date, &sev, &at, &t.Count); err != nil {
			return nil, fmt.Errorf("scan trend row: %w", err)
		}
		t.Severity = domain.Severity(sev)
		t.AnalysisType = domain.AnalysisType(at)
		trends = append(trends, t)
	}

	return trends, nil
}

func (r *AnalyticsRepository) SearchFindings(ctx context.Context, tenantID uuid.UUID, query string, limit int) ([]*domain.Finding, error) {
	if limit <= 0 {
		limit = 50
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT
			id, tenant_id, fingerprint, title, description,
			severity, normalized_score, status, analysis_type, category,
			source_scanner, first_seen_at, last_seen_at
		FROM code_analysis.security_findings
		WHERE tenant_id = ?
			AND (hasToken(lower(title), lower(?)) OR hasToken(lower(description), lower(?)))
		ORDER BY normalized_score DESC
		LIMIT ?
	`, tenantID, query, query, limit)
	if err != nil {
		return nil, fmt.Errorf("search findings: %w", err)
	}
	defer rows.Close()

	var findings []*domain.Finding
	for rows.Next() {
		f := &domain.Finding{}
		var sev, status, at string
		if err := rows.Scan(
			&f.ID, &f.TenantID, &f.Fingerprint, &f.Title, &f.Description,
			&sev, &f.NormalizedScore, &status, &at, &f.Category,
			&f.SourceScanner, &f.FirstSeenAt, &f.LastSeenAt,
		); err != nil {
			return nil, fmt.Errorf("scan search row: %w", err)
		}
		f.Severity = domain.Severity(sev)
		f.Status = domain.FindingStatus(status)
		f.AnalysisType = domain.AnalysisType(at)
		findings = append(findings, f)
	}

	return findings, nil
}

func (r *AnalyticsRepository) ScanMetrics(ctx context.Context, tenantID uuid.UUID, from, to time.Time) ([]map[string]any, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT
			scan_type,
			count() AS total_scans,
			avg(duration_ms) AS avg_duration_ms,
			sum(findings_new) AS total_findings_new,
			sum(findings_total) AS total_findings
		FROM code_analysis.scan_metrics
		WHERE tenant_id = ?
			AND started_at >= ?
			AND started_at < ?
		GROUP BY scan_type
		ORDER BY total_scans DESC
	`, tenantID, from, to)
	if err != nil {
		return nil, fmt.Errorf("scan metrics query: %w", err)
	}
	defer rows.Close()

	var metrics []map[string]any
	for rows.Next() {
		var scanType string
		var totalScans, totalFindingsNew, totalFindings uint64
		var avgDuration float64
		if err := rows.Scan(&scanType, &totalScans, &avgDuration, &totalFindingsNew, &totalFindings); err != nil {
			return nil, err
		}
		metrics = append(metrics, map[string]any{
			"scan_type":          scanType,
			"total_scans":        totalScans,
			"avg_duration_ms":    avgDuration,
			"total_findings_new": totalFindingsNew,
			"total_findings":     totalFindings,
		})
	}

	return metrics, nil
}
