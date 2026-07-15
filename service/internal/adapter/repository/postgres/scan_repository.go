package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentiae/vigil/service/internal/domain"
	"github.com/sentiae/vigil/service/internal/port/repository"
)

type scanRepository struct {
	pool *pgxpool.Pool
}

func NewScanRepository(pool *pgxpool.Pool) repository.ScanRepository {
	return &scanRepository{pool: pool}
}

func (r *scanRepository) Create(ctx context.Context, s *domain.Scan) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}

	_, err := r.pool.Exec(ctx, `
		INSERT INTO scans (
			id, tenant_id, scan_type, target, branch, commit_sha,
			status, priority, triggered_by, created_at, updated_at,
			findings_critical, findings_high, findings_medium, findings_low, findings_info
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
		s.ID, s.TenantID, s.Type, s.Target, s.Branch, s.CommitSHA,
		s.Status, s.Priority, s.TriggeredBy, s.CreatedAt, s.UpdatedAt,
		s.FindingsCritical, s.FindingsHigh, s.FindingsMedium, s.FindingsLow, s.FindingsInfo,
	)
	return err
}

func (r *scanRepository) Update(ctx context.Context, s *domain.Scan) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE scans SET
			status = $3, findings_new = $4, findings_total = $5,
			duration_ms = $6, error = $7, started_at = $8, completed_at = $9,
			findings_critical = $10, findings_high = $11, findings_medium = $12,
			findings_low = $13, findings_info = $14
		WHERE tenant_id = $1 AND id = $2`,
		s.TenantID, s.ID,
		s.Status, s.FindingsNew, s.FindingsTotal,
		s.DurationMs, s.Error, s.StartedAt, s.CompletedAt,
		s.FindingsCritical, s.FindingsHigh, s.FindingsMedium, s.FindingsLow, s.FindingsInfo,
	)
	return err
}

func (r *scanRepository) FindByID(ctx context.Context, tenantID, id uuid.UUID) (*domain.Scan, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT id, tenant_id, scan_type, target, branch, commit_sha,
			status, priority, findings_new, findings_total,
			findings_critical, findings_high, findings_medium, findings_low, findings_info,
			duration_ms, error,
			triggered_by, started_at, completed_at, created_at, updated_at
		FROM scans WHERE tenant_id = $1 AND id = $2`, tenantID, id)

	return scanScan(row)
}

func (r *scanRepository) List(ctx context.Context, filter repository.ScanFilter) ([]*domain.Scan, int, error) {
	var conditions []string
	var args []any
	argN := 1

	conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argN))
	args = append(args, filter.TenantID)
	argN++

	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argN))
		args = append(args, *filter.Status)
		argN++
	}
	if filter.Type != nil {
		conditions = append(conditions, fmt.Sprintf("scan_type = $%d", argN))
		args = append(args, *filter.Type)
		argN++
	}

	where := strings.Join(conditions, " AND ")

	var total int
	if err := r.pool.QueryRow(ctx, fmt.Sprintf("SELECT COUNT(*) FROM scans WHERE %s", where), args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}

	query := fmt.Sprintf(`
		SELECT id, tenant_id, scan_type, target, branch, commit_sha,
			status, priority, findings_new, findings_total,
			findings_critical, findings_high, findings_medium, findings_low, findings_info,
			duration_ms, error,
			triggered_by, started_at, completed_at, created_at, updated_at
		FROM scans WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, where, argN, argN+1)
	args = append(args, limit, filter.Offset)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var scans []*domain.Scan
	for rows.Next() {
		s := &domain.Scan{}
		if err := rows.Scan(
			&s.ID, &s.TenantID, &s.Type, &s.Target, &s.Branch, &s.CommitSHA,
			&s.Status, &s.Priority, &s.FindingsNew, &s.FindingsTotal,
			&s.FindingsCritical, &s.FindingsHigh, &s.FindingsMedium, &s.FindingsLow, &s.FindingsInfo,
			&s.DurationMs, &s.Error,
			&s.TriggeredBy, &s.StartedAt, &s.CompletedAt, &s.CreatedAt, &s.UpdatedAt,
		); err != nil {
			return nil, 0, err
		}
		scans = append(scans, s)
	}

	return scans, total, nil
}

func (r *scanRepository) UpdateStatus(ctx context.Context, tenantID, id uuid.UUID, status domain.ScanStatus) error {
	tag, err := r.pool.Exec(ctx,
		"UPDATE scans SET status = $3 WHERE tenant_id = $1 AND id = $2",
		tenantID, id, status)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrScanNotFound
	}
	return nil
}

func scanScan(row pgx.Row) (*domain.Scan, error) {
	s := &domain.Scan{}
	err := row.Scan(
		&s.ID, &s.TenantID, &s.Type, &s.Target, &s.Branch, &s.CommitSHA,
		&s.Status, &s.Priority, &s.FindingsNew, &s.FindingsTotal,
		&s.FindingsCritical, &s.FindingsHigh, &s.FindingsMedium, &s.FindingsLow, &s.FindingsInfo,
		&s.DurationMs, &s.Error,
		&s.TriggeredBy, &s.StartedAt, &s.CompletedAt, &s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrScanNotFound
		}
		return nil, fmt.Errorf("scan scan: %w", err)
	}
	return s, nil
}
