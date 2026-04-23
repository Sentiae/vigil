package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentiae/vigil/service/internal/domain"
	"github.com/sentiae/vigil/service/internal/port/repository"
)

type coverageRepository struct {
	pool *pgxpool.Pool
}

// NewCoverageRepository constructs a pgx-backed CoverageRepository.
func NewCoverageRepository(pool *pgxpool.Pool) repository.CoverageRepository {
	return &coverageRepository{pool: pool}
}

func (r *coverageRepository) Insert(ctx context.Context, rep *domain.CoverageReport) error {
	if rep.ID == uuid.Nil {
		rep.ID = uuid.New()
	}
	filesJSON, err := json.Marshal(rep.Files)
	if err != nil {
		return fmt.Errorf("marshal files: %w", err)
	}
	_, err = r.pool.Exec(ctx, `
		INSERT INTO coverage_reports (id, tenant_id, repo_id, commit_sha, branch, format, files, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, rep.ID, rep.OrgID, rep.RepoID, rep.CommitSHA, rep.Branch, string(rep.Format), filesJSON, rep.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert coverage: %w", err)
	}
	return nil
}

func (r *coverageRepository) GetLatest(ctx context.Context, tenantID uuid.UUID, repoID string) (*domain.CoverageReport, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT id, tenant_id, repo_id, commit_sha, branch, format, files, created_at
		FROM coverage_reports
		WHERE tenant_id = $1 AND repo_id = $2
		ORDER BY created_at DESC
		LIMIT 1
	`, tenantID, repoID)
	var rep domain.CoverageReport
	var filesJSON []byte
	var format string
	if err := row.Scan(&rep.ID, &rep.OrgID, &rep.RepoID, &rep.CommitSHA, &rep.Branch, &format, &filesJSON, &rep.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("query coverage: %w", err)
	}
	rep.Format = domain.CoverageFormat(format)
	if err := json.Unmarshal(filesJSON, &rep.Files); err != nil {
		return nil, fmt.Errorf("unmarshal files: %w", err)
	}
	return &rep, nil
}
