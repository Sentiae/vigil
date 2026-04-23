package repository

import (
	"context"

	"github.com/google/uuid"

	"github.com/sentiae/vigil/service/internal/domain"
)

// CoverageRepository persists Phase-8 coverage reports.
type CoverageRepository interface {
	// Insert creates a new report row. IDs are expected to be set by
	// the caller so tests can assert stable values.
	Insert(ctx context.Context, r *domain.CoverageReport) error

	// GetLatest returns the most recent report for (tenant, repo), or
	// nil when nothing has been ingested yet.
	GetLatest(ctx context.Context, tenantID uuid.UUID, repoID string) (*domain.CoverageReport, error)
}
