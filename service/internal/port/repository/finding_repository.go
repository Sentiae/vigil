package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/sentiae/vigil/service/internal/domain"
)

// FindingFilter holds the filter criteria for listing findings.
type FindingFilter struct {
	TenantID     uuid.UUID
	Severity     *domain.Severity
	Status       *domain.FindingStatus
	AnalysisType *domain.AnalysisType
	Category     string
	Limit        int
	Offset       int
}

// FindingRepository defines the data access interface for findings.
type FindingRepository interface {
	Create(ctx context.Context, finding *domain.Finding) error
	Update(ctx context.Context, finding *domain.Finding) error
	FindByID(ctx context.Context, tenantID, id uuid.UUID) (*domain.Finding, error)
	FindByFingerprint(ctx context.Context, tenantID uuid.UUID, fingerprint string) (*domain.Finding, error)
	List(ctx context.Context, filter FindingFilter) ([]*domain.Finding, int, error)
	UpdateLastSeen(ctx context.Context, tenantID uuid.UUID, fingerprint string) error
	BulkUpsert(ctx context.Context, findings []*domain.Finding) (created int, updated int, err error)
	CountBySeverity(ctx context.Context, tenantID uuid.UUID) (map[domain.Severity]int, error)
	UpdateStatus(ctx context.Context, tenantID, id uuid.UUID, status domain.FindingStatus) error
	ListSLABreached(ctx context.Context, tenantID uuid.UUID) ([]*domain.Finding, error)
	ListAllSLABreached(ctx context.Context, limit int) ([]*domain.Finding, error)
	ListActiveTenantIDs(ctx context.Context) ([]uuid.UUID, error)
}
