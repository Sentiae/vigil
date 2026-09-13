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
	// CountSLABreached counts the tenant's open findings whose SLA deadline has
	// passed. Read-only: it never claims or consumes a breach transition.
	CountSLABreached(ctx context.Context, tenantID uuid.UUID) (int, error)
	// ClaimSLABreaches marks every open finding of tenantID whose SLA deadline
	// has passed and whose breach has not yet been emitted for that deadline as
	// emitted, and returns exactly those findings. Called inside a transaction,
	// the claim commits only together with the caller's outbox rows; a finding
	// whose deadline later changes is claimable again.
	ClaimSLABreaches(ctx context.Context, tenantID uuid.UUID) ([]*domain.Finding, error)
	ListAllSLABreached(ctx context.Context, limit int) ([]*domain.Finding, error)
	ListActiveTenantIDs(ctx context.Context) ([]uuid.UUID, error)
}
