package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/sentiae/vigil/service/internal/domain"
)

// ScanFilter holds the filter criteria for listing scans.
type ScanFilter struct {
	TenantID uuid.UUID
	Status   *domain.ScanStatus
	Type     *domain.ScanType
	Limit    int
	Offset   int
}

// ScanRepository defines the data access interface for scans.
type ScanRepository interface {
	Create(ctx context.Context, scan *domain.Scan) error
	Update(ctx context.Context, scan *domain.Scan) error
	FindByID(ctx context.Context, tenantID, id uuid.UUID) (*domain.Scan, error)
	List(ctx context.Context, filter ScanFilter) ([]*domain.Scan, int, error)
	UpdateStatus(ctx context.Context, tenantID, id uuid.UUID, status domain.ScanStatus) error
}
