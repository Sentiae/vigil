package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/sentiae/vigil/service/internal/domain"
)

// AssetFilter holds the filter criteria for listing assets.
type AssetFilter struct {
	TenantID uuid.UUID
	Type     *domain.AssetType
	Limit    int
	Offset   int
}

// AssetRepository defines the data access interface for assets.
type AssetRepository interface {
	Create(ctx context.Context, asset *domain.Asset) error
	Update(ctx context.Context, asset *domain.Asset) error
	FindByID(ctx context.Context, tenantID, id uuid.UUID) (*domain.Asset, error)
	FindByARN(ctx context.Context, tenantID uuid.UUID, arn string) (*domain.Asset, error)
	List(ctx context.Context, filter AssetFilter) ([]*domain.Asset, int, error)
}
