package usecase

import (
	"context"

	"github.com/google/uuid"
	"github.com/sentiae/vigil/service/internal/domain"
)

// ComplianceUseCase defines the business logic interface for compliance.
type ComplianceUseCase interface {
	GetComplianceSummary(ctx context.Context, tenantID uuid.UUID) (*domain.ComplianceSummary, error)
	GetAssetPosture(ctx context.Context, tenantID, assetID uuid.UUID) (*domain.AssetSecurityPosture, error)
}
