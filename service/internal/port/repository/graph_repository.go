package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/sentiae/vigil/service/internal/domain"
)

// AssetRelationship represents an edge in the asset graph.
type AssetRelationship struct {
	FromAssetID uuid.UUID `json:"from_asset_id"`
	ToAssetID   uuid.UUID `json:"to_asset_id"`
	Type        string    `json:"type"` // depends_on, deployed_to, connects_to, authenticates_with
}

// BlastRadius represents the impact analysis from a compromised asset.
type BlastRadius struct {
	SourceAssetID  uuid.UUID       `json:"source_asset_id"`
	AffectedAssets []*domain.Asset `json:"affected_assets"`
	ImpactScore    float64         `json:"impact_score"`
	Depth          int             `json:"depth"`
}

// AttackPath represents a path from an exposed asset to a sensitive target.
type AttackPath struct {
	ID          uuid.UUID       `json:"id"`
	Steps       []*domain.Asset `json:"steps"`
	Likelihood  string          `json:"likelihood"` // high, medium, low
	Severity    domain.Severity `json:"severity"`
}

// GraphRepository defines the interface for the Neo4j asset graph layer.
type GraphRepository interface {
	CreateAsset(ctx context.Context, asset *domain.Asset) error
	UpdateAsset(ctx context.Context, asset *domain.Asset) error
	CreateRelationship(ctx context.Context, rel AssetRelationship) error
	BlastRadius(ctx context.Context, tenantID, assetID uuid.UUID, maxDepth int) (*BlastRadius, error)
	AttackPaths(ctx context.Context, tenantID, assetID uuid.UUID) ([]*AttackPath, error)
}
