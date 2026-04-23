package domain

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// AssetType represents the category of a discovered asset.
type AssetType string

const (
	AssetTypeRepository  AssetType = "repository"
	AssetTypeContainer   AssetType = "container"
	AssetTypeService     AssetType = "service"
	AssetTypeCloudResource AssetType = "cloud_resource"
	AssetTypeDatabase    AssetType = "database"
	AssetTypeNetwork     AssetType = "network"
	AssetTypeHost        AssetType = "host"
)

func (t AssetType) Valid() bool {
	switch t {
	case AssetTypeRepository, AssetTypeContainer, AssetTypeService,
		AssetTypeCloudResource, AssetTypeDatabase, AssetTypeNetwork, AssetTypeHost:
		return true
	}
	return false
}

// AssetCriticality represents the business importance of an asset.
type AssetCriticality string

const (
	CriticalityVeryHigh AssetCriticality = "very_high"
	CriticalityHigh     AssetCriticality = "high"
	CriticalityMedium   AssetCriticality = "medium"
	CriticalityLow      AssetCriticality = "low"
	CriticalityVeryLow  AssetCriticality = "very_low"
)

// Asset represents a discoverable entity in the customer's environment.
type Asset struct {
	ID             uuid.UUID        `json:"id"`
	TenantID       uuid.UUID        `json:"tenant_id"`
	Type           AssetType        `json:"asset_type"`
	Name           string           `json:"name"`
	CloudProvider  string           `json:"cloud_provider,omitempty"`
	CloudAccountID string           `json:"cloud_account_id,omitempty"`
	CloudRegion    string           `json:"cloud_region,omitempty"`
	ARN            string           `json:"arn,omitempty"`
	Criticality    AssetCriticality `json:"criticality"`
	Environment    string           `json:"environment,omitempty"`
	InternetFacing bool             `json:"internet_facing"`
	PIIHandling    bool             `json:"pii_handling"`
	Tags           map[string]string `json:"tags,omitempty"`
	LastScannedAt  *time.Time       `json:"last_scanned_at,omitempty"`
	CreatedAt      time.Time        `json:"created_at"`
	UpdatedAt      time.Time        `json:"updated_at"`
}

// Validate checks that the asset has all required fields.
func (a *Asset) Validate() error {
	if a.TenantID == uuid.Nil {
		return fmt.Errorf("%w: tenant_id is required", ErrInvalidAsset)
	}
	if !a.Type.Valid() {
		return fmt.Errorf("%w: invalid asset_type %q", ErrInvalidAsset, a.Type)
	}
	if a.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidAsset)
	}
	return nil
}

// CriticalityScore returns a numeric score (0-100) for the asset's criticality.
func (a *Asset) CriticalityScore() float64 {
	switch a.Criticality {
	case CriticalityVeryHigh:
		return 100
	case CriticalityHigh:
		return 80
	case CriticalityMedium:
		return 60
	case CriticalityLow:
		return 40
	case CriticalityVeryLow:
		return 20
	default:
		return 50
	}
}

// ExposureScore returns a score (0-100) based on the asset's exposure profile.
func (a *Asset) ExposureScore() float64 {
	score := 0.0
	if a.InternetFacing {
		score += 50
	}
	if a.Environment == "production" {
		score += 30
	}
	if a.PIIHandling {
		score += 20
	}
	return score
}
