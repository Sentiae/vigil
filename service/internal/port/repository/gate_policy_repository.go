package repository

import (
	"context"

	"github.com/google/uuid"

	"github.com/sentiae/vigil/service/internal/domain"
)

// GatePolicyRepository persists the deploy-gate org policy and the per-user
// preference (docs/designs/security-gate-policy.md §4).
type GatePolicyRepository interface {
	// UpsertPolicy inserts or fully updates the org row (one row per tenant).
	UpsertPolicy(ctx context.Context, p *domain.GatePolicy) error
	// FindPolicy returns domain.ErrGatePolicyNotFound when the org has no row.
	FindPolicy(ctx context.Context, tenantID uuid.UUID) (*domain.GatePolicy, error)
	// DeletePolicy removes the org row; no-op (nil) if absent.
	DeletePolicy(ctx context.Context, tenantID uuid.UUID) error
	UpsertUserPref(ctx context.Context, p *domain.GateUserPref) error
	// FindUserPref returns domain.ErrGateUserPrefNotFound when absent.
	FindUserPref(ctx context.Context, tenantID, userID uuid.UUID) (*domain.GateUserPref, error)
	DeleteUserPref(ctx context.Context, tenantID, userID uuid.UUID) error
}
