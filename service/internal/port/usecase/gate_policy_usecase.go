package usecase

import (
	"context"

	"github.com/google/uuid"

	"github.com/sentiae/vigil/service/internal/domain"
)

// SetGatePolicyInput is a partial update of the org policy: only fields whose
// Set* guard is true are applied (the identity eve_org.proto set_-guard
// semantics). Clear deletes the row outright.
type SetGatePolicyInput struct {
	TenantID  uuid.UUID
	UpdatedBy uuid.UUID
	Clear     bool // true: delete the org row; Set* fields ignored

	SetMode bool
	Mode    domain.GateMode

	SetSeverityThreshold bool
	SeverityThreshold    domain.Severity

	SetLocked bool
	Locked    bool
}

// SetGateUserPrefInput is the same partial-update shape for a member's
// personal preference.
type SetGateUserPrefInput struct {
	TenantID uuid.UUID
	UserID   uuid.UUID
	Clear    bool

	SetMode bool
	Mode    domain.GateMode

	SetSeverityThreshold bool
	SeverityThreshold    domain.Severity
}

// GatePolicyUseCase is the deploy-gate policy surface: delivery reads Resolve,
// the BFF drives the Get/Set pairs.
type GatePolicyUseCase interface {
	// Resolve walks the precedence ladder. userID == uuid.Nil means "no user
	// layer" (delivery's codegen path has no requester) — not an error.
	Resolve(ctx context.Context, tenantID, userID uuid.UUID) (domain.ResolvedGatePolicy, error)
	GetPolicy(ctx context.Context, tenantID uuid.UUID) (*domain.GatePolicy, error)    // ErrGatePolicyNotFound when unset
	SetPolicy(ctx context.Context, in SetGatePolicyInput) (*domain.GatePolicy, error) // returns nil after Clear
	GetUserPref(ctx context.Context, tenantID, userID uuid.UUID) (*domain.GateUserPref, error)
	SetUserPref(ctx context.Context, in SetGateUserPrefInput) (*domain.GateUserPref, error)
}
