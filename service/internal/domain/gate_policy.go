package domain

import (
	"time"

	"github.com/google/uuid"
)

// GateMode is what a security finding does to a deploy.
type GateMode string

const (
	GateModeEnforce GateMode = "enforce" // block the deploy
	GateModeWarn    GateMode = "warn"    // record findings on the approval, proceed
	GateModeOff     GateMode = "off"     // skip the scan entirely
)

func (m GateMode) Valid() bool {
	switch m {
	case GateModeEnforce, GateModeWarn, GateModeOff:
		return true
	}
	return false
}

// ValidGateThreshold reports whether s can gate a deploy.
// The gate ladder is the finding Severity ladder minus info — info never gates.
func ValidGateThreshold(s Severity) bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		return true
	}
	return false
}

// GatePolicy is the org-level policy. At most one row per tenant; absence
// means the org has not set a policy.
type GatePolicy struct {
	TenantID          uuid.UUID `json:"tenant_id"`
	Mode              GateMode  `json:"mode"`
	SeverityThreshold Severity  `json:"severity_threshold"`
	Locked            bool      `json:"locked"`
	UpdatedBy         uuid.UUID `json:"updated_by"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

func (p *GatePolicy) Validate() error {
	if !p.Mode.Valid() {
		return ErrInvalidGatePolicy
	}
	if !ValidGateThreshold(p.SeverityThreshold) {
		return ErrInvalidGatePolicy
	}
	if p.UpdatedBy == uuid.Nil {
		return ErrInvalidGatePolicy
	}
	return nil
}

// GateUserPref is one member's personal default. Absence = no preference.
type GateUserPref struct {
	TenantID          uuid.UUID `json:"tenant_id"`
	UserID            uuid.UUID `json:"user_id"`
	Mode              GateMode  `json:"mode"`
	SeverityThreshold Severity  `json:"severity_threshold"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

func (p *GateUserPref) Validate() error {
	if !p.Mode.Valid() {
		return ErrInvalidGatePolicy
	}
	if !ValidGateThreshold(p.SeverityThreshold) {
		return ErrInvalidGatePolicy
	}
	return nil
}

// GatePolicySource says which layer produced the resolved policy.
type GatePolicySource string

const (
	GateSourceOrg        GatePolicySource = "org"         // org policy, locked
	GateSourceUser       GatePolicySource = "user"        // user preference
	GateSourceOrgDefault GatePolicySource = "org_default" // org policy, unlocked, user has none
	GateSourceUnset      GatePolicySource = "unset"       // nothing configured — caller applies its platform default
)

// ResolvedGatePolicy is the outcome of the precedence walk.
type ResolvedGatePolicy struct {
	Set               bool             `json:"set"`
	Mode              GateMode         `json:"mode"`
	SeverityThreshold Severity         `json:"severity_threshold"`
	Source            GatePolicySource `json:"source"`
}

// ResolveGatePolicy is the PURE precedence function (design §4):
//
//	org set && org.Locked → org (source=org)
//	user set              → user (source=user)
//	org set (unlocked)    → org (source=org_default)
//	neither               → Set=false (source=unset)
//
// nil pointers mean "not configured". No I/O, no clock — table-driven-testable.
func ResolveGatePolicy(org *GatePolicy, user *GateUserPref) ResolvedGatePolicy {
	if org != nil && org.Locked {
		return ResolvedGatePolicy{
			Set:               true,
			Mode:              org.Mode,
			SeverityThreshold: org.SeverityThreshold,
			Source:            GateSourceOrg,
		}
	}
	if user != nil {
		return ResolvedGatePolicy{
			Set:               true,
			Mode:              user.Mode,
			SeverityThreshold: user.SeverityThreshold,
			Source:            GateSourceUser,
		}
	}
	if org != nil {
		return ResolvedGatePolicy{
			Set:               true,
			Mode:              org.Mode,
			SeverityThreshold: org.SeverityThreshold,
			Source:            GateSourceOrgDefault,
		}
	}
	return ResolvedGatePolicy{Set: false, Source: GateSourceUnset}
}
