package domain

import "errors"

// Sentinel errors for the vigil domain.
var (
	// Finding errors
	ErrFindingNotFound    = errors.New("finding not found")
	ErrDuplicateFinding   = errors.New("duplicate finding")
	ErrInvalidFingerprint = errors.New("invalid fingerprint")
	ErrInvalidFinding     = errors.New("invalid finding")

	// Scan errors
	ErrScanNotFound  = errors.New("scan not found")
	ErrScanInProgress = errors.New("scan already in progress for this target")
	ErrInvalidScan   = errors.New("invalid scan")

	// Asset errors
	ErrAssetNotFound = errors.New("asset not found")
	ErrInvalidAsset  = errors.New("invalid asset")

	// Policy errors
	ErrPolicyNotFound = errors.New("policy not found")
	ErrInvalidPolicy  = errors.New("invalid policy")

	// SLA errors
	ErrSLABreached = errors.New("SLA deadline breached")

	// Agent errors
	ErrAgentNotFound       = errors.New("agent not found")
	ErrAgentAlreadyExists  = errors.New("agent already registered")
	ErrInvalidBootstrapToken = errors.New("invalid bootstrap token")

	// General
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
	ErrNotFound     = errors.New("not found")
)
