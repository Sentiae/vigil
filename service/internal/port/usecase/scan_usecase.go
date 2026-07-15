package usecase

import (
	"context"

	"github.com/google/uuid"
	"github.com/sentiae/vigil/service/internal/domain"
	"github.com/sentiae/vigil/service/internal/port/repository"
)

// TriggerScanInput represents the input for triggering a new scan.
type TriggerScanInput struct {
	TenantID  uuid.UUID       `json:"tenant_id"`
	ScanType  domain.ScanType `json:"scan_type"`
	Target    string          `json:"target"`
	Branch    string          `json:"branch,omitempty"`
	Priority  string          `json:"priority,omitempty"`
	TriggeredBy string        `json:"triggered_by"`
	// RegistryPullToken is a short-lived registry Basic-auth password used by
	// the worker to pull a private image target. It is never persisted — it
	// travels only in the in-memory asynq task payload.
	RegistryPullToken string  `json:"-"`
}

// ScanUseCase defines the business logic interface for scans.
type ScanUseCase interface {
	TriggerScan(ctx context.Context, input TriggerScanInput) (*domain.Scan, error)
	GetScan(ctx context.Context, tenantID, id uuid.UUID) (*domain.Scan, error)
	ListScans(ctx context.Context, filter repository.ScanFilter) ([]*domain.Scan, int, error)
}
