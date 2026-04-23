package usecase

import (
	"context"

	"github.com/google/uuid"
	"github.com/sentiae/vigil/service/internal/domain"
	"github.com/sentiae/vigil/service/internal/port/repository"
)

// ResolveFindingInput represents the input for resolving a finding.
type ResolveFindingInput struct {
	FindingID  uuid.UUID            `json:"finding_id"`
	Resolution domain.FindingStatus `json:"resolution"` // resolved, false_positive, risk_accepted
	Note       string               `json:"note"`
	ResolvedBy string               `json:"resolved_by"`
}

// FindingUseCase defines the business logic interface for findings.
type FindingUseCase interface {
	GetFinding(ctx context.Context, tenantID, id uuid.UUID) (*domain.Finding, error)
	ListFindings(ctx context.Context, filter repository.FindingFilter) ([]*domain.Finding, int, error)
	ResolveFinding(ctx context.Context, tenantID uuid.UUID, input ResolveFindingInput) (*domain.Finding, error)
	IngestFindings(ctx context.Context, tenantID uuid.UUID, findings []*domain.Finding) (created int, updated int, err error)
	CountBySeverity(ctx context.Context, tenantID uuid.UUID) (map[domain.Severity]int, error)
}
