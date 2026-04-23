package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/sentiae/vigil/service/internal/domain"
	"github.com/sentiae/vigil/service/internal/port/repository"
	portuc "github.com/sentiae/vigil/service/internal/port/usecase"
	"github.com/sentiae/vigil/service/pkg/events"
	"github.com/sentiae/vigil/service/pkg/logger"
)

type findingService struct {
	findingRepo   repository.FindingRepository
	analyticsRepo repository.AnalyticsRepository
	publisher     events.Publisher
	scoring       *ScoringService
	policy        *PolicyService
}

func NewFindingService(
	findingRepo repository.FindingRepository,
	analyticsRepo repository.AnalyticsRepository,
	publisher events.Publisher,
	scoring *ScoringService,
	policy *PolicyService,
) portuc.FindingUseCase {
	return &findingService{
		findingRepo:   findingRepo,
		analyticsRepo: analyticsRepo,
		publisher:     publisher,
		scoring:       scoring,
		policy:        policy,
	}
}

func (s *findingService) GetFinding(ctx context.Context, tenantID, id uuid.UUID) (*domain.Finding, error) {
	return s.findingRepo.FindByID(ctx, tenantID, id)
}

func (s *findingService) ListFindings(ctx context.Context, filter repository.FindingFilter) ([]*domain.Finding, int, error) {
	return s.findingRepo.List(ctx, filter)
}

func (s *findingService) ResolveFinding(ctx context.Context, tenantID uuid.UUID, input portuc.ResolveFindingInput) (*domain.Finding, error) {
	finding, err := s.findingRepo.FindByID(ctx, tenantID, input.FindingID)
	if err != nil {
		return nil, err
	}

	if !input.Resolution.Valid() || !input.Resolution.IsTerminal() {
		return nil, fmt.Errorf("%w: resolution must be resolved, false_positive, or risk_accepted", domain.ErrInvalidFinding)
	}

	oldStatus := finding.Status
	finding.Status = input.Resolution
	finding.LastSeenAt = time.Now()

	if err := s.findingRepo.Update(ctx, finding); err != nil {
		return nil, fmt.Errorf("update finding: %w", err)
	}

	if s.publisher != nil {
		go func() {
			publishCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = s.publisher.Publish(publishCtx, events.EventFindingResolved, events.EventData{
				ActorID:      input.ResolvedBy,
				ActorType:    "user",
				ResourceType: "finding",
				ResourceID:   finding.ID.String(),
				Metadata: map[string]any{
					"finding_id": finding.ID.String(),
					"old_status": string(oldStatus),
					"new_status": string(finding.Status),
					"resolution": string(input.Resolution),
					"note":       input.Note,
				},
				Timestamp: time.Now(),
			})
			cancel()
		}()
	}

	return finding, nil
}

func (s *findingService) IngestFindings(ctx context.Context, tenantID uuid.UUID, findings []*domain.Finding) (int, int, error) {
	now := time.Now()
	for _, f := range findings {
		f.TenantID = tenantID
		if f.Fingerprint == "" {
			f.Fingerprint = f.ComputeFingerprint()
		}
		if f.Status == "" {
			f.Status = domain.FindingStatusNew
		}
		if f.FirstSeenAt.IsZero() {
			f.FirstSeenAt = now
		}
		f.LastSeenAt = now

		// Apply compliance mappings
		if s.policy != nil {
			refs := s.policy.EvaluateFinding(ctx, f)
			if len(refs) > 0 {
				f.ComplianceMappings = refs
			}
		}

		// Compute composite score
		if s.scoring != nil {
			f.NormalizedScore = s.scoring.ScoreFinding(ctx, f, nil)
		}

		// Assign SLA deadline if not set
		if f.SLADeadline == nil {
			AssignSLADeadline(f, true) // default to production SLA
		}
	}

	created, updated, err := s.findingRepo.BulkUpsert(ctx, findings)
	if err != nil {
		return 0, 0, fmt.Errorf("bulk upsert: %w", err)
	}

	// Write to ClickHouse analytics (async, non-blocking)
	if s.analyticsRepo != nil {
		go func() {
			if err := s.analyticsRepo.InsertFindings(context.Background(), findings); err != nil {
				logger.Warn(ctx, "Failed to write findings to ClickHouse", "error", err)
			}
		}()
	}

	// Publish events for findings
	if s.publisher != nil {
		for _, f := range findings {
			eventType := events.EventFindingCreated
			if f.Severity == domain.SeverityCritical {
				eventType = events.EventAlertCritical
			}

			// Verified secret detection gets its own high-priority event
			if f.AnalysisType == domain.AnalysisTypeSecretDetection {
				if verified, ok := f.Metadata["verified"].(bool); ok && verified {
					_ = s.publisher.Publish(ctx, events.EventSecretDetected, events.EventData{
						ActorType:    "system",
						ResourceType: "finding",
						ResourceID:   f.ID.String(),
						Metadata: map[string]any{
							"finding_id":  f.ID.String(),
							"secret_type": f.SourceRuleID,
							"verified":    true,
							"repository":  f.Location.Repository,
							"file_path":   f.Location.FilePath,
							"commit_sha":  f.Location.CommitSHA,
						},
						Timestamp: now,
					})
				}
			}

			meta := map[string]any{
				"finding_id":       f.ID.String(),
				"severity":         string(f.Severity),
				"analysis_type":    string(f.AnalysisType),
				"normalized_score": f.NormalizedScore,
				"title":            f.Title,
				"category":         f.Category,
				"source_scanner":   f.SourceScanner,
			}
			if len(f.CVEs) > 0 {
				meta["cves"] = f.CVEs
			}
			if f.EPSSScore != nil {
				meta["epss_score"] = *f.EPSSScore
			}
			if f.CVSSScore != nil {
				meta["cvss_score"] = *f.CVSSScore
			}

			if err := s.publisher.Publish(ctx, eventType, events.EventData{
				ActorType:    "system",
				ResourceType: "finding",
				ResourceID:   f.ID.String(),
				Metadata:     meta,
				Timestamp:    now,
			}); err != nil {
				logger.Warn(ctx, "Failed to publish finding event", "error", err)
			}
		}
	}

	return created, updated, nil
}

func (s *findingService) CountBySeverity(ctx context.Context, tenantID uuid.UUID) (map[domain.Severity]int, error) {
	return s.findingRepo.CountBySeverity(ctx, tenantID)
}
