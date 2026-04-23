package usecase

import (
	"context"
	"math"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sentiae/vigil/service/internal/domain"
	"github.com/sentiae/vigil/service/internal/port/repository"
	"github.com/sentiae/vigil/service/pkg/events"
	"github.com/sentiae/vigil/service/pkg/logger"
	"github.com/sentiae/vigil/service/pkg/telemetry"
)

// SLAService monitors findings for SLA deadline breaches and publishes events.
type SLAService struct {
	findingRepo repository.FindingRepository
	publisher   events.Publisher
	stopOnce    sync.Once
	stopCh      chan struct{}
}

func NewSLAService(
	findingRepo repository.FindingRepository,
	publisher events.Publisher,
) *SLAService {
	return &SLAService{
		findingRepo: findingRepo,
		publisher:   publisher,
		stopCh:      make(chan struct{}),
	}
}

// Start begins the SLA enforcement loop, checking every interval.
func (s *SLAService) Start(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}

	logger.Info(ctx, "SLA enforcement started", "interval", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.checkBreaches(ctx)
		case <-s.stopCh:
			logger.Info(ctx, "SLA enforcement stopped")
			return
		case <-ctx.Done():
			logger.Info(ctx, "SLA enforcement stopped (context cancelled)")
			return
		}
	}
}

// Stop signals the SLA enforcement loop to stop. Safe to call multiple times.
func (s *SLAService) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
}

func (s *SLAService) checkBreaches(ctx context.Context) {
	tenantIDs, err := s.findingRepo.ListActiveTenantIDs(ctx)
	if err != nil {
		logger.Error(ctx, "Failed to list active tenants for SLA check", "error", err)
		return
	}

	totalBreached := 0
	for _, tenantID := range tenantIDs {
		count, err := s.CheckTenantSLABreaches(ctx, tenantID)
		if err != nil {
			logger.Error(ctx, "SLA check failed for tenant", "tenant_id", tenantID, "error", err)
			continue
		}
		totalBreached += count
	}

	if totalBreached > 0 {
		telemetry.SLABreachesTotal.Add(float64(totalBreached))
		logger.Warn(ctx, "SLA breaches found", "total_breached", totalBreached, "tenants_checked", len(tenantIDs))
	} else {
		logger.Debug(ctx, "SLA check complete, no breaches", "tenants_checked", len(tenantIDs))
	}
}

// CheckTenantSLABreaches checks and publishes SLA breach events for a specific tenant.
func (s *SLAService) CheckTenantSLABreaches(ctx context.Context, tenantID uuid.UUID) (int, error) {
	breached, err := s.findingRepo.ListSLABreached(ctx, tenantID)
	if err != nil {
		return 0, err
	}

	if len(breached) == 0 {
		return 0, nil
	}

	now := time.Now()
	for _, f := range breached {
		if f.SLADeadline == nil {
			continue
		}

		daysOverdue := int(math.Ceil(now.Sub(*f.SLADeadline).Hours() / 24))
		if daysOverdue < 0 {
			continue
		}

		if s.publisher != nil {
			_ = s.publisher.Publish(ctx, events.EventFindingSLABreach, events.EventData{
				ActorType:    "system",
				ResourceType: "finding",
				ResourceID:   f.ID.String(),
				Metadata: map[string]any{
					"finding_id":   f.ID.String(),
					"severity":     string(f.Severity),
					"days_overdue": daysOverdue,
					"sla_deadline": f.SLADeadline.Format(time.RFC3339),
					"title":        f.Title,
				},
				Timestamp: now,
			})
		}

		logger.Warn(ctx, "SLA breach detected",
			"finding_id", f.ID,
			"severity", f.Severity,
			"days_overdue", daysOverdue,
		)
	}

	return len(breached), nil
}

// AssignSLADeadline sets the SLA deadline on a finding based on severity and environment.
func AssignSLADeadline(f *domain.Finding, isProduction bool) {
	policies := domain.DefaultSLAPolicies()
	for _, p := range policies {
		if p.Severity == f.Severity {
			deadline := f.FirstSeenAt
			if isProduction {
				deadline = deadline.Add(p.ProductionDeadline)
			} else {
				deadline = deadline.Add(p.NonProductionDeadline)
			}
			f.SLADeadline = &deadline
			return
		}
	}
}
