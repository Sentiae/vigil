package usecase

import (
	"context"
	"encoding/json"
	"fmt"
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

// SLAService turns SLA deadline breaches into transitions. Each (finding,
// deadline) breach is claimed once and its event appended to the transactional
// outbox in the same transaction; the outbox relay publishes and retries. An
// unchanged overdue finding is not re-emitted by later scans; a changed deadline
// is a new transition.
type SLAService struct {
	findingRepo repository.FindingRepository
	txManager   repository.TransactionManager
	outbox      repository.OutboxWriter
	clock       Clock
	stopOnce    sync.Once
	stopCh      chan struct{}
}

func NewSLAService(
	findingRepo repository.FindingRepository,
	txManager repository.TransactionManager,
	outbox repository.OutboxWriter,
	clock Clock,
) *SLAService {
	return &SLAService{
		findingRepo: findingRepo,
		txManager:   txManager,
		outbox:      outbox,
		clock:       clock,
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

	newTransitions := 0
	for _, tenantID := range tenantIDs {
		count, err := s.CheckTenantSLABreaches(ctx, tenantID)
		if err != nil {
			logger.Error(ctx, "SLA breach claim failed for tenant", "tenant_id", tenantID, "error", err)
			continue
		}
		newTransitions += count
	}

	if newTransitions > 0 {
		telemetry.SLABreachesTotal.Add(float64(newTransitions))
		logger.Warn(ctx, "SLA breach transitions claimed", "new_transitions", newTransitions, "tenants_checked", len(tenantIDs))
	} else {
		logger.Debug(ctx, "SLA check complete, no new breach transitions", "tenants_checked", len(tenantIDs))
	}
}

// CheckTenantSLABreaches claims the tenant's new (finding, deadline) breaches and
// appends one outbox event per claim, all in one transaction. It returns the
// number of committed transitions; on error nothing is claimed or appended.
func (s *SLAService) CheckTenantSLABreaches(ctx context.Context, tenantID uuid.UUID) (int, error) {
	claimed := 0
	err := s.txManager.WithTransaction(ctx, func(txCtx context.Context) error {
		breached, err := s.findingRepo.ClaimSLABreaches(txCtx, tenantID)
		if err != nil {
			return fmt.Errorf("claim sla breaches: %w", err)
		}
		now := s.clock.Now()
		for _, f := range breached {
			event, err := slaBreachOutboxEvent(f, now)
			if err != nil {
				return err
			}
			if err := s.outbox.Append(txCtx, event); err != nil {
				return fmt.Errorf("append sla breach event for finding %s: %w", f.ID, err)
			}
		}
		claimed = len(breached)
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("sla breach transaction for tenant %s: %w", tenantID, err)
	}
	return claimed, nil
}

// slaBreachOutboxEvent builds the security.finding.sla_breach outbox row for a
// claimed finding. The relay unmarshals Payload back into events.EventData.
func slaBreachOutboxEvent(f *domain.Finding, now time.Time) (*repository.OutboxEvent, error) {
	if f.SLADeadline == nil {
		return nil, fmt.Errorf("claimed finding %s has no sla deadline", f.ID)
	}
	daysOverdue := int(math.Ceil(now.Sub(*f.SLADeadline).Hours() / 24))
	payload, err := json.Marshal(events.EventData{
		ActorType:      "system",
		ResourceType:   "finding",
		ResourceID:     f.ID.String(),
		OrganizationID: f.TenantID.String(),
		Metadata: map[string]any{
			"finding_id":   f.ID.String(),
			"severity":     string(f.Severity),
			"days_overdue": daysOverdue,
			"sla_deadline": f.SLADeadline.Format(time.RFC3339),
			"title":        f.Title,
		},
		Timestamp: now,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal sla breach event for finding %s: %w", f.ID, err)
	}
	return &repository.OutboxEvent{
		EventType: events.EventFindingSLABreach,
		Payload:   payload,
		CreatedAt: now,
	}, nil
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
