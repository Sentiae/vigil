package usecase

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/hibiken/asynq"

	"github.com/sentiae/vigil/service/internal/domain"
	"github.com/sentiae/vigil/service/internal/port/repository"
	portuc "github.com/sentiae/vigil/service/internal/port/usecase"
	"github.com/sentiae/vigil/service/pkg/events"
	"github.com/sentiae/vigil/service/pkg/logger"
)

// scanTaskPayload is the JSON shape enqueued for the scanner worker. It mirrors
// scanner.ScanTaskPayload (the worker-side decode target); kept local so the
// usecase layer does not import the adapter. RegistryPullToken is a short-lived
// secret carried only in this in-memory task payload — never persisted.
type scanTaskPayload struct {
	ScanID            string `json:"scan_id"`
	TenantID          string `json:"tenant_id"`
	Target            string `json:"target"`
	Branch            string `json:"branch"`
	RegistryPullToken string `json:"registry_pull_token,omitempty"`
}

type scanService struct {
	scanRepo  repository.ScanRepository
	publisher events.Publisher
	asynqClient *asynq.Client
}

func NewScanService(
	scanRepo repository.ScanRepository,
	publisher events.Publisher,
	asynqClient *asynq.Client,
) portuc.ScanUseCase {
	return &scanService{
		scanRepo:    scanRepo,
		publisher:   publisher,
		asynqClient: asynqClient,
	}
}

func (s *scanService) TriggerScan(ctx context.Context, input portuc.TriggerScanInput) (*domain.Scan, error) {
	now := time.Now()

	scan := &domain.Scan{
		ID:          uuid.New(),
		TenantID:    input.TenantID,
		Type:        input.ScanType,
		Target:      input.Target,
		Branch:      input.Branch,
		Status:      domain.ScanStatusQueued,
		Priority:    input.Priority,
		TriggeredBy: input.TriggeredBy,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := scan.Validate(); err != nil {
		return nil, err
	}

	if err := s.scanRepo.Create(ctx, scan); err != nil {
		return nil, fmt.Errorf("create scan: %w", err)
	}

	// Enqueue asynq task for the worker
	if s.asynqClient != nil {
		taskType := fmt.Sprintf("scan:%s", scan.Type)
		// Marshal (not string-interpolate) so a secret registry pull token is
		// escaped correctly and never breaks the JSON payload.
		payload, err := json.Marshal(scanTaskPayload{
			ScanID:            scan.ID.String(),
			TenantID:          scan.TenantID.String(),
			Target:            scan.Target,
			Branch:            scan.Branch,
			RegistryPullToken: input.RegistryPullToken,
		})
		if err != nil {
			return nil, fmt.Errorf("marshal scan task payload: %w", err)
		}

		queue := "default"
		if scan.Priority == "critical" {
			queue = "critical"
		}

		task := asynq.NewTask(taskType, payload)
		if _, err := s.asynqClient.Enqueue(task, asynq.Queue(queue)); err != nil {
			// Fail closed: a scan that never enqueues would sit queued forever and a
			// caller (e.g. the delivery gate) would poll to timeout. Mark it failed
			// and return so the failure is immediate and honest.
			scan.MarkFailed(fmt.Sprintf("enqueue failed: %v", err))
			if uerr := s.scanRepo.Update(ctx, scan); uerr != nil {
				logger.Error(ctx, "Failed to mark scan as failed after enqueue error", "error", uerr, "scan_id", scan.ID)
			}
			return nil, fmt.Errorf("enqueue scan task: %w", err)
		}
	}

	// Publish scan started event (async — don't block the API response)
	if s.publisher != nil {
		go func() {
			publishCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := s.publisher.Publish(publishCtx, events.EventScanStarted, events.EventData{
				ActorID:      input.TriggeredBy,
				ActorType:    "user",
				ResourceType: "scan",
				ResourceID:   scan.ID.String(),
				Metadata: map[string]any{
					"scan_id":   scan.ID.String(),
					"scan_type": string(scan.Type),
					"target":    scan.Target,
				},
				Timestamp: now,
			}); err != nil {
				logger.Warn(publishCtx, "Failed to publish scan started event", "error", err)
			}
		}()
	}

	return scan, nil
}

func (s *scanService) GetScan(ctx context.Context, tenantID, id uuid.UUID) (*domain.Scan, error) {
	return s.scanRepo.FindByID(ctx, tenantID, id)
}

func (s *scanService) ListScans(ctx context.Context, filter repository.ScanFilter) ([]*domain.Scan, int, error) {
	return s.scanRepo.List(ctx, filter)
}
