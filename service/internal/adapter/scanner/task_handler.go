package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/hibiken/asynq"

	"github.com/sentiae/vigil/service/internal/domain"
	portscanner "github.com/sentiae/vigil/service/internal/port/scanner"
	portuc "github.com/sentiae/vigil/service/internal/port/usecase"
	"github.com/sentiae/vigil/service/internal/port/repository"
	"github.com/sentiae/vigil/service/pkg/events"
	"github.com/sentiae/vigil/service/pkg/logger"
	"github.com/sentiae/vigil/service/pkg/telemetry"
)

// ScanTaskPayload is the JSON payload for scan tasks in the asynq queue.
type ScanTaskPayload struct {
	ScanID   string `json:"scan_id"`
	TenantID string `json:"tenant_id"`
	Target   string `json:"target"`
	Branch   string `json:"branch"`
}

// TaskHandler handles asynq scan tasks by running the appropriate scanners.
type TaskHandler struct {
	registry    *Registry
	findingUC   portuc.FindingUseCase
	scanRepo    repository.ScanRepository
	publisher   events.Publisher
}

// NewTaskHandler creates a new scan task handler.
func NewTaskHandler(
	registry *Registry,
	findingUC portuc.FindingUseCase,
	scanRepo repository.ScanRepository,
	publisher events.Publisher,
) *TaskHandler {
	return &TaskHandler{
		registry:  registry,
		findingUC: findingUC,
		scanRepo:  scanRepo,
		publisher: publisher,
	}
}

// HandleScanTask processes a scan task from the asynq queue.
func (h *TaskHandler) HandleScanTask(scanType domain.ScanType) asynq.HandlerFunc {
	return func(ctx context.Context, t *asynq.Task) error {
		var payload ScanTaskPayload
		if err := json.Unmarshal(t.Payload(), &payload); err != nil {
			return fmt.Errorf("unmarshal payload: %w", err)
		}

		scanID, _ := uuid.Parse(payload.ScanID)
		tenantID, _ := uuid.Parse(payload.TenantID)

		logger.Info(ctx, "Processing scan task",
			"scan_id", scanID, "scan_type", scanType, "target", payload.Target)

		// Mark scan as running
		scan := &domain.Scan{
			ID:       scanID,
			TenantID: tenantID,
			Type:     scanType,
			Target:   payload.Target,
		}
		scan.MarkRunning()
		if err := h.scanRepo.Update(ctx, scan); err != nil {
			logger.Error(ctx, "Failed to mark scan as running", "error", err)
		}

		// Determine target type and prepare scan target
		var target portscanner.ScanTarget

		if isURLTarget(scanType) {
			// DAST/API/endpoint scans target live URLs — no cloning needed
			target = portscanner.ScanTarget{
				Type: "url",
				URI:  payload.Target,
			}
		} else {
			// Code scans need a cloned repository
			localPath, cleanup, err := CloneRepository(ctx, payload.Target, payload.Branch)
			if err != nil {
				scan.MarkFailed(fmt.Sprintf("clone failed: %v", err))
				_ = h.scanRepo.Update(ctx, scan)
				h.publishScanFailed(ctx, scan, err)
				return fmt.Errorf("clone: %w", err)
			}
			defer cleanup()

			target = portscanner.ScanTarget{
				Type:      "repository",
				URI:       payload.Target,
				Branch:    payload.Branch,
				LocalPath: localPath,
			}
		}

		findings, err := h.registry.RunScan(ctx, scanType, target)
		if err != nil {
			scan.MarkFailed(fmt.Sprintf("scan failed: %v", err))
			_ = h.scanRepo.Update(ctx, scan)
			h.publishScanFailed(ctx, scan, err)
			return fmt.Errorf("run scan: %w", err)
		}

		// Ingest findings
		created, updated := 0, 0
		if len(findings) > 0 {
			created, updated, err = h.findingUC.IngestFindings(ctx, tenantID, findings)
			if err != nil {
				logger.Error(ctx, "Failed to ingest findings", "error", err)
			}
		}

		// Mark scan as completed
		scan.MarkCompleted(created, created+updated)
		if err := h.scanRepo.Update(ctx, scan); err != nil {
			logger.Error(ctx, "Failed to mark scan as completed", "error", err)
		}

		// Record metrics
		telemetry.ScansTotal.WithLabelValues(string(scanType), "completed").Inc()
		telemetry.ScanDuration.WithLabelValues(string(scanType)).Observe(float64(scan.DurationMs) / 1000.0)

		// Publish completion event
		if h.publisher != nil {
			_ = h.publisher.Publish(ctx, events.EventScanCompleted, events.EventData{
				ActorType:    "system",
				ResourceType: "scan",
				ResourceID:   scanID.String(),
				Metadata: map[string]any{
					"scan_id":        scanID.String(),
					"scan_type":      string(scanType),
					"target":         payload.Target,
					"findings_new":   created,
					"findings_total": created + updated,
					"duration_ms":    scan.DurationMs,
				},
				Timestamp: time.Now(),
			})
		}

		logger.Info(ctx, "Scan completed",
			"scan_id", scanID, "findings_new", created, "findings_updated", updated)

		return nil
	}
}

// isURLTarget returns true for scan types that target live URLs instead of git repos.
func isURLTarget(scanType domain.ScanType) bool {
	switch scanType {
	case domain.ScanTypeDAST, domain.ScanTypeEndpointDiscovery, domain.ScanTypeAPITest,
		domain.ScanTypeNetwork, domain.ScanTypeDatabase:
		return true
	}
	return false
}

func (h *TaskHandler) publishScanFailed(ctx context.Context, scan *domain.Scan, scanErr error) {
	if h.publisher == nil {
		return
	}
	_ = h.publisher.Publish(ctx, events.EventScanFailed, events.EventData{
		ActorType:    "system",
		ResourceType: "scan",
		ResourceID:   scan.ID.String(),
		Metadata: map[string]any{
			"scan_id":   scan.ID.String(),
			"scan_type": string(scan.Type),
			"target":    scan.Target,
			"error":     scanErr.Error(),
		},
		Timestamp: time.Now(),
	})
}
