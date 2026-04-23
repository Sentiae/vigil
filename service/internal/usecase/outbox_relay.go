package usecase

import (
	"context"
	"encoding/json"
	"time"

	"github.com/sentiae/vigil/service/internal/port/repository"
	"github.com/sentiae/vigil/service/pkg/events"
	"github.com/sentiae/vigil/service/pkg/logger"
)

// OutboxRelay polls the outbox table for undelivered events and publishes them to Kafka.
// This ensures at-least-once delivery even if Kafka was temporarily unavailable when
// the finding was ingested.
type OutboxRelay struct {
	outboxRepo repository.OutboxRepository
	publisher  events.Publisher
	interval   time.Duration
}

func NewOutboxRelay(outboxRepo repository.OutboxRepository, publisher events.Publisher, interval time.Duration) *OutboxRelay {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	return &OutboxRelay{
		outboxRepo: outboxRepo,
		publisher:  publisher,
		interval:   interval,
	}
}

// Start begins the relay loop. Call from a goroutine.
func (r *OutboxRelay) Start(ctx context.Context) {
	logger.Info(ctx, "Outbox relay started", "interval", r.interval)

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.relay(ctx)
		case <-ctx.Done():
			logger.Info(ctx, "Outbox relay stopped")
			return
		}
	}
}

func (r *OutboxRelay) relay(ctx context.Context) {
	pending, err := r.outboxRepo.ListUndelivered(ctx, 100)
	if err != nil {
		logger.Error(ctx, "Outbox relay: failed to list undelivered", "error", err)
		return
	}

	if len(pending) == 0 {
		return
	}

	delivered := 0
	for _, event := range pending {
		var data events.EventData
		if err := json.Unmarshal(event.Payload, &data); err != nil {
			logger.Warn(ctx, "Outbox relay: failed to unmarshal event", "id", event.ID, "error", err)
			continue
		}

		publishCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := r.publisher.Publish(publishCtx, event.EventType, data)
		cancel()

		if err != nil {
			logger.Warn(ctx, "Outbox relay: publish failed, will retry", "id", event.ID, "error", err)
			break // Stop on first failure, retry next tick
		}

		if err := r.outboxRepo.MarkDelivered(ctx, event.ID); err != nil {
			logger.Warn(ctx, "Outbox relay: failed to mark delivered", "id", event.ID, "error", err)
		}
		delivered++
	}

	if delivered > 0 {
		logger.Info(ctx, "Outbox relay: delivered events", "count", delivered)
	}
}
