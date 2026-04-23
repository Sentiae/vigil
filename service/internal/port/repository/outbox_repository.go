package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// OutboxEvent represents an event stored in the transactional outbox.
type OutboxEvent struct {
	ID          uuid.UUID  `json:"id"`
	EventType   string     `json:"event_type"`
	Payload     []byte     `json:"payload"`
	CreatedAt   time.Time  `json:"created_at"`
	DeliveredAt *time.Time `json:"delivered_at,omitempty"`
}

// OutboxRepository defines the data access interface for the transactional outbox.
type OutboxRepository interface {
	Insert(ctx context.Context, event *OutboxEvent) error
	ListUndelivered(ctx context.Context, limit int) ([]*OutboxEvent, error)
	MarkDelivered(ctx context.Context, id uuid.UUID) error
}
