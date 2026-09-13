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

// TransactionManager runs fn inside one database transaction carried on txCtx.
// Every repository and outbox call made with txCtx joins that transaction, so a
// state change and the event announcing it commit or roll back together
// (CLAUDE.md §19).
type TransactionManager interface {
	WithTransaction(ctx context.Context, fn func(txCtx context.Context) error) error
}

// OutboxWriter appends an event to the transactional outbox. Called with a
// transaction context, the row commits only if that transaction does; the
// outbox relay publishes it afterwards.
type OutboxWriter interface {
	Append(ctx context.Context, event *OutboxEvent) error
}

// OutboxRepository defines the data access interface for the transactional
// outbox: the writer side plus the relay's read/ack side.
type OutboxRepository interface {
	OutboxWriter
	ListUndelivered(ctx context.Context, limit int) ([]*OutboxEvent, error)
	MarkDelivered(ctx context.Context, id uuid.UUID) error
}
