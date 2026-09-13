package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentiae/vigil/service/internal/port/repository"
)

type outboxRepository struct {
	pool *pgxpool.Pool
}

func NewOutboxRepository(pool *pgxpool.Pool) repository.OutboxRepository {
	return &outboxRepository{pool: pool}
}

// Append inserts the event into the outbox, joining the transaction carried on
// ctx when there is one.
func (r *outboxRepository) Append(ctx context.Context, event *repository.OutboxEvent) error {
	if event.ID == uuid.Nil {
		event.ID = uuid.New()
	}

	if _, err := dbFrom(ctx, r.pool).Exec(ctx, `
		INSERT INTO outbox_events (id, event_type, payload, created_at)
		VALUES ($1, $2, $3, $4)`,
		event.ID, event.EventType, event.Payload, event.CreatedAt,
	); err != nil {
		return fmt.Errorf("append outbox event: %w", err)
	}
	return nil
}

func (r *outboxRepository) ListUndelivered(ctx context.Context, limit int) ([]*repository.OutboxEvent, error) {
	if limit <= 0 {
		limit = 100
	}

	rows, err := r.pool.Query(ctx, `
		SELECT id, event_type, payload, created_at, delivered_at
		FROM outbox_events
		WHERE delivered_at IS NULL
		ORDER BY created_at ASC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*repository.OutboxEvent
	for rows.Next() {
		e := &repository.OutboxEvent{}
		if err := rows.Scan(&e.ID, &e.EventType, &e.Payload, &e.CreatedAt, &e.DeliveredAt); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, nil
}

func (r *outboxRepository) MarkDelivered(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx,
		"UPDATE outbox_events SET delivered_at = NOW() WHERE id = $1 AND delivered_at IS NULL", id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("outbox event not found or already delivered")
	}
	return nil
}
