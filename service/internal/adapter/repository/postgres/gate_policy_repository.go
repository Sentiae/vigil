package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentiae/vigil/service/internal/domain"
	"github.com/sentiae/vigil/service/internal/port/repository"
)

type gatePolicyRepository struct {
	pool *pgxpool.Pool
}

func NewGatePolicyRepository(pool *pgxpool.Pool) repository.GatePolicyRepository {
	return &gatePolicyRepository{pool: pool}
}

func (r *gatePolicyRepository) UpsertPolicy(ctx context.Context, p *domain.GatePolicy) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO security_gate_policies (
			tenant_id, mode, severity_threshold, locked, updated_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, now(), now())
		ON CONFLICT (tenant_id) DO UPDATE SET
			mode = $2,
			severity_threshold = $3,
			locked = $4,
			updated_by = $5,
			updated_at = now()`,
		p.TenantID, p.Mode, p.SeverityThreshold, p.Locked, p.UpdatedBy,
	)
	if err != nil {
		return fmt.Errorf("upsert gate policy: %w", err)
	}
	return nil
}

func (r *gatePolicyRepository) FindPolicy(ctx context.Context, tenantID uuid.UUID) (*domain.GatePolicy, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT tenant_id, mode, severity_threshold, locked, updated_by, created_at, updated_at
		FROM security_gate_policies WHERE tenant_id = $1`, tenantID)

	return gatePolicyScan(row)
}

func (r *gatePolicyRepository) DeletePolicy(ctx context.Context, tenantID uuid.UUID) error {
	if _, err := r.pool.Exec(ctx,
		"DELETE FROM security_gate_policies WHERE tenant_id = $1", tenantID); err != nil {
		return fmt.Errorf("delete gate policy: %w", err)
	}
	return nil
}

func (r *gatePolicyRepository) UpsertUserPref(ctx context.Context, p *domain.GateUserPref) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO security_gate_user_prefs (
			tenant_id, user_id, mode, severity_threshold, created_at, updated_at
		) VALUES ($1, $2, $3, $4, now(), now())
		ON CONFLICT (tenant_id, user_id) DO UPDATE SET
			mode = $3,
			severity_threshold = $4,
			updated_at = now()`,
		p.TenantID, p.UserID, p.Mode, p.SeverityThreshold,
	)
	if err != nil {
		return fmt.Errorf("upsert gate user pref: %w", err)
	}
	return nil
}

func (r *gatePolicyRepository) FindUserPref(ctx context.Context, tenantID, userID uuid.UUID) (*domain.GateUserPref, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT tenant_id, user_id, mode, severity_threshold, created_at, updated_at
		FROM security_gate_user_prefs WHERE tenant_id = $1 AND user_id = $2`, tenantID, userID)

	return gateUserPrefScan(row)
}

func (r *gatePolicyRepository) DeleteUserPref(ctx context.Context, tenantID, userID uuid.UUID) error {
	if _, err := r.pool.Exec(ctx,
		"DELETE FROM security_gate_user_prefs WHERE tenant_id = $1 AND user_id = $2",
		tenantID, userID); err != nil {
		return fmt.Errorf("delete gate user pref: %w", err)
	}
	return nil
}

func gatePolicyScan(row pgx.Row) (*domain.GatePolicy, error) {
	p := &domain.GatePolicy{}
	err := row.Scan(
		&p.TenantID, &p.Mode, &p.SeverityThreshold, &p.Locked, &p.UpdatedBy,
		&p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrGatePolicyNotFound
		}
		return nil, fmt.Errorf("gate policy scan: %w", err)
	}
	return p, nil
}

func gateUserPrefScan(row pgx.Row) (*domain.GateUserPref, error) {
	p := &domain.GateUserPref{}
	err := row.Scan(
		&p.TenantID, &p.UserID, &p.Mode, &p.SeverityThreshold,
		&p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrGateUserPrefNotFound
		}
		return nil, fmt.Errorf("gate user pref scan: %w", err)
	}
	return p, nil
}
