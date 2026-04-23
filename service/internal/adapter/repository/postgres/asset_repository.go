package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentiae/vigil/service/internal/domain"
	"github.com/sentiae/vigil/service/internal/port/repository"
)

type assetRepository struct {
	pool *pgxpool.Pool
}

func NewAssetRepository(pool *pgxpool.Pool) repository.AssetRepository {
	return &assetRepository{pool: pool}
}

func (r *assetRepository) Create(ctx context.Context, a *domain.Asset) error {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}

	tagsJSON, _ := json.Marshal(a.Tags)

	_, err := r.pool.Exec(ctx, `
		INSERT INTO assets (
			id, tenant_id, asset_type, name, cloud_provider, cloud_account_id,
			cloud_region, arn, criticality, environment, internet_facing, pii_handling,
			tags, last_scanned_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
		a.ID, a.TenantID, a.Type, a.Name, a.CloudProvider, a.CloudAccountID,
		a.CloudRegion, a.ARN, a.Criticality, a.Environment, a.InternetFacing, a.PIIHandling,
		tagsJSON, a.LastScannedAt, a.CreatedAt, a.UpdatedAt,
	)
	return err
}

func (r *assetRepository) Update(ctx context.Context, a *domain.Asset) error {
	tagsJSON, _ := json.Marshal(a.Tags)

	_, err := r.pool.Exec(ctx, `
		UPDATE assets SET
			name = $3, cloud_provider = $4, cloud_account_id = $5, cloud_region = $6,
			arn = $7, criticality = $8, environment = $9, internet_facing = $10,
			pii_handling = $11, tags = $12, last_scanned_at = $13
		WHERE tenant_id = $1 AND id = $2`,
		a.TenantID, a.ID,
		a.Name, a.CloudProvider, a.CloudAccountID, a.CloudRegion,
		a.ARN, a.Criticality, a.Environment, a.InternetFacing,
		a.PIIHandling, tagsJSON, a.LastScannedAt,
	)
	return err
}

func (r *assetRepository) FindByID(ctx context.Context, tenantID, id uuid.UUID) (*domain.Asset, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT id, tenant_id, asset_type, name, cloud_provider, cloud_account_id,
			cloud_region, arn, criticality, environment, internet_facing, pii_handling,
			tags, last_scanned_at, created_at, updated_at
		FROM assets WHERE tenant_id = $1 AND id = $2`, tenantID, id)

	return scanAsset(row)
}

func (r *assetRepository) FindByARN(ctx context.Context, tenantID uuid.UUID, arn string) (*domain.Asset, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT id, tenant_id, asset_type, name, cloud_provider, cloud_account_id,
			cloud_region, arn, criticality, environment, internet_facing, pii_handling,
			tags, last_scanned_at, created_at, updated_at
		FROM assets WHERE tenant_id = $1 AND arn = $2`, tenantID, arn)

	return scanAsset(row)
}

func (r *assetRepository) List(ctx context.Context, filter repository.AssetFilter) ([]*domain.Asset, int, error) {
	var conditions []string
	var args []any
	argN := 1

	conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argN))
	args = append(args, filter.TenantID)
	argN++

	if filter.Type != nil {
		conditions = append(conditions, fmt.Sprintf("asset_type = $%d", argN))
		args = append(args, *filter.Type)
		argN++
	}

	where := strings.Join(conditions, " AND ")

	var total int
	if err := r.pool.QueryRow(ctx, fmt.Sprintf("SELECT COUNT(*) FROM assets WHERE %s", where), args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}

	query := fmt.Sprintf(`
		SELECT id, tenant_id, asset_type, name, cloud_provider, cloud_account_id,
			cloud_region, arn, criticality, environment, internet_facing, pii_handling,
			tags, last_scanned_at, created_at, updated_at
		FROM assets WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, where, argN, argN+1)
	args = append(args, limit, filter.Offset)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var assets []*domain.Asset
	for rows.Next() {
		a, err := scanAssetFromRows(rows)
		if err != nil {
			return nil, 0, err
		}
		assets = append(assets, a)
	}

	return assets, total, nil
}

func scanAsset(row pgx.Row) (*domain.Asset, error) {
	a := &domain.Asset{}
	var tagsJSON []byte

	err := row.Scan(
		&a.ID, &a.TenantID, &a.Type, &a.Name, &a.CloudProvider, &a.CloudAccountID,
		&a.CloudRegion, &a.ARN, &a.Criticality, &a.Environment, &a.InternetFacing, &a.PIIHandling,
		&tagsJSON, &a.LastScannedAt, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrAssetNotFound
		}
		return nil, fmt.Errorf("scan asset: %w", err)
	}

	_ = json.Unmarshal(tagsJSON, &a.Tags)
	return a, nil
}

func scanAssetFromRows(rows pgx.Rows) (*domain.Asset, error) {
	a := &domain.Asset{}
	var tagsJSON []byte

	err := rows.Scan(
		&a.ID, &a.TenantID, &a.Type, &a.Name, &a.CloudProvider, &a.CloudAccountID,
		&a.CloudRegion, &a.ARN, &a.Criticality, &a.Environment, &a.InternetFacing, &a.PIIHandling,
		&tagsJSON, &a.LastScannedAt, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scan asset row: %w", err)
	}

	_ = json.Unmarshal(tagsJSON, &a.Tags)
	return a, nil
}
