package neo4j

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/sentiae/vigil/service/internal/domain"
	"github.com/sentiae/vigil/service/internal/port/repository"
	"github.com/sentiae/vigil/service/pkg/logger"
)

// AssetGraphRepository implements the GraphRepository interface using Neo4j.
type AssetGraphRepository struct {
	driver neo4j.DriverWithContext
}

func NewAssetGraphRepository(driver neo4j.DriverWithContext) repository.GraphRepository {
	return &AssetGraphRepository{driver: driver}
}

func (r *AssetGraphRepository) CreateAsset(ctx context.Context, asset *domain.Asset) error {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: "neo4j"})
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		_, err := tx.Run(ctx, `
			MERGE (a:Asset {id: $id})
			SET a.tenant_id = $tenant_id,
			    a.type = $type,
			    a.name = $name,
			    a.cloud_provider = $cloud_provider,
			    a.arn = $arn,
			    a.criticality = $criticality,
			    a.environment = $environment,
			    a.internet_facing = $internet_facing
		`, map[string]any{
			"id":              asset.ID.String(),
			"tenant_id":       asset.TenantID.String(),
			"type":            string(asset.Type),
			"name":            asset.Name,
			"cloud_provider":  asset.CloudProvider,
			"arn":             asset.ARN,
			"criticality":     string(asset.Criticality),
			"environment":     asset.Environment,
			"internet_facing": asset.InternetFacing,
		})
		return nil, err
	})
	if err != nil {
		return fmt.Errorf("create asset node: %w", err)
	}

	logger.Debug(ctx, "Asset node created/updated in graph", "asset_id", asset.ID, "name", asset.Name)
	return nil
}

func (r *AssetGraphRepository) UpdateAsset(ctx context.Context, asset *domain.Asset) error {
	return r.CreateAsset(ctx, asset) // MERGE handles create-or-update
}

func (r *AssetGraphRepository) CreateRelationship(ctx context.Context, rel repository.AssetRelationship) error {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: "neo4j"})
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		query := fmt.Sprintf(`
			MATCH (from:Asset {id: $from_id})
			MATCH (to:Asset {id: $to_id})
			MERGE (from)-[r:%s]->(to)
			SET r.created_at = datetime()
		`, sanitizeRelType(rel.Type))

		_, err := tx.Run(ctx, query, map[string]any{
			"from_id": rel.FromAssetID.String(),
			"to_id":   rel.ToAssetID.String(),
		})
		return nil, err
	})
	if err != nil {
		return fmt.Errorf("create relationship: %w", err)
	}
	return nil
}

func (r *AssetGraphRepository) BlastRadius(ctx context.Context, tenantID, assetID uuid.UUID, maxDepth int) (*repository.BlastRadius, error) {
	if maxDepth <= 0 {
		maxDepth = 3
	}

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: "neo4j", AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		records, err := tx.Run(ctx, `
			MATCH (source:Asset {id: $asset_id, tenant_id: $tenant_id})
			CALL apoc.path.subgraphNodes(source, {maxLevel: $max_depth}) YIELD node
			WHERE node <> source AND node.tenant_id = $tenant_id
			RETURN node.id AS id, node.name AS name, node.type AS type,
			       node.criticality AS criticality, node.environment AS environment
		`, map[string]any{
			"asset_id":  assetID.String(),
			"tenant_id": tenantID.String(),
			"max_depth": maxDepth,
		})
		if err != nil {
			return nil, err
		}

		var assets []*domain.Asset
		for records.Next(ctx) {
			record := records.Record()
			id, _ := uuid.Parse(record.Values[0].(string))
			name, _ := record.Values[1].(string)
			assetType, _ := record.Values[2].(string)
			crit, _ := record.Values[3].(string)
			env, _ := record.Values[4].(string)

			assets = append(assets, &domain.Asset{
				ID:          id,
				TenantID:    tenantID,
				Type:        domain.AssetType(assetType),
				Name:        name,
				Criticality: domain.AssetCriticality(crit),
				Environment: env,
			})
		}
		return assets, nil
	})
	if err != nil {
		return nil, fmt.Errorf("blast radius query: %w", err)
	}

	affected := result.([]*domain.Asset)

	// Compute impact score based on criticality of affected assets
	impactScore := 0.0
	for _, a := range affected {
		impactScore += a.CriticalityScore() / 100.0
	}
	if len(affected) > 0 {
		impactScore = (impactScore / float64(len(affected))) * 100
	}

	return &repository.BlastRadius{
		SourceAssetID:  assetID,
		AffectedAssets: affected,
		ImpactScore:    impactScore,
		Depth:          maxDepth,
	}, nil
}

func (r *AssetGraphRepository) AttackPaths(ctx context.Context, tenantID, assetID uuid.UUID) ([]*repository.AttackPath, error) {
	session := r.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: "neo4j", AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		// Find shortest paths from internet-facing assets to the target
		records, err := tx.Run(ctx, `
			MATCH (exposed:Asset {tenant_id: $tenant_id, internet_facing: true})
			MATCH (target:Asset {id: $asset_id, tenant_id: $tenant_id})
			WHERE exposed <> target
			MATCH path = shortestPath((exposed)-[*..6]->(target))
			RETURN [n IN nodes(path) | {id: n.id, name: n.name, type: n.type, criticality: n.criticality}] AS steps
			LIMIT 10
		`, map[string]any{
			"asset_id":  assetID.String(),
			"tenant_id": tenantID.String(),
		})
		if err != nil {
			return nil, err
		}

		var paths []*repository.AttackPath
		for records.Next(ctx) {
			record := records.Record()
			stepsRaw, ok := record.Values[0].([]any)
			if !ok {
				continue
			}

			var steps []*domain.Asset
			for _, stepRaw := range stepsRaw {
				stepMap, ok := stepRaw.(map[string]any)
				if !ok {
					continue
				}
				id, _ := uuid.Parse(stepMap["id"].(string))
				steps = append(steps, &domain.Asset{
					ID:          id,
					TenantID:    tenantID,
					Name:        stepMap["name"].(string),
					Type:        domain.AssetType(stepMap["type"].(string)),
					Criticality: domain.AssetCriticality(stepMap["criticality"].(string)),
				})
			}

			likelihood := "medium"
			if len(steps) <= 2 {
				likelihood = "high"
			} else if len(steps) > 4 {
				likelihood = "low"
			}

			paths = append(paths, &repository.AttackPath{
				ID:         uuid.New(),
				Steps:      steps,
				Likelihood: likelihood,
				Severity:   domain.SeverityHigh,
			})
		}
		return paths, nil
	})
	if err != nil {
		return nil, fmt.Errorf("attack paths query: %w", err)
	}

	return result.([]*repository.AttackPath), nil
}

// sanitizeRelType ensures the relationship type is safe for Cypher queries.
func sanitizeRelType(relType string) string {
	allowed := map[string]bool{
		"DEPENDS_ON":        true,
		"DEPLOYED_TO":       true,
		"CONNECTS_TO":       true,
		"AUTHENTICATES_WITH": true,
	}

	// Convert to uppercase with underscores
	switch relType {
	case "depends_on":
		return "DEPENDS_ON"
	case "deployed_to":
		return "DEPLOYED_TO"
	case "connects_to":
		return "CONNECTS_TO"
	case "authenticates_with":
		return "AUTHENTICATES_WITH"
	default:
		if allowed[relType] {
			return relType
		}
		return "RELATES_TO"
	}
}
