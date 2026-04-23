package database

import (
	"context"
	"fmt"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/sentiae/vigil/service/pkg/config"
	"github.com/sentiae/vigil/service/pkg/logger"
)

// NewNeo4jDriver creates a Neo4j driver connection.
func NewNeo4jDriver(ctx context.Context, cfg config.Neo4jConfig) (neo4j.DriverWithContext, error) {
	if cfg.URI == "" {
		return nil, fmt.Errorf("neo4j URI is empty")
	}

	driver, err := neo4j.NewDriverWithContext(cfg.URI, neo4j.BasicAuth(cfg.User, cfg.Password, ""))
	if err != nil {
		return nil, fmt.Errorf("create neo4j driver: %w", err)
	}

	if err := driver.VerifyConnectivity(ctx); err != nil {
		driver.Close(ctx)
		return nil, fmt.Errorf("neo4j connectivity: %w", err)
	}

	logger.Info(ctx, "Neo4j connected", "uri", cfg.URI)
	return driver, nil
}
