package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/ClickHouse/clickhouse-go/v2" // Register "clickhouse" driver for database/sql

	"github.com/sentiae/vigil/service/pkg/config"
	"github.com/sentiae/vigil/service/pkg/logger"
)

// NewClickHouseDB creates a connection to ClickHouse using database/sql.
// Uses the clickhouse-go driver registered as "clickhouse" in database/sql.
func NewClickHouseDB(ctx context.Context, cfg config.ClickHouseConfig) (*sql.DB, error) {
	if cfg.Addr == "" {
		return nil, fmt.Errorf("clickhouse address is empty")
	}

	dsn := fmt.Sprintf("clickhouse://%s:%s@%s/%s",
		cfg.User, cfg.Password, cfg.Addr, cfg.Database,
	)

	db, err := sql.Open("clickhouse", dsn)
	if err != nil {
		return nil, fmt.Errorf("open clickhouse: %w", err)
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := db.PingContext(pingCtx); err != nil {
		db.Close()
		logger.Warn(ctx, "ClickHouse ping failed (service will work without analytics)", "error", err)
		return nil, fmt.Errorf("clickhouse ping: %w", err)
	}

	logger.Info(ctx, "ClickHouse connected", "addr", cfg.Addr, "database", cfg.Database)
	return db, nil
}
