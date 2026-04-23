package database

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentiae/vigil/service/pkg/config"
	"github.com/sentiae/vigil/service/pkg/logger"
)

func NewPostgresPool(ctx context.Context, cfg config.DatabaseConfig) (*pgxpool.Pool, error) {
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		cfg.User, cfg.Password, cfg.Host, cfg.Port, cfg.Name, cfg.SSLMode,
	)

	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database config: %w", err)
	}

	poolCfg.MaxConns = int32(cfg.MaxOpenConns)
	poolCfg.MinConns = int32(cfg.MaxIdleConns)
	poolCfg.MaxConnLifetime = cfg.MaxLifetime

	for i := 0; i < 5; i++ {
		pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
		if err != nil {
			logger.Warn(ctx, "Failed to create database pool", "attempt", i+1, "error", err)
			time.Sleep(time.Duration(i+1) * time.Second)
			continue
		}

		pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = pool.Ping(pingCtx)
		cancel()

		if err == nil {
			return pool, nil
		}

		pool.Close()
		logger.Warn(ctx, "Database ping failed", "attempt", i+1, "error", err)
		time.Sleep(time.Duration(i+1) * time.Second)
	}

	return nil, fmt.Errorf("failed to connect to database after 5 attempts")
}
