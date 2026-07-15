// Package migrate applies vigil's embedded Postgres schema migrations at boot.
//
// vigil ships its schema as Atlas single-file migrations (migrations/NNNN_*.sql,
// not up/down pairs), so it cannot use golang-migrate. This runner mirrors
// golang-migrate's tracking model minimally: a schema_migrations table records
// each applied filename, and every unapplied file runs — together with its
// bookkeeping INSERT — inside one transaction, so a partial file never marks
// itself applied and a re-run is a no-op.
package migrate

import (
	"context"
	"fmt"
	"io/fs"
	"sort"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentiae/vigil/service/migrations"
	"github.com/sentiae/vigil/service/pkg/logger"
)

const createTrackingTable = `CREATE TABLE IF NOT EXISTS schema_migrations (
	version    TEXT PRIMARY KEY,
	applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);`

// Apply runs every embedded migration that has not yet been recorded in
// schema_migrations, in ascending filename order. It is safe to call on every
// boot: already-applied versions are skipped. Any error is returned so the
// caller can fail server startup.
func Apply(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx, createTrackingTable); err != nil {
		return fmt.Errorf("create schema_migrations table: %w", err)
	}

	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("read embedded migrations: %w", err)
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && len(e.Name()) > 4 && e.Name()[len(e.Name())-4:] == ".sql" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		var exists bool
		if err := pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)`, name,
		).Scan(&exists); err != nil {
			return fmt.Errorf("check migration %s: %w", name, err)
		}
		if exists {
			continue
		}

		body, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}

		if err := applyOne(ctx, pool, name, string(body)); err != nil {
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
		logger.Info(ctx, "applied migration", "version", name)
	}

	return nil
}

// applyOne runs a single migration file and records it, atomically.
func applyOne(ctx context.Context, pool *pgxpool.Pool, name, body string) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, body); err != nil {
		return fmt.Errorf("exec sql: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO schema_migrations (version) VALUES ($1)`, name,
	); err != nil {
		return fmt.Errorf("record version: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}
