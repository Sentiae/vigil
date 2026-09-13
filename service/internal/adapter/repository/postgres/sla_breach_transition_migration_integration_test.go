//go:build integration

package postgres

import (
	"context"
	"io/fs"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentiae/vigil/service/internal/infrastructure/migrate"
	"github.com/sentiae/vigil/service/migrations"
)

// applyMigrationsThrough stages a database exactly as production holds it
// before a newer migration ships: every embedded migration up to and including
// last is applied and recorded in schema_migrations, so a later migrate.Apply
// runs only what is newer — the real runner, on a pre-existing database.
func applyMigrationsThrough(t *testing.T, pool *pgxpool.Pool, last string) {
	t.Helper()
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    TEXT PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}

	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		t.Fatalf("read embedded migrations: %v", err)
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") && e.Name() <= last {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 || names[len(names)-1] != last {
		t.Fatalf("migration %s not embedded (have %v)", last, names)
	}

	for _, name := range names {
		body, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if _, err := pool.Exec(ctx, string(body)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, name); err != nil {
			t.Fatalf("record %s: %v", name, err)
		}
	}
}

// insertFinding writes one finding with the given deadline and status and
// returns its id. A nil deadline leaves sla_deadline NULL.
func insertFinding(t *testing.T, pool *pgxpool.Pool, tenantID uuid.UUID, deadline *time.Time, status string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO findings (id, tenant_id, fingerprint, title, severity, status, analysis_type, source_scanner, sla_deadline)
		VALUES ($1, $2, $3, $4, 'high', $5, 'sast', 'test', $6)`,
		id, tenantID, "fp-"+id.String(), "finding "+id.String(), status, deadline,
	); err != nil {
		t.Fatalf("insert finding: %v", err)
	}
	return id
}

// emittedDeadline reads a finding's persisted breach marker (nil = NULL).
func emittedDeadline(t *testing.T, pool *pgxpool.Pool, id uuid.UUID) *time.Time {
	t.Helper()
	var v *time.Time
	if err := pool.QueryRow(context.Background(),
		`SELECT sla_breach_emitted_deadline FROM findings WHERE id = $1`, id,
	).Scan(&v); err != nil {
		t.Fatalf("read sla_breach_emitted_deadline: %v", err)
	}
	return v
}

// TestMigration007_BackfillsOpenOverdueFindings proves 007 treats every finding
// that is ALREADY open and overdue when it ships as emitted for its current
// deadline (those breaches were published by every earlier scan), and leaves
// every other row unmarked.
func TestMigration007_BackfillsOpenOverdueFindings(t *testing.T) {
	pool := startPostgres(t)
	applyMigrationsThrough(t, pool, "006_security_gate_policy.sql")

	tenant := uuid.New()
	past := time.Now().Add(-48 * time.Hour).UTC().Truncate(time.Microsecond)
	future := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Microsecond)

	openOverdue := insertFinding(t, pool, tenant, &past, "new")
	inProgressOverdue := insertFinding(t, pool, tenant, &past, "in_progress")
	resolvedOverdue := insertFinding(t, pool, tenant, &past, "resolved")
	falsePositiveOverdue := insertFinding(t, pool, tenant, &past, "false_positive")
	acceptedOverdue := insertFinding(t, pool, tenant, &past, "risk_accepted")
	notYetDue := insertFinding(t, pool, tenant, &future, "new")
	noDeadline := insertFinding(t, pool, tenant, nil, "new")

	if err := migrate.Apply(context.Background(), pool); err != nil {
		t.Fatalf("migrate.Apply: %v", err)
	}

	var recorded bool
	if err := pool.QueryRow(context.Background(),
		`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = '007_sla_breach_transition.sql')`,
	).Scan(&recorded); err != nil {
		t.Fatalf("read schema_migrations: %v", err)
	}
	if !recorded {
		t.Fatalf("007_sla_breach_transition.sql was not applied by the runner")
	}

	for name, id := range map[string]uuid.UUID{"open overdue": openOverdue, "in-progress overdue": inProgressOverdue} {
		got := emittedDeadline(t, pool, id)
		if got == nil || !got.Equal(past) {
			t.Errorf("%s: sla_breach_emitted_deadline = %v, want %v", name, got, past)
		}
	}
	for name, id := range map[string]uuid.UUID{
		"resolved overdue":       resolvedOverdue,
		"false-positive overdue": falsePositiveOverdue,
		"risk-accepted overdue":  acceptedOverdue,
		"not yet due":            notYetDue,
		"no deadline":            noDeadline,
	} {
		if got := emittedDeadline(t, pool, id); got != nil {
			t.Errorf("%s: sla_breach_emitted_deadline = %v, want NULL", name, *got)
		}
	}
}
