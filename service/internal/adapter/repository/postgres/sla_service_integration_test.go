//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	pkkafka "github.com/sentiae/platform-kit/kafka"

	"github.com/sentiae/vigil/service/internal/infrastructure/migrate"
	"github.com/sentiae/vigil/service/internal/port/repository"
	"github.com/sentiae/vigil/service/internal/usecase"
	"github.com/sentiae/vigil/service/pkg/events"
)

// recordingPublisher records every event the outbox relay hands to Kafka.
type recordingPublisher struct {
	mu    sync.Mutex
	types []string
	sent  []events.EventData
}

func (p *recordingPublisher) Publish(_ context.Context, eventType string, d events.EventData) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.types = append(p.types, eventType)
	p.sent = append(p.sent, d)
	return nil
}
func (p *recordingPublisher) PublishBatch(context.Context, []pkkafka.Event) error { return nil }
func (p *recordingPublisher) EnsureTopics(context.Context) error                  { return nil }
func (p *recordingPublisher) Close() error                                        { return nil }

func (p *recordingPublisher) snapshot() ([]string, []events.EventData) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.types...), append([]events.EventData(nil), p.sent...)
}

// failingOutbox delegates the first okAppends appends to the real outbox writer
// (so real rows ARE inserted inside the transaction) and then fails.
type failingOutbox struct {
	real      repository.OutboxWriter
	okAppends int
	calls     int
}

var errForcedAppend = errors.New("forced outbox append failure")

func (w *failingOutbox) Append(ctx context.Context, e *repository.OutboxEvent) error {
	w.calls++
	if w.calls > w.okAppends {
		return errForcedAppend
	}
	return w.real.Append(ctx, e)
}

type testClock struct{}

func (testClock) Now() time.Time { return time.Now().UTC() }

// newSLAService wires the production adapters exactly as the container does.
func newSLAService(pool *pgxpool.Pool) *usecase.SLAService {
	return usecase.NewSLAService(NewFindingRepository(pool), NewTxManager(pool), NewOutboxRepository(pool), testClock{})
}

// seedOverdue inserts n open findings for tenant whose deadlines passed an hour
// or more ago and that carry no breach marker.
func seedOverdue(t *testing.T, pool *pgxpool.Pool, tenant uuid.UUID, n int) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO findings (tenant_id, fingerprint, title, severity, status, analysis_type, source_scanner, sla_deadline)
		SELECT $1, 'fp-' || g, 'finding ' || g, 'high', 'new', 'sast', 'test',
		       now() - interval '1 hour' - make_interval(secs => g)
		FROM generate_series(1, $2) AS g`, tenant, n,
	); err != nil {
		t.Fatalf("seed %d overdue findings: %v", n, err)
	}
}

func countOutbox(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM outbox_events`).Scan(&n); err != nil {
		t.Fatalf("count outbox: %v", err)
	}
	return n
}

// outboxPayloads decodes every outbox row's payload.
func outboxPayloads(t *testing.T, pool *pgxpool.Pool) []events.EventData {
	t.Helper()
	rows, err := pool.Query(context.Background(), `SELECT event_type, payload FROM outbox_events ORDER BY created_at, id`)
	if err != nil {
		t.Fatalf("read outbox: %v", err)
	}
	defer rows.Close()
	var out []events.EventData
	for rows.Next() {
		var typ string
		var raw []byte
		if err := rows.Scan(&typ, &raw); err != nil {
			t.Fatalf("scan outbox row: %v", err)
		}
		if typ != events.EventFindingSLABreach {
			t.Fatalf("outbox event_type = %q, want %q", typ, events.EventFindingSLABreach)
		}
		var d events.EventData
		if err := json.Unmarshal(raw, &d); err != nil {
			t.Fatalf("decode outbox payload: %v", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate outbox: %v", err)
	}
	return out
}

// countMarked counts the tenant's findings whose breach marker is set.
func countMarked(t *testing.T, pool *pgxpool.Pool, tenant uuid.UUID) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM findings WHERE tenant_id = $1 AND sla_breach_emitted_deadline IS NOT NULL`, tenant,
	).Scan(&n); err != nil {
		t.Fatalf("count marked: %v", err)
	}
	return n
}

func scan(t *testing.T, svc *usecase.SLAService, tenant uuid.UUID) int {
	t.Helper()
	n, err := svc.CheckTenantSLABreaches(context.Background(), tenant)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return n
}

// TestSLAScan_TenThousandOverdue_TwoScans is the D-512 R9 control on real
// Postgres: 10,000 overdue findings through two scans. The first writes exactly
// one outbox row per (finding, deadline); the second writes none; a changed
// deadline is exactly one new transition.
func TestSLAScan_TenThousandOverdue_TwoScans(t *testing.T) {
	pool := newMigratedPool(t)
	tenant := uuid.New()
	seedOverdue(t, pool, tenant, 10000)
	svc := newSLAService(pool)

	if got := scan(t, svc, tenant); got != 10000 {
		t.Errorf("scan 1 claimed %d, want 10000", got)
	}
	payloads := outboxPayloads(t, pool)
	if len(payloads) != 10000 {
		t.Fatalf("scan 1 outbox rows = %d, want 10000", len(payloads))
	}
	perKey := map[string]int{}
	for _, d := range payloads {
		perKey[d.Metadata["finding_id"].(string)+"|"+d.Metadata["sla_deadline"].(string)]++
	}
	for key, n := range perKey {
		if n > 1 {
			t.Fatalf("(finding, deadline) %s has %d outbox rows, want at most 1", key, n)
		}
	}
	if len(perKey) != 10000 {
		t.Fatalf("distinct (finding, deadline) in outbox = %d, want 10000", len(perKey))
	}

	if got := scan(t, svc, tenant); got != 0 {
		t.Errorf("scan 2 claimed %d, want 0", got)
	}
	if got := countOutbox(t, pool); got != 10000 {
		t.Fatalf("outbox rows after scan 2 = %d, want 10000 (scan 2 must add none)", got)
	}

	// A changed SLA deadline is a new transition — exactly one.
	var changed uuid.UUID
	if err := pool.QueryRow(context.Background(), `
		UPDATE findings SET sla_deadline = sla_deadline - interval '1 day'
		WHERE id = (SELECT id FROM findings WHERE tenant_id = $1 ORDER BY id LIMIT 1)
		RETURNING id`, tenant,
	).Scan(&changed); err != nil {
		t.Fatalf("change deadline: %v", err)
	}
	if got := scan(t, svc, tenant); got != 1 {
		t.Errorf("scan after deadline change claimed %d, want 1", got)
	}
	payloads = outboxPayloads(t, pool)
	if len(payloads) != 10001 {
		t.Fatalf("outbox rows after deadline change = %d, want 10001", len(payloads))
	}
	if last := payloads[len(payloads)-1]; last.ResourceID != changed.String() {
		t.Errorf("new transition is for finding %s, want the changed finding %s", last.ResourceID, changed)
	}
	if got := scan(t, svc, tenant); got != 0 {
		t.Errorf("scan after the transition claimed %d, want 0", got)
	}
}

// TestSLAScan_AfterMigration007Backfill: a finding already open and overdue when
// 007 ships is NOT re-emitted; a finding that becomes overdue after 007, or
// whose deadline changes, is emitted exactly once. Deterministic: the not-yet-due
// row is proven unclaimed, then its deadline is moved into the past — no
// wall-clock wait.
func TestSLAScan_AfterMigration007Backfill(t *testing.T) {
	pool := startPostgres(t)
	applyMigrationsThrough(t, pool, "006_security_gate_policy.sql")

	tenant := uuid.New()
	past := time.Now().Add(-48 * time.Hour).UTC()
	future := time.Now().Add(48 * time.Hour).UTC()
	alreadyOverdue := insertFinding(t, pool, tenant, &past, "new")
	becomesOverdue := insertFinding(t, pool, tenant, &future, "new")

	if err := migrate.Apply(context.Background(), pool); err != nil {
		t.Fatalf("migrate.Apply (007): %v", err)
	}
	svc := newSLAService(pool)

	if got := scan(t, svc, tenant); got != 0 {
		t.Errorf("first scan after 007 claimed %d, want 0 (backfilled breach must not re-emit)", got)
	}
	if got := countOutbox(t, pool); got != 0 {
		t.Fatalf("outbox rows after first scan = %d, want 0", got)
	}

	if got := emittedDeadline(t, pool, becomesOverdue); got != nil {
		t.Fatalf("not-yet-due finding marked emitted (%v) before its deadline passed", *got)
	}

	if _, err := pool.Exec(context.Background(),
		`UPDATE findings SET sla_deadline = now() - interval '1 minute' WHERE id = $1`, becomesOverdue,
	); err != nil {
		t.Fatalf("move deadline into the past: %v", err)
	}
	if got := scan(t, svc, tenant); got != 1 {
		t.Errorf("scan after the deadline passed claimed %d, want 1", got)
	}
	if p := outboxPayloads(t, pool); len(p) != 1 || p[0].ResourceID != becomesOverdue.String() {
		t.Fatalf("outbox after deadline passed = %+v, want one row for %s", p, becomesOverdue)
	}

	if _, err := pool.Exec(context.Background(),
		`UPDATE findings SET sla_deadline = sla_deadline + interval '1 hour' WHERE id = $1`, alreadyOverdue,
	); err != nil {
		t.Fatalf("change deadline: %v", err)
	}
	if got := scan(t, svc, tenant); got != 1 {
		t.Errorf("scan after the backfilled finding's deadline changed claimed %d, want 1", got)
	}
	if p := outboxPayloads(t, pool); len(p) != 2 || p[1].ResourceID != alreadyOverdue.String() {
		t.Fatalf("outbox after deadline change = %+v, want a second row for %s", p, alreadyOverdue)
	}
	if got := scan(t, svc, tenant); got != 0 {
		t.Errorf("final scan claimed %d, want 0", got)
	}
}

// TestClaimSLABreaches_ConcurrentClaimsEmitOnce: two transactions claim the
// same tenant at once. The second blocks on the first's row locks (proven via
// pg_stat_activity), then re-evaluates the guard and claims nothing — exactly
// one outbox row per finding.
func TestClaimSLABreaches_ConcurrentClaimsEmitOnce(t *testing.T) {
	pool := newMigratedPool(t)
	tenant := uuid.New()
	const n = 50
	seedOverdue(t, pool, tenant, n)

	findings := NewFindingRepository(pool)
	outbox := NewOutboxRepository(pool)
	txm := NewTxManager(pool)

	claimAndAppend := func(ctx context.Context, afterClaim func()) (int, error) {
		claimed := 0
		err := txm.WithTransaction(ctx, func(txCtx context.Context) error {
			got, err := findings.ClaimSLABreaches(txCtx, tenant)
			if err != nil {
				return err
			}
			if afterClaim != nil {
				afterClaim()
			}
			for _, f := range got {
				payload, err := json.Marshal(events.EventData{ResourceID: f.ID.String()})
				if err != nil {
					return err
				}
				if err := outbox.Append(txCtx, &repository.OutboxEvent{
					EventType: events.EventFindingSLABreach, Payload: payload, CreatedAt: time.Now().UTC(),
				}); err != nil {
					return err
				}
			}
			claimed = len(got)
			return nil
		})
		return claimed, err
	}

	claimed := make(chan struct{})
	release := make(chan struct{})
	var firstN, secondN int
	var firstErr, secondErr error
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		firstN, firstErr = claimAndAppend(context.Background(), func() {
			close(claimed)
			<-release
		})
	}()
	<-claimed

	wg.Add(1)
	go func() {
		defer wg.Done()
		secondN, secondErr = claimAndAppend(context.Background(), nil)
	}()

	// Hold the first transaction open until the second is observably waiting
	// on its row locks, so the two claims genuinely overlap.
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting int
		if err := pool.QueryRow(context.Background(), `
			SELECT count(*) FROM pg_stat_activity
			WHERE datname = current_database() AND wait_event_type = 'Lock'
			  AND query LIKE '%sla_breach_emitted_deadline%'`,
		).Scan(&waiting); err != nil {
			close(release)
			t.Fatalf("poll pg_stat_activity: %v", err)
		}
		if waiting > 0 {
			break
		}
		if time.Now().After(deadline) {
			close(release)
			wg.Wait()
			t.Fatalf("second claim never blocked on the first's row locks")
		}
		time.Sleep(20 * time.Millisecond)
	}
	close(release)
	wg.Wait()

	if firstErr != nil || secondErr != nil {
		t.Fatalf("claims failed: first=%v second=%v", firstErr, secondErr)
	}
	if firstN != n || secondN != 0 {
		t.Errorf("claimed first=%d second=%d, want first=%d second=0", firstN, secondN, n)
	}
	if got := countOutbox(t, pool); got != n {
		t.Errorf("outbox rows = %d, want exactly %d (one per finding)", got, n)
	}
}

// TestSLAScan_AppendFailureRollsBackClaimAndOutbox: when an append fails after
// earlier appends succeeded, the whole tenant transaction rolls back — no
// breach marker and no outbox row survive — and the next scan claims them all.
func TestSLAScan_AppendFailureRollsBackClaimAndOutbox(t *testing.T) {
	pool := newMigratedPool(t)
	tenant := uuid.New()
	seedOverdue(t, pool, tenant, 5)

	failing := &failingOutbox{real: NewOutboxRepository(pool), okAppends: 2}
	svc := usecase.NewSLAService(NewFindingRepository(pool), NewTxManager(pool), failing, testClock{})

	n, err := svc.CheckTenantSLABreaches(context.Background(), tenant)
	if !errors.Is(err, errForcedAppend) {
		t.Fatalf("scan error = %v, want the forced append failure", err)
	}
	if n != 0 {
		t.Errorf("failed scan reported %d transitions, want 0", n)
	}
	if failing.calls != 3 {
		t.Fatalf("append calls = %d, want 3 (two real inserts, then the failure)", failing.calls)
	}
	if got := countMarked(t, pool, tenant); got != 0 {
		t.Errorf("breach markers after rollback = %d, want 0", got)
	}
	if got := countOutbox(t, pool); got != 0 {
		t.Errorf("outbox rows after rollback = %d, want 0", got)
	}

	if got := scan(t, newSLAService(pool), tenant); got != 5 {
		t.Errorf("retry scan claimed %d, want 5", got)
	}
	if got := countOutbox(t, pool); got != 5 {
		t.Errorf("outbox rows after retry = %d, want 5", got)
	}
}

// TestSLAScan_TenantScoped: under the production superuser posture (RLS
// bypassed), claiming tenant A touches only A's findings and writes only A's
// events. This fails if the explicit tenant predicate is removed.
func TestSLAScan_TenantScoped(t *testing.T) {
	pool := newMigratedPool(t)
	var super bool
	if err := pool.QueryRow(context.Background(),
		`SELECT rolsuper FROM pg_roles WHERE rolname = current_user`).Scan(&super); err != nil || !super {
		t.Fatalf("test role must be a superuser like production (rolsuper=%v, err=%v)", super, err)
	}

	tenantA, tenantB := uuid.New(), uuid.New()
	seedOverdue(t, pool, tenantA, 3)
	seedOverdue(t, pool, tenantB, 2)

	if got := scan(t, newSLAService(pool), tenantA); got != 3 {
		t.Errorf("claimed %d for tenant A, want 3", got)
	}
	if got := countMarked(t, pool, tenantA); got != 3 {
		t.Errorf("tenant A markers = %d, want 3", got)
	}
	if got := countMarked(t, pool, tenantB); got != 0 {
		t.Errorf("tenant B markers = %d, want 0 (claiming A must not touch B)", got)
	}
	payloads := outboxPayloads(t, pool)
	if len(payloads) != 3 {
		t.Fatalf("outbox rows = %d, want 3", len(payloads))
	}
	for _, d := range payloads {
		if d.OrganizationID != tenantA.String() {
			t.Errorf("outbox payload for organization %s, want only tenant A %s", d.OrganizationID, tenantA)
		}
	}
}

// TestSLAScan_KafkaDisabled_RetainsBreachForLaterRelay: the SLA producer has no
// publisher dependency at all — with Kafka disabled a claimed breach still
// commits its marker and outbox row, and a relay attached later delivers it.
func TestSLAScan_KafkaDisabled_RetainsBreachForLaterRelay(t *testing.T) {
	pool := newMigratedPool(t)
	tenant := uuid.New()
	seedOverdue(t, pool, tenant, 1)

	if got := scan(t, newSLAService(pool), tenant); got != 1 {
		t.Fatalf("claimed %d, want 1", got)
	}
	if got := countMarked(t, pool, tenant); got != 1 {
		t.Fatalf("breach marker not committed (marked=%d)", got)
	}
	var findingID uuid.UUID
	if err := pool.QueryRow(context.Background(), `SELECT id FROM findings WHERE tenant_id = $1`, tenant).Scan(&findingID); err != nil {
		t.Fatalf("read finding: %v", err)
	}
	var undelivered int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM outbox_events WHERE delivered_at IS NULL`).Scan(&undelivered); err != nil {
		t.Fatalf("count undelivered: %v", err)
	}
	if undelivered != 1 {
		t.Fatalf("undelivered outbox rows = %d, want 1 retained for the relay", undelivered)
	}

	pub := &recordingPublisher{}
	relay := usecase.NewOutboxRelay(NewOutboxRepository(pool), pub, 50*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		relay.Start(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()

	deadline := time.Now().Add(10 * time.Second)
	for {
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM outbox_events WHERE delivered_at IS NULL`).Scan(&undelivered); err != nil {
			t.Fatalf("count undelivered: %v", err)
		}
		if undelivered == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("relay did not deliver the retained breach within 10s")
		}
		time.Sleep(50 * time.Millisecond)
	}
	types, sent := pub.snapshot()
	if len(sent) != 1 || types[0] != events.EventFindingSLABreach || sent[0].Metadata["finding_id"] != findingID.String() {
		t.Fatalf("relay published %v %+v, want one %s for finding %s", types, sent, events.EventFindingSLABreach, findingID)
	}
}

// TestCountSLABreached_ReadOnlySamePredicate: the compliance count uses the
// claim's eligibility predicate (tenant, passed deadline, open status), counts
// overdue findings whether or not their breach was already emitted, and never
// writes a breach marker.
func TestCountSLABreached_ReadOnlySamePredicate(t *testing.T) {
	pool := newMigratedPool(t)
	tenantA, tenantB := uuid.New(), uuid.New()
	past := time.Now().Add(-48 * time.Hour).UTC()
	future := time.Now().Add(48 * time.Hour).UTC()

	seedOverdue(t, pool, tenantA, 3)
	insertFinding(t, pool, tenantA, &past, "resolved")
	insertFinding(t, pool, tenantA, &past, "false_positive")
	insertFinding(t, pool, tenantA, &past, "risk_accepted")
	insertFinding(t, pool, tenantA, &future, "new")
	insertFinding(t, pool, tenantA, nil, "new")
	seedOverdue(t, pool, tenantB, 2)

	repo := NewFindingRepository(pool)
	count := func() int {
		t.Helper()
		n, err := repo.CountSLABreached(context.Background(), tenantA)
		if err != nil {
			t.Fatalf("CountSLABreached: %v", err)
		}
		return n
	}

	if got := count(); got != 3 {
		t.Errorf("count before claim = %d, want 3", got)
	}
	if got := countMarked(t, pool, tenantA); got != 0 {
		t.Errorf("markers after counting = %d, want 0 (count must be read-only)", got)
	}
	if got := countOutbox(t, pool); got != 0 {
		t.Errorf("outbox rows after counting = %d, want 0", got)
	}

	if got := scan(t, newSLAService(pool), tenantA); got != 3 {
		t.Fatalf("claimed %d, want 3", got)
	}
	if got := count(); got != 3 {
		t.Errorf("count after claim = %d, want 3 (emitted breaches are still breaches)", got)
	}
}
