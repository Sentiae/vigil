package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/mock"

	"github.com/sentiae/vigil/service/internal/domain"
	"github.com/sentiae/vigil/service/internal/mocks"
	"github.com/sentiae/vigil/service/internal/port/repository"
	"github.com/sentiae/vigil/service/pkg/events"
	"github.com/sentiae/vigil/service/pkg/logger"
	"github.com/sentiae/vigil/service/pkg/telemetry"
)

// captureHandler records every log record so a test can count warnings.
type captureHandler struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.recs = append(h.recs, r.Clone())
	return nil
}
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

func (h *captureHandler) warnings() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []slog.Record
	for _, r := range h.recs {
		if r.Level == slog.LevelWarn {
			out = append(out, r)
		}
	}
	return out
}

func (h *captureHandler) reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.recs = nil
}

func captureLogs(t *testing.T) *captureHandler {
	t.Helper()
	h := &captureHandler{}
	prev := logger.Log
	logger.Log = slog.New(h)
	t.Cleanup(func() { logger.Log = prev })
	return h
}

func overdueFindings(tenant uuid.UUID, n int, now time.Time) []*domain.Finding {
	out := make([]*domain.Finding, n)
	for i := range out {
		deadline := now.Add(-time.Duration(i+1) * time.Hour)
		out[i] = &domain.Finding{
			ID: uuid.New(), TenantID: tenant, Severity: domain.SeverityHigh,
			Title: "overdue", SLADeadline: &deadline,
		}
	}
	return out
}

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

// passThroughTx runs fn with the caller's context, as a transaction would.
func passThroughTx(t *testing.T) *mocks.MockTransactionManager {
	txm := mocks.NewMockTransactionManager(t)
	txm.EXPECT().WithTransaction(mock.Anything, mock.Anything).
		RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error { return fn(ctx) })
	return txm
}

// TestSLAService_TwoScans_CountsAndWarnsOnlyNewTransitions is the D-512 R9 / Q5
// control: 10,000 newly overdue findings through two scans. The first scan
// appends 10,000 outbox events, adds 10,000 to the counter and logs ONE
// aggregate warning; the second (nothing new to claim) changes neither and
// logs no warning.
func TestSLAService_TwoScans_CountsAndWarnsOnlyNewTransitions(t *testing.T) {
	logs := captureLogs(t)
	tenant := uuid.New()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	findings := overdueFindings(tenant, 10000, now)

	repo := mocks.NewMockFindingRepository(t)
	repo.EXPECT().ListActiveTenantIDs(mock.Anything).Return([]uuid.UUID{tenant}, nil)
	repo.EXPECT().ClaimSLABreaches(mock.Anything, tenant).Return(findings, nil).Once()
	repo.EXPECT().ClaimSLABreaches(mock.Anything, tenant).Return(nil, nil).Once()

	var appended []*repository.OutboxEvent
	outbox := mocks.NewMockOutboxRepository(t)
	outbox.EXPECT().Append(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, e *repository.OutboxEvent) error {
			appended = append(appended, e)
			return nil
		})

	svc := NewSLAService(repo, passThroughTx(t), outbox, fixedClock{t: now})

	before := promtestutil.ToFloat64(telemetry.SLABreachesTotal)
	svc.checkBreaches(context.Background())
	if d := promtestutil.ToFloat64(telemetry.SLABreachesTotal) - before; d != 10000 {
		t.Errorf("scan 1 counter delta = %v, want 10000", d)
	}
	if len(appended) != 10000 {
		t.Errorf("scan 1 appended %d outbox events, want 10000", len(appended))
	}
	warns := logs.warnings()
	if len(warns) != 1 {
		t.Fatalf("scan 1 warnings = %d, want exactly 1 aggregate warning", len(warns))
	}
	attrs := map[string]any{}
	warns[0].Attrs(func(a slog.Attr) bool { attrs[a.Key] = a.Value.Any(); return true })
	if attrs["new_transitions"] != int64(10000) || attrs["tenants_checked"] != int64(1) {
		t.Errorf("aggregate warning attrs = %v, want new_transitions=10000 tenants_checked=1", attrs)
	}

	first := appended[0]
	if first.EventType != events.EventFindingSLABreach {
		t.Errorf("event type = %q, want %q", first.EventType, events.EventFindingSLABreach)
	}
	if !first.CreatedAt.Equal(now) {
		t.Errorf("created_at = %v, want the injected clock %v", first.CreatedAt, now)
	}
	var data events.EventData
	if err := json.Unmarshal(first.Payload, &data); err != nil {
		t.Fatalf("payload does not decode as events.EventData: %v", err)
	}
	if data.ResourceID != findings[0].ID.String() || data.OrganizationID != tenant.String() ||
		data.Metadata["finding_id"] != findings[0].ID.String() ||
		data.Metadata["sla_deadline"] != findings[0].SLADeadline.Format(time.RFC3339) ||
		data.Metadata["days_overdue"] != float64(1) {
		t.Errorf("payload = %+v, want finding %s of tenant %s, deadline %s, 1 day overdue",
			data, findings[0].ID, tenant, findings[0].SLADeadline.Format(time.RFC3339))
	}

	logs.reset()
	appended = nil
	before = promtestutil.ToFloat64(telemetry.SLABreachesTotal)
	svc.checkBreaches(context.Background())
	if d := promtestutil.ToFloat64(telemetry.SLABreachesTotal) - before; d != 0 {
		t.Errorf("scan 2 counter delta = %v, want 0", d)
	}
	if len(appended) != 0 {
		t.Errorf("scan 2 appended %d outbox events, want 0", len(appended))
	}
	if w := len(logs.warnings()); w != 0 {
		t.Errorf("scan 2 warnings = %d, want 0", w)
	}
}

// TestSLAService_FailedTenantTransaction: a failed claim or append aborts the
// tenant's transaction — nothing is counted, one error is logged for the
// tenant, and no breach warning is emitted.
func TestSLAService_FailedTenantTransaction(t *testing.T) {
	tenant := uuid.New()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	boom := errors.New("boom")

	tests := []struct {
		name      string
		claimErr  error
		appendErr error
	}{
		{"claim fails", boom, nil},
		{"append fails", nil, boom},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureLogs(t)
			repo := mocks.NewMockFindingRepository(t)
			repo.EXPECT().ListActiveTenantIDs(mock.Anything).Return([]uuid.UUID{tenant}, nil)
			outbox := mocks.NewMockOutboxRepository(t)
			if tt.claimErr != nil {
				repo.EXPECT().ClaimSLABreaches(mock.Anything, tenant).Return(nil, tt.claimErr)
			} else {
				repo.EXPECT().ClaimSLABreaches(mock.Anything, tenant).Return(overdueFindings(tenant, 3, now), nil)
				outbox.EXPECT().Append(mock.Anything, mock.Anything).Return(tt.appendErr).Once()
			}

			svc := NewSLAService(repo, passThroughTx(t), outbox, fixedClock{t: now})
			before := promtestutil.ToFloat64(telemetry.SLABreachesTotal)
			svc.checkBreaches(context.Background())

			if d := promtestutil.ToFloat64(telemetry.SLABreachesTotal) - before; d != 0 {
				t.Errorf("counter delta = %v, want 0", d)
			}
			if w := len(logs.warnings()); w != 0 {
				t.Errorf("warnings = %d, want 0", w)
			}
			errs := 0
			for _, r := range logs.recs {
				if r.Level == slog.LevelError {
					errs++
				}
			}
			if errs != 1 {
				t.Errorf("error records = %d, want 1 for the failed tenant", errs)
			}
		})
	}
}

// TestSLAService_NegativeAppClockDaysOverdueStillEmits: once Postgres NOW()
// has admitted and claimed a breach, the event is appended and counted even
// when the application clock lags so far behind that days_overdue is negative.
// That metadata must never veto the event — skipping it would commit the
// breach marker without the event it stands for.
func TestSLAService_NegativeAppClockDaysOverdueStillEmits(t *testing.T) {
	logs := captureLogs(t)
	tenant := uuid.New()
	appNow := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	deadline := appNow.Add(72 * time.Hour) // app clock 3 days behind the database
	claimed := &domain.Finding{
		ID: uuid.New(), TenantID: tenant, Severity: domain.SeverityCritical,
		Title: "skewed", SLADeadline: &deadline,
	}

	repo := mocks.NewMockFindingRepository(t)
	repo.EXPECT().ListActiveTenantIDs(mock.Anything).Return([]uuid.UUID{tenant}, nil)
	repo.EXPECT().ClaimSLABreaches(mock.Anything, tenant).Return([]*domain.Finding{claimed}, nil).Once()

	var appended []*repository.OutboxEvent
	outbox := mocks.NewMockOutboxRepository(t)
	outbox.EXPECT().Append(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, e *repository.OutboxEvent) error {
			appended = append(appended, e)
			return nil
		})

	svc := NewSLAService(repo, passThroughTx(t), outbox, fixedClock{t: appNow})
	before := promtestutil.ToFloat64(telemetry.SLABreachesTotal)
	svc.checkBreaches(context.Background())

	if d := promtestutil.ToFloat64(telemetry.SLABreachesTotal) - before; d != 1 {
		t.Errorf("counter delta = %v, want 1 (the claimed transition committed)", d)
	}
	if len(appended) != 1 {
		t.Fatalf("appended %d outbox events, want 1", len(appended))
	}
	var data events.EventData
	if err := json.Unmarshal(appended[0].Payload, &data); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if data.ResourceID != claimed.ID.String() || data.Metadata["days_overdue"] != float64(-3) {
		t.Errorf("payload = %+v, want finding %s with days_overdue -3", data, claimed.ID)
	}
	if w := len(logs.warnings()); w != 1 {
		t.Errorf("warnings = %d, want 1 aggregate warning", w)
	}
}
