package event

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"

	"github.com/sentiae/vigil/service/internal/domain"
	portrepo "github.com/sentiae/vigil/service/internal/port/repository"
	portuc "github.com/sentiae/vigil/service/internal/port/usecase"
	"github.com/sentiae/vigil/service/pkg/events"
)

// fakeScanUC records TriggerScan calls so tests can assert that the new
// event aliases (sentiae.git.push.received, sentiae.git.change.created)
// route through the same scan-dispatch path as the legacy sentiae.git.push
// event.
type fakeScanUC struct {
	mu    sync.Mutex
	calls []portuc.TriggerScanInput
}

func (f *fakeScanUC) TriggerScan(_ context.Context, in portuc.TriggerScanInput) (*domain.Scan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, in)
	return &domain.Scan{ID: uuid.New()}, nil
}

func (f *fakeScanUC) GetScan(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*domain.Scan, error) {
	return nil, nil
}

func (f *fakeScanUC) ListScans(_ context.Context, _ portrepo.ScanFilter) ([]*domain.Scan, int, error) {
	return nil, 0, nil
}

func newGitPushMessage(t *testing.T, typ string, orgID string) kafka.Message {
	t.Helper()
	ev := events.CloudEvent{
		Type: typ,
		Data: mustMarshal(t, events.EventData{
			Metadata: map[string]any{
				"repository":      "org/repo",
				"branch":          "main",
				"organization_id": orgID,
			},
		}),
	}
	return kafka.Message{Value: mustMarshal(t, ev)}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// §B40 — the consumer must fan out SAST + secrets scans for all three
// git push aliases. Before the fix only sentiae.git.push worked.
func TestHandleGitEvent_DispatchesForAllPushAliases(t *testing.T) {
	orgID := uuid.New().String()
	for _, typ := range []string{
		"sentiae.git.push",
		"sentiae.git.push.received",
		"sentiae.git.change.created",
	} {
		t.Run(typ, func(t *testing.T) {
			uc := &fakeScanUC{}
			c := NewConsumer(uc, nil, "")
			msg := newGitPushMessage(t, typ, orgID)
			c.handleGitEvent(context.Background(), msg)
			uc.mu.Lock()
			got := len(uc.calls)
			uc.mu.Unlock()
			if got != 2 {
				t.Fatalf("want 2 scan dispatches (sast+secrets), got %d for %s", got, typ)
			}
		})
	}
}

func TestHandleGitEvent_IgnoresUnknownType(t *testing.T) {
	uc := &fakeScanUC{}
	c := NewConsumer(uc, nil, "")
	ev := events.CloudEvent{Type: "sentiae.git.noop"}
	msg := kafka.Message{Value: mustMarshal(t, ev)}
	c.handleGitEvent(context.Background(), msg)
	if len(uc.calls) != 0 {
		t.Fatalf("unknown event must not dispatch scans, got %d", len(uc.calls))
	}
}
