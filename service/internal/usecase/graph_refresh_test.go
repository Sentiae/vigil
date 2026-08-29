package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	kafka "github.com/sentiae/platform-kit/kafka"

	"github.com/sentiae/vigil/service/pkg/events"
)

type fakeFetcher struct {
	files []string
	err   error
}

func (f *fakeFetcher) FetchChangedFiles(_ context.Context, _ uuid.UUID, _, _ string) ([]string, error) {
	return f.files, f.err
}

type fakeRefresher struct {
	called bool
	err    error
}

func (f *fakeRefresher) RefreshNodes(_ context.Context, _ uuid.UUID, _ string, _ []string) error {
	f.called = true
	return f.err
}

type fakePublisher struct {
	called bool
	err    error
}

func (f *fakePublisher) PublishCodeGraphUpdated(_ context.Context, _ uuid.UUID, _ string, _ []string) error {
	f.called = true
	return f.err
}

func TestHandlePushHappyPath(t *testing.T) {
	f := &fakeFetcher{files: []string{"a.go", "b.go"}}
	r := &fakeRefresher{}
	p := &fakePublisher{}
	g := NewGraphRefresher(f, r, p)

	changed, err := g.HandlePush(context.Background(), PushEvent{RepoID: uuid.New(), CommitSHA: "abc", Before: "xyz", Ref: "refs/heads/main"})
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 2 {
		t.Errorf("want 2 files, got %d", len(changed))
	}
	if !r.called {
		t.Error("refresher not called")
	}
	if !p.called {
		t.Error("publisher not called")
	}
}

func TestHandlePushValidatesInputs(t *testing.T) {
	g := NewGraphRefresher(nil, nil, nil)
	if _, err := g.HandlePush(context.Background(), PushEvent{}); err == nil {
		t.Fatal("expected error for empty inputs")
	}
	if _, err := g.HandlePush(context.Background(), PushEvent{RepoID: uuid.New()}); err == nil {
		t.Fatal("expected error for missing commit")
	}
}

func TestHandlePushSurfacesFetcherError(t *testing.T) {
	g := NewGraphRefresher(&fakeFetcher{err: errors.New("boom")}, &fakeRefresher{}, &fakePublisher{})
	if _, err := g.HandlePush(context.Background(), PushEvent{RepoID: uuid.New(), CommitSHA: "abc"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestHandlePushAllOptionalDeps(t *testing.T) {
	// With all deps nil the pipeline should still succeed — used in tests
	// and minimal deployments that only want to exercise validation.
	g := NewGraphRefresher(nil, nil, nil)
	changed, err := g.HandlePush(context.Background(), PushEvent{RepoID: uuid.New(), CommitSHA: "abc"})
	if err != nil {
		t.Fatal(err)
	}
	if changed != nil {
		t.Errorf("want nil changed, got %v", changed)
	}
}

// capturingPublisher records the exact EventData KafkaGraphPublisher builds so
// the payload can be validated against the platform-kit taxonomy schema.
type capturingPublisher struct {
	eventType string
	data      events.EventData
}

func (c *capturingPublisher) Publish(_ context.Context, eventType string, data events.EventData) error {
	c.eventType = eventType
	c.data = data
	return nil
}

func (c *capturingPublisher) PublishBatch(_ context.Context, _ []kafka.Event) error { return nil }
func (c *capturingPublisher) EnsureTopics(_ context.Context) error                  { return nil }
func (c *capturingPublisher) Close() error                                          { return nil }

// TestPublishCodeGraphUpdatedIsEnvelopeComplete is a producer-conformance test:
// the publisher rejects any payload failing ValidateEventPayload, so a payload
// missing the envelope fields silently kills the whole code.graph.updated
// stream. Asserting the real validator here catches that at build time.
func TestPublishCodeGraphUpdatedIsEnvelopeComplete(t *testing.T) {
	cap := &capturingPublisher{}
	repoID := uuid.New()

	err := NewKafkaGraphPublisher(cap).PublishCodeGraphUpdated(
		context.Background(), repoID, "deadbeef", []string{"a.go"})
	if err != nil {
		t.Fatalf("publish: %v", err)
	}

	if cap.eventType != kafka.EventCodeGraphUpdated {
		t.Errorf("event type = %q, want %q", cap.eventType, kafka.EventCodeGraphUpdated)
	}
	if err := kafka.ValidateEventPayload(kafka.EventCodeGraphUpdated, cap.data); err != nil {
		t.Fatalf("payload rejected by the taxonomy validator: %v", err)
	}
	if cap.data.ResourceID != repoID.String() {
		t.Errorf("resource_id = %q, want %q", cap.data.ResourceID, repoID.String())
	}
}
