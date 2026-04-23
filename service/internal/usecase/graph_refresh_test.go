package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
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
