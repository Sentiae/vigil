// Package usecase — Graph refresh (§11.3).
//
// On receiving sentiae.git.push (or an equivalent repo-updated event)
// we re-run incremental code intelligence for the changed files only:
//
//   1. Fetch the list of changed files from git-service.
//   2. For each changed file, re-parse + update symbol graph deltas.
//   3. Rewrite the repo's .nodes/ metadata via git-service.
//   4. Emit sentiae.code.graph.updated for canvas-service.
//
// The implementation here is the in-service coordinator — HTTP calls
// out to git-service do the heavy filesystem work so this service
// stays stateless about repositories.
package usecase

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/sentiae/vigil/service/pkg/events"
)

// GitChangedFilesFetcher abstracts the git-service call.
type GitChangedFilesFetcher interface {
	// FetchChangedFiles returns the changed files between fromSHA and toSHA.
	FetchChangedFiles(ctx context.Context, repoID uuid.UUID, fromSHA, toSHA string) ([]string, error)
}

// NodesRefresher rewrites the repo's on-disk .nodes/ metadata so the
// canvas pulls the latest snapshot next render.
type NodesRefresher interface {
	// RefreshNodes signals git-service to regenerate .nodes/.
	RefreshNodes(ctx context.Context, repoID uuid.UUID, commitSHA string, changedFiles []string) error
}

// GraphUpdatedPublisher emits the downstream event for canvas consumers.
type GraphUpdatedPublisher interface {
	PublishCodeGraphUpdated(ctx context.Context, repoID uuid.UUID, commitSHA string, changedFiles []string) error
}

// GraphRefresher wires the three deps. Any can be nil; missing
// dependencies degrade a specific step to a log-only warning so the
// handler still makes forward progress for the others.
type GraphRefresher struct {
	fetcher   GitChangedFilesFetcher
	refresher NodesRefresher
	publisher GraphUpdatedPublisher
}

// NewGraphRefresher wires the refresher.
func NewGraphRefresher(fetcher GitChangedFilesFetcher, refresher NodesRefresher, publisher GraphUpdatedPublisher) *GraphRefresher {
	return &GraphRefresher{fetcher: fetcher, refresher: refresher, publisher: publisher}
}

// PushEvent is the minimal shape we care about from sentiae.git.push.
// CloudEvent → EventData already unmarshaled.
type PushEvent struct {
	RepoID    uuid.UUID
	CommitSHA string
	Before    string
	Ref       string
}

// HandlePush runs the full refresh pipeline for one push event.
// Returns the list of changed files so callers can log / test.
func (g *GraphRefresher) HandlePush(ctx context.Context, ev PushEvent) ([]string, error) {
	if ev.RepoID == uuid.Nil || ev.CommitSHA == "" {
		return nil, fmt.Errorf("graph refresh: repo_id and commit_sha required")
	}

	var changed []string
	if g.fetcher != nil {
		files, err := g.fetcher.FetchChangedFiles(ctx, ev.RepoID, ev.Before, ev.CommitSHA)
		if err != nil {
			return nil, fmt.Errorf("fetch changed files: %w", err)
		}
		changed = files
	}

	if g.refresher != nil {
		if err := g.refresher.RefreshNodes(ctx, ev.RepoID, ev.CommitSHA, changed); err != nil {
			// Non-fatal: we still want to publish so downstream consumers
			// know something shifted.
			return changed, fmt.Errorf("refresh nodes: %w", err)
		}
	}

	if g.publisher != nil {
		if err := g.publisher.PublishCodeGraphUpdated(ctx, ev.RepoID, ev.CommitSHA, changed); err != nil {
			return changed, fmt.Errorf("publish graph-updated: %w", err)
		}
	}
	return changed, nil
}

// =============================================================================
// HTTP adapter over git-service
// =============================================================================

// TODO(A7.2): Migrate HTTPGitClient to a gRPC client once git-service grows
// the required RPCs on GitService. As of 2026-04-19, git-service/proto/git/v1
// exposes GetRepository / ListRepositories / branches / commits / PRs but no
// counterparts for:
//
//   - GET  /api/v1/repos/id/{id}/diff?from=A&to=B&format=files (FetchChangedFiles)
//   - POST /api/v1/repos/id/{id}/nodes/refresh                  (RefreshNodes)
//
// Needs: `rpc DiffFiles(DiffFilesRequest) returns (DiffFilesResponse)` and
// `rpc RefreshNodes(RefreshNodesRequest) returns (RefreshNodesResponse)` on
// GitService in git-service/proto/git/v1/git.proto. Until then the HTTP
// client below is the correct — and only — transport for vigil-service's
// graph-refresh coordinator.

// HTTPGitClient implements both GitChangedFilesFetcher and NodesRefresher
// against the git-service REST API.
type HTTPGitClient struct {
	baseURL string
	http    *http.Client
}

// NewHTTPGitClient builds a client. baseURL falls back to in-cluster default.
func NewHTTPGitClient(baseURL string) *HTTPGitClient {
	if baseURL == "" {
		baseURL = "http://git-service:8082"
	}
	return &HTTPGitClient{
		baseURL: baseURL,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

// FetchChangedFiles calls git-service's diff endpoint.
func (c *HTTPGitClient) FetchChangedFiles(ctx context.Context, repoID uuid.UUID, fromSHA, toSHA string) ([]string, error) {
	if toSHA == "" {
		return nil, nil
	}
	url := fmt.Sprintf("%s/api/v1/repos/id/%s/diff?from=%s&to=%s&format=files", c.baseURL, repoID, fromSHA, toSHA)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("git-service diff %d: %s", resp.StatusCode, string(body))
	}
	var payload struct {
		Files []string `json:"files"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	return payload.Files, nil
}

// RefreshNodes POSTs to git-service to trigger a .nodes/ rewrite.
func (c *HTTPGitClient) RefreshNodes(ctx context.Context, repoID uuid.UUID, commitSHA string, changedFiles []string) error {
	body, _ := json.Marshal(map[string]any{
		"commit_sha":    commitSHA,
		"changed_files": changedFiles,
		"incremental":   true,
	})
	url := fmt.Sprintf("%s/api/v1/repos/id/%s/nodes/refresh", c.baseURL, repoID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("git-service nodes refresh %d: %s", resp.StatusCode, string(respBody))
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// =============================================================================
// Kafka publisher adapter
// =============================================================================

// KafkaGraphPublisher emits sentiae.code.graph.updated via the existing
// platform-kit publisher used by vigil-service.
type KafkaGraphPublisher struct {
	pub events.Publisher
}

// NewKafkaGraphPublisher wraps a Publisher.
func NewKafkaGraphPublisher(pub events.Publisher) *KafkaGraphPublisher {
	return &KafkaGraphPublisher{pub: pub}
}

// PublishCodeGraphUpdated fans out the event. Best-effort: errors are
// returned for logging but don't roll back upstream writes.
func (k *KafkaGraphPublisher) PublishCodeGraphUpdated(ctx context.Context, repoID uuid.UUID, commitSHA string, changedFiles []string) error {
	if k.pub == nil {
		return nil
	}
	data := events.EventData{
		Metadata: map[string]any{
			"repository_id": repoID.String(),
			"commit_sha":    commitSHA,
			"changed_files": changedFiles,
		},
	}
	return k.pub.Publish(ctx, "code.graph.updated", data)
}
