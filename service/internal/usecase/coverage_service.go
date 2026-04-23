// CoverageService — thin ingest + query surface for test-coverage
// reports. Storage is in-memory for this first Phase-8 iteration; a
// Postgres-backed repo can be swapped in later without changing the
// handler surface.
//
// Design choices:
//   - Reports are keyed on (OrgID, RepoID). Only the latest report per
//     key is retained — "what's the current coverage?" is the
//     risk-zone use case; historical trending is a separate feature
//     and can bolt onto a real repo.
//   - CommitSHA/Branch are stored on the report so callers can verify
//     the upload isn't stale (the portal will want to show "coverage
//     from commit abc123, 2h ago").
package usecase

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sentiae/vigil/service/internal/domain"
	"github.com/sentiae/vigil/service/internal/port/repository"
)

// CoverageService is the public usecase. When a CoverageRepository is
// wired, reports persist across restarts; otherwise we fall back to
// an in-memory cache so dev setups still work without migrations.
type CoverageService struct {
	repo repository.CoverageRepository

	mu     sync.RWMutex
	latest map[coverageKey]*domain.CoverageReport
}

type coverageKey struct {
	orgID  uuid.UUID
	repoID string
}

// NewCoverageService builds a service that uses the in-memory cache.
// Prefer NewCoverageServiceWithRepo in production.
func NewCoverageService() *CoverageService {
	return &CoverageService{latest: make(map[coverageKey]*domain.CoverageReport)}
}

// NewCoverageServiceWithRepo wires the Postgres repository. Reads go
// to the repo first and fall back to the in-memory cache on error so
// a flaky DB doesn't collapse the risk-zone pipeline.
func NewCoverageServiceWithRepo(repo repository.CoverageRepository) *CoverageService {
	return &CoverageService{repo: repo, latest: make(map[coverageKey]*domain.CoverageReport)}
}

// CoverageIngestInput captures everything the HTTP handler needs to
// turn a raw tracefile into a stored report.
type CoverageIngestInput struct {
	OrgID     uuid.UUID
	RepoID    string
	CommitSHA string
	Branch    string
	Format    domain.CoverageFormat
	Body      io.Reader
}

// Ingest parses the body according to Format, stores the resulting
// report as "latest" for (OrgID, RepoID), and returns it. An
// unrecognized format is a hard error so callers can surface it to CI.
func (s *CoverageService) Ingest(ctx context.Context, in CoverageIngestInput) (*domain.CoverageReport, error) {
	if in.OrgID == uuid.Nil {
		return nil, fmt.Errorf("coverage ingest: org_id is required")
	}
	if in.RepoID == "" {
		return nil, fmt.Errorf("coverage ingest: repo_id is required")
	}
	if in.Body == nil {
		return nil, fmt.Errorf("coverage ingest: body is required")
	}

	var files []domain.FileCoverage
	var err error
	switch in.Format {
	case domain.CoverageFormatLCOV:
		files, err = ParseLCOV(in.Body)
	case domain.CoverageFormatGoCoverprofile:
		files, err = ParseGoCoverprofile(in.Body)
	case domain.CoverageFormatCobertura:
		files, err = ParseCobertura(in.Body)
	case domain.CoverageFormatIstanbul:
		files, err = ParseIstanbul(in.Body)
	default:
		return nil, fmt.Errorf("coverage ingest: unsupported format %q", in.Format)
	}
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", in.Format, err)
	}
	_ = ctx

	report := &domain.CoverageReport{
		ID:        uuid.New(),
		OrgID:     in.OrgID,
		RepoID:    in.RepoID,
		CommitSHA: in.CommitSHA,
		Branch:    in.Branch,
		Format:    in.Format,
		Files:     files,
		CreatedAt: time.Now().UTC(),
	}
	// Persist to Postgres when configured. The in-memory cache is
	// updated either way so subsequent reads hit RAM.
	if s.repo != nil {
		if err := s.repo.Insert(ctx, report); err != nil {
			return nil, fmt.Errorf("persist coverage: %w", err)
		}
	}
	key := coverageKey{orgID: in.OrgID, repoID: in.RepoID}
	s.mu.Lock()
	s.latest[key] = report
	s.mu.Unlock()
	return report, nil
}

// GetLatest returns the most recent report for (OrgID, RepoID), or
// nil when nothing has been ingested yet. Postgres takes precedence
// over the in-memory cache; the cache is a warm-start fallback for
// deployments without a DB.
func (s *CoverageService) GetLatest(ctx context.Context, orgID uuid.UUID, repoID string) (*domain.CoverageReport, error) {
	if s.repo != nil {
		if r, err := s.repo.GetLatest(ctx, orgID, repoID); err == nil && r != nil {
			return r, nil
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.latest[coverageKey{orgID: orgID, repoID: repoID}]
	if !ok {
		return nil, nil
	}
	// Return a copy so callers can't mutate shared state.
	cp := *r
	cp.Files = append([]domain.FileCoverage(nil), r.Files...)
	return &cp, nil
}

// CoverageByFile is a convenience wrapper the risk-zone code path uses.
// Returns an empty map when no report exists.
func (s *CoverageService) CoverageByFile(ctx context.Context, orgID uuid.UUID, repoID string) (map[string]float64, error) {
	r, err := s.GetLatest(ctx, orgID, repoID)
	if err != nil || r == nil {
		return map[string]float64{}, err
	}
	return r.CoverageByFile(), nil
}
