// Phase 8: test-coverage reporting.
//
// CI systems produce coverage reports in many languages but a small
// number of formats. We normalize to a single shape (CoverageReport)
// keyed by repo so the risk-zone service can ask: "what fraction of
// `pkg/billing/charge.go` is covered?" and get a number.
//
// Supported ingest formats:
//   - LCOV (standard output of lcov, jest --coverage, pytest-cov via
//     coverage.py, gcov, c8). Line-based; we collapse to a fraction.
//   - Go coverprofile (`go test -coverprofile=coverage.out`).
//
// Other formats (Cobertura XML, Clover, go-test-json) can be added
// later by teaching the parser layer — the domain model below is
// format-agnostic.
package domain

import (
	"time"

	"github.com/google/uuid"
)

// CoverageFormat identifies how the raw report was produced. Carried
// on the report so dashboards can explain "this number comes from
// LCOV / Go coverprofile / …" and detect stale uploads.
type CoverageFormat string

const (
	CoverageFormatLCOV           CoverageFormat = "lcov"
	CoverageFormatGoCoverprofile CoverageFormat = "go_coverprofile"
	CoverageFormatCobertura      CoverageFormat = "cobertura"
	CoverageFormatIstanbul       CoverageFormat = "istanbul"
)

// FileCoverage is the per-file summary. LinesHit / LinesTotal are the
// canonical numbers; Fraction is derived for convenience on read.
type FileCoverage struct {
	Path       string  `json:"path"`
	LinesHit   int     `json:"lines_hit"`
	LinesTotal int     `json:"lines_total"`
	Fraction   float64 `json:"fraction"` // [0,1]; 0 when LinesTotal==0
}

// CoverageReport is one upload worth of data. Identified by
// (OrgID, RepoID, CommitSHA) so re-uploads for the same commit just
// replace the prior row — useful when CI retries.
type CoverageReport struct {
	ID        uuid.UUID      `json:"id"`
	OrgID     uuid.UUID      `json:"org_id"`
	RepoID    string         `json:"repo_id"` // owner/name or UUID — service is agnostic
	CommitSHA string         `json:"commit_sha,omitempty"`
	Branch    string         `json:"branch,omitempty"`
	Format    CoverageFormat `json:"format"`
	Files     []FileCoverage `json:"files"`
	CreatedAt time.Time      `json:"created_at"`
}

// CoverageByFile returns a map of path → fraction for easy lookup
// from the risk-zone blender.
func (r *CoverageReport) CoverageByFile() map[string]float64 {
	out := make(map[string]float64, len(r.Files))
	for _, f := range r.Files {
		out[f.Path] = f.Fraction
	}
	return out
}
