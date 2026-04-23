// Phase 7: Risk zones.
//
// Blend four independent signals into a single per-file risk score so
// the portal can surface "where changes are most likely to go wrong":
//
//   - Change frequency    — git churn (recent commits touching the file)
//   - Test coverage gap   — 1.0 - coverage fraction (files with no tests
//                           are max-risk on this axis)
//   - Past incidents      — ops-service incidents that pointed at the
//                           file via postmortem / commit linkage
//   - Cyclomatic complexity — static analysis signal, normalized
//
// Each signal is normalized to [0,1] and combined with configurable
// weights. Default weights come from decision #15's spirit: prefer
// "lived experience" (churn + incidents) over pure-static signals
// (complexity), with coverage as the strongest single axis because a
// low-coverage hot-spot is the paradigmatic risk zone.
//
//	score = 0.35*coverageGap + 0.25*churn + 0.25*incidents + 0.15*complexity
//
// The service is intentionally signal-agnostic: it pulls raw numbers
// from narrow interfaces and does the blending here. That keeps it
// testable without git, ops-service, or a scanner running.
package usecase

import (
	"context"
	"math"
	"sort"
)

// RiskSignalProvider is the narrow surface we need from each signal
// source. Every source returns a per-file metric keyed by repo-relative
// path. Sources that don't have data for a file simply omit it.
type RiskSignalProvider interface {
	// ChangeFrequency returns commit counts per file over the lookback
	// window (typically 90 days). Higher = hotter.
	ChangeFrequency(ctx context.Context, orgID, repoID string) (map[string]int, error)
	// CoverageByFile returns test-coverage fractions in [0,1]. Missing
	// files are treated as zero coverage.
	CoverageByFile(ctx context.Context, orgID, repoID string) (map[string]float64, error)
	// IncidentHits returns incident counts per file from postmortems /
	// commit-level linkage.
	IncidentHits(ctx context.Context, orgID, repoID string) (map[string]int, error)
	// Complexity returns a normalized complexity score per file (already
	// rescaled to [0,1] by the provider so languages stay comparable).
	Complexity(ctx context.Context, orgID, repoID string) (map[string]float64, error)
}

// RiskZoneWeights controls the blend. Callers can override at runtime
// when they have tenant-specific tuning (decision #15 lets admins shift
// the weights via Vigil config).
type RiskZoneWeights struct {
	CoverageGap float64
	Churn       float64
	Incidents   float64
	Complexity  float64
}

// DefaultRiskZoneWeights matches the doc-string rationale above.
func DefaultRiskZoneWeights() RiskZoneWeights {
	return RiskZoneWeights{
		CoverageGap: 0.35,
		Churn:       0.25,
		Incidents:   0.25,
		Complexity:  0.15,
	}
}

// RiskZone is one scored file.
type RiskZone struct {
	File            string  `json:"file"`
	Score           float64 `json:"score"`
	ChurnScore      float64 `json:"churn_score"`
	CoverageGap     float64 `json:"coverage_gap"`
	IncidentScore   float64 `json:"incident_score"`
	ComplexityScore float64 `json:"complexity_score"`
	// Raw values so the portal can show "23 commits, 0 tests, 2 incidents"
	// instead of only the blended number.
	RawChurn      int     `json:"raw_churn"`
	RawCoverage   float64 `json:"raw_coverage"`
	RawIncidents  int     `json:"raw_incidents"`
	RawComplexity float64 `json:"raw_complexity"`
}

// RiskZoneService blends the signals into ranked RiskZones.
type RiskZoneService struct {
	provider RiskSignalProvider
	weights  RiskZoneWeights
}

// NewRiskZoneService constructs the service with default weights.
// Callers wanting custom weights should call WithWeights afterwards.
func NewRiskZoneService(p RiskSignalProvider) *RiskZoneService {
	return &RiskZoneService{provider: p, weights: DefaultRiskZoneWeights()}
}

// WithWeights replaces the blend weights in-place. Weights need not
// sum to 1 — the final score is normalized to the weight total so any
// combo produces a [0,1] output.
func (s *RiskZoneService) WithWeights(w RiskZoneWeights) *RiskZoneService {
	s.weights = w
	return s
}

// ComputeRiskZones fetches each signal, normalizes it, blends them,
// and returns the files sorted high-to-low by score. Signals that
// fail to load are treated as "no data" (empty map) — we never hard-
// fail because one source is down.
func (s *RiskZoneService) ComputeRiskZones(ctx context.Context, orgID, repoID string, topN int) ([]RiskZone, error) {
	churn, _ := s.provider.ChangeFrequency(ctx, orgID, repoID)
	coverage, _ := s.provider.CoverageByFile(ctx, orgID, repoID)
	incidents, _ := s.provider.IncidentHits(ctx, orgID, repoID)
	complexity, _ := s.provider.Complexity(ctx, orgID, repoID)

	// Union of every file any signal saw. A file only seen in coverage
	// is still a valid risk candidate (likely low-risk but shouldn't be
	// silently dropped).
	files := make(map[string]struct{})
	for f := range churn {
		files[f] = struct{}{}
	}
	for f := range coverage {
		files[f] = struct{}{}
	}
	for f := range incidents {
		files[f] = struct{}{}
	}
	for f := range complexity {
		files[f] = struct{}{}
	}

	maxChurn := maxInt(churn)
	maxIncidents := maxInt(incidents)
	wSum := s.weights.CoverageGap + s.weights.Churn + s.weights.Incidents + s.weights.Complexity
	if wSum == 0 {
		wSum = 1 // guard against a misconfigured all-zero weight profile
	}

	out := make([]RiskZone, 0, len(files))
	for f := range files {
		c := churn[f]
		cov := coverage[f]
		inc := incidents[f]
		cx := complexity[f]

		churnNorm := 0.0
		if maxChurn > 0 {
			churnNorm = float64(c) / float64(maxChurn)
		}
		incNorm := 0.0
		if maxIncidents > 0 {
			incNorm = float64(inc) / float64(maxIncidents)
		}
		coverageGap := 1.0 - clamp01(cov)
		cxNorm := clamp01(cx)

		score := (s.weights.CoverageGap*coverageGap +
			s.weights.Churn*churnNorm +
			s.weights.Incidents*incNorm +
			s.weights.Complexity*cxNorm) / wSum

		out = append(out, RiskZone{
			File:            f,
			Score:           round3(score),
			ChurnScore:      round3(churnNorm),
			CoverageGap:     round3(coverageGap),
			IncidentScore:   round3(incNorm),
			ComplexityScore: round3(cxNorm),
			RawChurn:        c,
			RawCoverage:     cov,
			RawIncidents:    inc,
			RawComplexity:   cx,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].File < out[j].File // stable tiebreak for deterministic UIs
	})

	if topN > 0 && len(out) > topN {
		out = out[:topN]
	}
	return out, nil
}

func maxInt(m map[string]int) int {
	max := 0
	for _, v := range m {
		if v > max {
			max = v
		}
	}
	return max
}

func clamp01(v float64) float64 {
	if math.IsNaN(v) || v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func round3(v float64) float64 {
	return math.Round(v*1000) / 1000
}
