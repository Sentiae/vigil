package domain

import (
	"math"
	"time"
)

// ScoringWeights holds the configurable weights for the composite scoring formula.
type ScoringWeights struct {
	CVSS     float64 `json:"cvss"`
	EPSS     float64 `json:"epss"`
	Asset    float64 `json:"asset"`
	Exposure float64 `json:"exposure"`
	KEV      float64 `json:"kev"`
	Age      float64 `json:"age"`
}

// DefaultScoringWeights returns the default scoring weights per the blueprint.
func DefaultScoringWeights() ScoringWeights {
	return ScoringWeights{
		CVSS:     0.20,
		EPSS:     0.25,
		Asset:    0.20,
		Exposure: 0.15,
		KEV:      0.10,
		Age:      0.10,
	}
}

// CompositeScore computes the normalized score (0-100) for a finding.
func CompositeScore(f *Finding, asset *Asset, kevCVEs map[string]bool, w ScoringWeights) float64 {
	// CVSS: normalize 0-10 to 0-100
	cvssBase := 0.0
	if f.CVSSScore != nil {
		cvssBase = (*f.CVSSScore / 10.0) * 100
	}

	// EPSS: normalize 0-1 to 0-100
	epss := 0.0
	if f.EPSSScore != nil {
		epss = *f.EPSSScore * 100
	}

	// Asset criticality: 0-100
	assetScore := 50.0
	if asset != nil {
		assetScore = asset.CriticalityScore()
	}

	// Exposure: 0-100
	exposure := 0.0
	if asset != nil {
		exposure = asset.ExposureScore()
	}

	// CISA KEV membership: +25 boost if any CVE is in the catalog
	kevBoost := 0.0
	if kevCVEs != nil {
		for _, cve := range f.CVEs {
			if kevCVEs[cve] {
				kevBoost = 25.0
				break
			}
		}
	}

	// Age factor: increases over time, capped at 100
	ageFactor := ageFactor(f.FirstSeenAt)

	score := cvssBase*w.CVSS + epss*w.EPSS + assetScore*w.Asset +
		exposure*w.Exposure + ageFactor*w.Age + kevBoost*w.KEV

	return math.Min(score, 100.0)
}

// ageFactor returns a score 0-100 based on how long a finding has been open.
func ageFactor(firstSeen time.Time) float64 {
	days := time.Since(firstSeen).Hours() / 24
	// Reaches 100 at 90 days, linear ramp
	factor := (days / 90.0) * 100
	return math.Min(factor, 100.0)
}
