package usecase

import (
	"context"
	"testing"
)

// fakeRiskProvider satisfies RiskSignalProvider with whatever maps the
// test pre-loads. Any missing signal map is returned as an empty map,
// which mirrors how the real providers behave when a source is offline.
type fakeRiskProvider struct {
	churn      map[string]int
	coverage   map[string]float64
	incidents  map[string]int
	complexity map[string]float64
}

func (f *fakeRiskProvider) ChangeFrequency(_ context.Context, _, _ string) (map[string]int, error) {
	return f.churn, nil
}
func (f *fakeRiskProvider) CoverageByFile(_ context.Context, _, _ string) (map[string]float64, error) {
	return f.coverage, nil
}
func (f *fakeRiskProvider) IncidentHits(_ context.Context, _, _ string) (map[string]int, error) {
	return f.incidents, nil
}
func (f *fakeRiskProvider) Complexity(_ context.Context, _, _ string) (map[string]float64, error) {
	return f.complexity, nil
}

// TestRiskZones_RankedHighToLow verifies that a file with high churn,
// zero coverage, and incidents outranks a calm well-tested file.
func TestRiskZones_RankedHighToLow(t *testing.T) {
	p := &fakeRiskProvider{
		churn:      map[string]int{"hot.go": 40, "calm.go": 2},
		coverage:   map[string]float64{"hot.go": 0.1, "calm.go": 0.95},
		incidents:  map[string]int{"hot.go": 3},
		complexity: map[string]float64{"hot.go": 0.9, "calm.go": 0.2},
	}
	svc := NewRiskZoneService(p)
	zones, err := svc.ComputeRiskZones(context.Background(), "org", "repo", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(zones) != 2 {
		t.Fatalf("want 2 zones, got %d", len(zones))
	}
	if zones[0].File != "hot.go" {
		t.Fatalf("expected hot.go ranked first, got %s", zones[0].File)
	}
	if zones[0].Score <= zones[1].Score {
		t.Fatalf("hot.go score %f should beat calm.go score %f", zones[0].Score, zones[1].Score)
	}
}

// TestRiskZones_TopN truncates to topN.
func TestRiskZones_TopN(t *testing.T) {
	p := &fakeRiskProvider{
		churn: map[string]int{"a.go": 10, "b.go": 5, "c.go": 1},
	}
	svc := NewRiskZoneService(p)
	zones, _ := svc.ComputeRiskZones(context.Background(), "org", "repo", 2)
	if len(zones) != 2 {
		t.Fatalf("want top-2, got %d", len(zones))
	}
}

// TestRiskZones_MissingSignalsDontPanic — a provider with nothing but
// churn should still produce scores (the other axes just contribute 0).
func TestRiskZones_MissingSignalsDontPanic(t *testing.T) {
	p := &fakeRiskProvider{
		churn: map[string]int{"only.go": 1},
	}
	svc := NewRiskZoneService(p)
	zones, err := svc.ComputeRiskZones(context.Background(), "org", "repo", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(zones) != 1 || zones[0].File != "only.go" {
		t.Fatalf("want one zone for only.go, got %+v", zones)
	}
	// coverage=0 → coverageGap=1.0, so the score should be non-zero even
	// without a coverage map present.
	if zones[0].Score <= 0 {
		t.Fatalf("missing-coverage should still produce a non-zero score, got %f", zones[0].Score)
	}
}

// TestRiskZones_WeightsChange — with 100% coverage weight, a file that's
// fully covered must score 0 regardless of churn/incidents.
func TestRiskZones_WeightsChange(t *testing.T) {
	p := &fakeRiskProvider{
		churn:     map[string]int{"covered.go": 100},
		coverage:  map[string]float64{"covered.go": 1.0},
		incidents: map[string]int{"covered.go": 10},
	}
	svc := NewRiskZoneService(p).WithWeights(RiskZoneWeights{CoverageGap: 1.0})
	zones, _ := svc.ComputeRiskZones(context.Background(), "org", "repo", 0)
	if len(zones) != 1 {
		t.Fatalf("want 1 zone, got %d", len(zones))
	}
	if zones[0].Score != 0 {
		t.Fatalf("coverage-only weighting with full coverage should yield 0, got %f", zones[0].Score)
	}
}
