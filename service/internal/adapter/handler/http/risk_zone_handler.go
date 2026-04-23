package http

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/sentiae/vigil/service/internal/usecase"
)

// RiskZoneHandler exposes the Phase-7 risk-zone blending endpoint.
//
// The endpoint is POST-driven because risk scoring needs signals from
// multiple upstream services (git churn, ops incidents, coverage, etc.)
// and we don't want this service to reach across the stack itself.
// The caller — usually the BFF — aggregates the raw signals and
// posts them here; we do the blending + ranking.
type RiskZoneHandler struct{}

func NewRiskZoneHandler() *RiskZoneHandler { return &RiskZoneHandler{} }

// RiskZoneRequest is the POST body shape. Missing maps are treated as
// empty — the service tolerates incomplete signal sets.
type RiskZoneRequest struct {
	OrgID      string             `json:"org_id"`
	RepoID     string             `json:"repo_id"`
	TopN       int                `json:"top_n,omitempty"`
	Weights    *RiskZoneWeightsIn `json:"weights,omitempty"`
	Churn      map[string]int     `json:"churn,omitempty"`
	Coverage   map[string]float64 `json:"coverage,omitempty"`
	Incidents  map[string]int     `json:"incidents,omitempty"`
	Complexity map[string]float64 `json:"complexity,omitempty"`
}

// RiskZoneWeightsIn overrides the default blend at request time. Admins
// who want per-repo tuning set this on the request; everyone else
// relies on the server-side defaults.
type RiskZoneWeightsIn struct {
	CoverageGap float64 `json:"coverage_gap"`
	Churn       float64 `json:"churn"`
	Incidents   float64 `json:"incidents"`
	Complexity  float64 `json:"complexity"`
}

// HandleCompute is POST /api/v1/risk-zones
func (h *RiskZoneHandler) HandleCompute(w http.ResponseWriter, r *http.Request) {
	var req RiskZoneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.OrgID == "" || req.RepoID == "" {
		respondWithError(w, http.StatusBadRequest, "org_id and repo_id are required")
		return
	}

	provider := &mapProvider{
		churn:      req.Churn,
		coverage:   req.Coverage,
		incidents:  req.Incidents,
		complexity: req.Complexity,
	}
	svc := usecase.NewRiskZoneService(provider)
	if req.Weights != nil {
		svc = svc.WithWeights(usecase.RiskZoneWeights{
			CoverageGap: req.Weights.CoverageGap,
			Churn:       req.Weights.Churn,
			Incidents:   req.Weights.Incidents,
			Complexity:  req.Weights.Complexity,
		})
	}

	zones, err := svc.ComputeRiskZones(r.Context(), req.OrgID, req.RepoID, req.TopN)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondWithJSON(w, http.StatusOK, map[string]interface{}{"zones": zones})
}

// mapProvider is the trivial RiskSignalProvider that returns exactly
// what the HTTP caller sent. Fast, testable, and keeps the upstream
// service boundaries sharp.
type mapProvider struct {
	churn      map[string]int
	coverage   map[string]float64
	incidents  map[string]int
	complexity map[string]float64
}

func (p *mapProvider) ChangeFrequency(_ context.Context, _, _ string) (map[string]int, error) {
	return p.churn, nil
}
func (p *mapProvider) CoverageByFile(_ context.Context, _, _ string) (map[string]float64, error) {
	return p.coverage, nil
}
func (p *mapProvider) IncidentHits(_ context.Context, _, _ string) (map[string]int, error) {
	return p.incidents, nil
}
func (p *mapProvider) Complexity(_ context.Context, _, _ string) (map[string]float64, error) {
	return p.complexity, nil
}
