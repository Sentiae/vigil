package http

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/sentiae/vigil/service/internal/domain"
	"github.com/sentiae/vigil/service/internal/middleware"
	"github.com/sentiae/vigil/service/internal/port/repository"
	"github.com/sentiae/vigil/service/internal/port/usecase"
)

type FindingHandler struct {
	findingUC usecase.FindingUseCase
}

func NewFindingHandler(findingUC usecase.FindingUseCase) *FindingHandler {
	return &FindingHandler{findingUC: findingUC}
}

func (h *FindingHandler) ListFindings(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantIDFromContext(r.Context())
	if tenantID == uuid.Nil {
		respondWithError(w, http.StatusUnauthorized, "tenant_id required")
		return
	}

	filter := repository.FindingFilter{
		TenantID: tenantID,
	}

	if sev := r.URL.Query().Get("severity"); sev != "" {
		s := domain.Severity(sev)
		filter.Severity = &s
	}
	if status := r.URL.Query().Get("status"); status != "" {
		s := domain.FindingStatus(status)
		filter.Status = &s
	}
	if at := r.URL.Query().Get("analysis_type"); at != "" {
		a := domain.AnalysisType(at)
		filter.AnalysisType = &a
	}
	if lim := r.URL.Query().Get("limit"); lim != "" {
		if n, err := strconv.Atoi(lim); err == nil {
			filter.Limit = n
		}
	}
	if off := r.URL.Query().Get("offset"); off != "" {
		if n, err := strconv.Atoi(off); err == nil {
			filter.Offset = n
		}
	}

	findings, total, err := h.findingUC.ListFindings(r.Context(), filter)
	if err != nil {
		handleError(w, err)
		return
	}

	// Count by severity for summary
	counts, _ := h.findingUC.CountBySeverity(r.Context(), tenantID)

	respondWithJSON(w, http.StatusOK, map[string]any{
		"findings": findings,
		"total":    total,
		"critical": counts[domain.SeverityCritical],
		"high":     counts[domain.SeverityHigh],
		"medium":   counts[domain.SeverityMedium],
		"low":      counts[domain.SeverityLow],
	})
}

func (h *FindingHandler) GetFinding(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantIDFromContext(r.Context())
	findingID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid finding id")
		return
	}

	finding, err := h.findingUC.GetFinding(r.Context(), tenantID, findingID)
	if err != nil {
		handleError(w, err)
		return
	}

	respondWithJSON(w, http.StatusOK, finding)
}

func (h *FindingHandler) ResolveFinding(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantIDFromContext(r.Context())
	findingID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid finding id")
		return
	}

	var input struct {
		Resolution string `json:"resolution"`
		Note       string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	userID := middleware.GetUserIDFromContext(r.Context())

	finding, err := h.findingUC.ResolveFinding(r.Context(), tenantID, usecase.ResolveFindingInput{
		FindingID:  findingID,
		Resolution: domain.FindingStatus(input.Resolution),
		Note:       input.Note,
		ResolvedBy: userID.String(),
	})
	if err != nil {
		handleError(w, err)
		return
	}

	respondWithJSON(w, http.StatusOK, finding)
}
