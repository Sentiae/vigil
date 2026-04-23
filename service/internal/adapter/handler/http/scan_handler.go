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

type ScanHandler struct {
	scanUC usecase.ScanUseCase
}

func NewScanHandler(scanUC usecase.ScanUseCase) *ScanHandler {
	return &ScanHandler{scanUC: scanUC}
}

func (h *ScanHandler) ListScans(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantIDFromContext(r.Context())

	filter := repository.ScanFilter{
		TenantID: tenantID,
	}

	if status := r.URL.Query().Get("status"); status != "" {
		s := domain.ScanStatus(status)
		filter.Status = &s
	}
	if limit := r.URL.Query().Get("limit"); limit != "" {
		if n, err := strconv.Atoi(limit); err == nil {
			filter.Limit = n
		}
	}

	scans, total, err := h.scanUC.ListScans(r.Context(), filter)
	if err != nil {
		handleError(w, err)
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]any{
		"scans": scans,
		"total": total,
	})
}

func (h *ScanHandler) GetScan(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantIDFromContext(r.Context())
	scanID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid scan id")
		return
	}

	scan, err := h.scanUC.GetScan(r.Context(), tenantID, scanID)
	if err != nil {
		handleError(w, err)
		return
	}

	respondWithJSON(w, http.StatusOK, scan)
}

func (h *ScanHandler) TriggerScan(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantIDFromContext(r.Context())

	var input struct {
		ScanType string `json:"scan_type"`
		Target   string `json:"target"`
		Branch   string `json:"branch"`
		Priority string `json:"priority"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	userID := middleware.GetUserIDFromContext(r.Context())

	scan, err := h.scanUC.TriggerScan(r.Context(), usecase.TriggerScanInput{
		TenantID:    tenantID,
		ScanType:    domain.ScanType(input.ScanType),
		Target:      input.Target,
		Branch:      input.Branch,
		Priority:    input.Priority,
		TriggeredBy: userID.String(),
	})
	if err != nil {
		handleError(w, err)
		return
	}

	respondWithJSON(w, http.StatusCreated, scan)
}
