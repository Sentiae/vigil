package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/sentiae/vigil/service/internal/middleware"
	"github.com/sentiae/vigil/service/internal/port/usecase"
)

type ComplianceHandler struct {
	complianceUC usecase.ComplianceUseCase
}

func NewComplianceHandler(complianceUC usecase.ComplianceUseCase) *ComplianceHandler {
	return &ComplianceHandler{complianceUC: complianceUC}
}

func (h *ComplianceHandler) GetComplianceSummary(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantIDFromContext(r.Context())
	if tenantID == uuid.Nil {
		respondWithError(w, http.StatusUnauthorized, "tenant_id required")
		return
	}

	summary, err := h.complianceUC.GetComplianceSummary(r.Context(), tenantID)
	if err != nil {
		handleError(w, err)
		return
	}

	respondWithJSON(w, http.StatusOK, summary)
}

func (h *ComplianceHandler) GetAssetPosture(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantIDFromContext(r.Context())
	assetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid asset id")
		return
	}

	posture, err := h.complianceUC.GetAssetPosture(r.Context(), tenantID, assetID)
	if err != nil {
		handleError(w, err)
		return
	}

	respondWithJSON(w, http.StatusOK, posture)
}
