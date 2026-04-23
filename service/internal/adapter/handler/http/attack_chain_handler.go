package http

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/sentiae/vigil/service/internal/middleware"
	"github.com/sentiae/vigil/service/internal/usecase"
)

type AttackChainHandler struct {
	attackChainSvc *usecase.AttackChainService
}

func NewAttackChainHandler(svc *usecase.AttackChainService) *AttackChainHandler {
	return &AttackChainHandler{attackChainSvc: svc}
}

func (h *AttackChainHandler) GetAttackChains(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantIDFromContext(r.Context())
	if tenantID == uuid.Nil {
		respondWithError(w, http.StatusUnauthorized, "tenant_id required")
		return
	}

	chains, err := h.attackChainSvc.Analyze(r.Context(), tenantID)
	if err != nil {
		handleError(w, err)
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]any{
		"attack_chains": chains,
		"total":         len(chains),
	})
}
