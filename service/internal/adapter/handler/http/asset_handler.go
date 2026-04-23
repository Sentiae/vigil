package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/sentiae/vigil/service/internal/middleware"
	"github.com/sentiae/vigil/service/internal/port/repository"
)

// AssetHandler serves graph-based asset security endpoints.
type AssetHandler struct {
	graphRepo repository.GraphRepository
}

func NewAssetHandler(graphRepo repository.GraphRepository) *AssetHandler {
	return &AssetHandler{graphRepo: graphRepo}
}

func (h *AssetHandler) GetBlastRadius(w http.ResponseWriter, r *http.Request) {
	if h.graphRepo == nil {
		respondWithError(w, http.StatusServiceUnavailable, "graph database not available")
		return
	}

	tenantID := middleware.GetTenantIDFromContext(r.Context())
	assetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid asset id")
		return
	}

	radius, err := h.graphRepo.BlastRadius(r.Context(), tenantID, assetID, 3)
	if err != nil {
		handleError(w, err)
		return
	}

	respondWithJSON(w, http.StatusOK, radius)
}

func (h *AssetHandler) GetAttackPaths(w http.ResponseWriter, r *http.Request) {
	if h.graphRepo == nil {
		respondWithError(w, http.StatusServiceUnavailable, "graph database not available")
		return
	}

	tenantID := middleware.GetTenantIDFromContext(r.Context())
	assetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid asset id")
		return
	}

	paths, err := h.graphRepo.AttackPaths(r.Context(), tenantID, assetID)
	if err != nil {
		handleError(w, err)
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]any{
		"attack_paths": paths,
		"total":        len(paths),
	})
}
