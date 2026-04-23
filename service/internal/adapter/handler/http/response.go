package http

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/sentiae/vigil/service/internal/domain"
)

type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

func respondWithJSON(w http.ResponseWriter, code int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}

func respondWithError(w http.ResponseWriter, code int, message string) {
	respondWithJSON(w, code, errorResponse{Error: http.StatusText(code), Message: message})
}

func handleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrFindingNotFound),
		errors.Is(err, domain.ErrScanNotFound),
		errors.Is(err, domain.ErrAssetNotFound),
		errors.Is(err, domain.ErrNotFound):
		respondWithError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, domain.ErrInvalidFinding),
		errors.Is(err, domain.ErrInvalidScan),
		errors.Is(err, domain.ErrInvalidAsset):
		respondWithError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, domain.ErrDuplicateFinding),
		errors.Is(err, domain.ErrScanInProgress):
		respondWithError(w, http.StatusConflict, err.Error())
	case errors.Is(err, domain.ErrUnauthorized):
		respondWithError(w, http.StatusUnauthorized, err.Error())
	case errors.Is(err, domain.ErrForbidden):
		respondWithError(w, http.StatusForbidden, err.Error())
	default:
		respondWithError(w, http.StatusInternalServerError, "internal server error")
	}
}
