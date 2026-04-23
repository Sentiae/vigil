package http

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/sentiae/vigil/service/internal/usecase"
)

// FrameworkHandler exposes B10 — framework detection (§11.2).
//
// The handler is intentionally stateless: the caller supplies the
// project root (either via request body for ad-hoc analysis or via
// projectID lookup for a previously-cloned workspace). We don't
// fan out to git-service from here; the BFF or a cron consumer does
// the clone and then posts the path.
type FrameworkHandler struct {
	detector *usecase.FrameworkDetector
	// resolver maps a projectID from the URL into an absolute path
	// on the worker filesystem. nil in the default wiring — the BFF
	// passes the path on the request body — but we accept it so the
	// worker binary can inject a real resolver without touching this
	// handler.
	resolver func(projectID string) (string, error)
}

// NewFrameworkHandler wires the handler with the default detector.
// Pass nil resolver for body-driven detection.
func NewFrameworkHandler(resolver func(string) (string, error)) *FrameworkHandler {
	return &FrameworkHandler{
		detector: usecase.NewFrameworkDetector(),
		resolver: resolver,
	}
}

// FrameworkAnalyzeRequest is the body shape for the body-driven path.
type FrameworkAnalyzeRequest struct {
	Path string `json:"path"`
}

// FrameworkAnalyzeResponse wraps the detector output under a top-level
// key so we have room to add scan metadata (duration, file count, etc.)
// without breaking the client.
type FrameworkAnalyzeResponse struct {
	Frameworks []usecase.DetectedFramework `json:"frameworks"`
}

// HandleAnalyze is GET /analyze/{projectID}/frameworks (resolver path)
// or POST /analyze/frameworks (body path). We switch on whether the
// projectID URL param is populated.
func (h *FrameworkHandler) HandleAnalyze(w http.ResponseWriter, r *http.Request) {
	var path string

	if projectID := chi.URLParam(r, "projectID"); projectID != "" {
		if h.resolver == nil {
			respondWithError(w, http.StatusServiceUnavailable, "project resolver not configured; post path in body instead")
			return
		}
		p, err := h.resolver(projectID)
		if err != nil {
			respondWithError(w, http.StatusNotFound, err.Error())
			return
		}
		path = p
	} else {
		var req FrameworkAnalyzeRequest
		if r.Body != nil && r.ContentLength != 0 {
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				respondWithError(w, http.StatusBadRequest, "invalid request body")
				return
			}
		}
		path = req.Path
	}

	if path == "" {
		respondWithError(w, http.StatusBadRequest, "path is required")
		return
	}

	frameworks, err := h.detector.Detect(path)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	respondWithJSON(w, http.StatusOK, FrameworkAnalyzeResponse{Frameworks: frameworks})
}
