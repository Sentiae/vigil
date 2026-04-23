package http

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/sentiae/vigil/service/internal/domain"
	"github.com/sentiae/vigil/service/internal/middleware"
	"github.com/sentiae/vigil/service/internal/usecase"
)

// CoverageHandler exposes the Phase-8 coverage ingest + query surface.
//
// Ingest accepts a raw tracefile with query-string metadata so CI
// uploaders (curl in a GitHub Action) stay simple — no multi-part body
// or JSON envelope.
type CoverageHandler struct {
	svc *usecase.CoverageService
}

func NewCoverageHandler(svc *usecase.CoverageService) *CoverageHandler {
	return &CoverageHandler{svc: svc}
}

// HandleIngest is POST /api/v1/security/coverage-reports
//
//	?repo_id=<owner/name>&commit_sha=<sha>&branch=<branch>&format=<lcov|go_coverprofile>
//
// Body: the raw tracefile, up to 25 MiB (large monorepos can produce
// LCOV files in the low MiB; 25 MiB buffers future growth).
func (h *CoverageHandler) HandleIngest(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantIDFromContext(r.Context())
	if tenantID == uuid.Nil {
		respondWithError(w, http.StatusUnauthorized, "tenant_id required")
		return
	}
	q := r.URL.Query()
	repoID := q.Get("repo_id")
	if repoID == "" {
		respondWithError(w, http.StatusBadRequest, "repo_id query param is required")
		return
	}
	format := domain.CoverageFormat(q.Get("format"))
	if format == "" {
		format = domain.CoverageFormatLCOV
	}

	r.Body = http.MaxBytesReader(w, r.Body, 25*1024*1024)
	defer r.Body.Close()

	report, err := h.svc.Ingest(r.Context(), usecase.CoverageIngestInput{
		OrgID:     tenantID,
		RepoID:    repoID,
		CommitSHA: q.Get("commit_sha"),
		Branch:    q.Get("branch"),
		Format:    format,
		Body:      r.Body,
	})
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	respondWithJSON(w, http.StatusCreated, report)
}

// HandleGetLatest is GET /api/v1/security/coverage?repo_id=<id>
// Returns 200 with the full report or 200 with `{"coverage":null}`
// when no report has been ingested yet — keeps the BFF happy without
// a 404-vs-empty branch.
func (h *CoverageHandler) HandleGetLatest(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantIDFromContext(r.Context())
	if tenantID == uuid.Nil {
		respondWithError(w, http.StatusUnauthorized, "tenant_id required")
		return
	}
	repoID := r.URL.Query().Get("repo_id")
	if repoID == "" {
		respondWithError(w, http.StatusBadRequest, "repo_id query param is required")
		return
	}
	report, err := h.svc.GetLatest(r.Context(), tenantID, repoID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondWithJSON(w, http.StatusOK, map[string]interface{}{"coverage": report})
}

// HandleByFile is GET /api/v1/security/coverage/by-file?repo_id=<id>
// and returns `{files: {"path": fraction, ...}}`. This is the shape
// the risk-zone pipeline consumes; kept separate from HandleGetLatest
// because the BFF doesn't need the full per-line record for blending.
func (h *CoverageHandler) HandleByFile(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantIDFromContext(r.Context())
	if tenantID == uuid.Nil {
		respondWithError(w, http.StatusUnauthorized, "tenant_id required")
		return
	}
	repoID := r.URL.Query().Get("repo_id")
	if repoID == "" {
		respondWithError(w, http.StatusBadRequest, "repo_id query param is required")
		return
	}
	m, err := h.svc.CoverageByFile(r.Context(), tenantID, repoID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Mirror the shape the risk-zone handler accepts so the BFF can
	// forward it verbatim.
	respondWithJSON(w, http.StatusOK, map[string]any{"files": m})
}
