// Package http — HTTP surface for §11.2 code intelligence.
//
// Routes:
//
//   GET  /api/v1/code/embeddings/search?repo_id=X&q=...&limit=20
//   GET  /api/v1/code/entry-points?repo_id=X&kind=http_route
//   POST /api/v1/code/entry-points/detect   (body: {path, repo_id})
//
// The handlers stay stateless — their job is param parsing +
// delegation. Heavy lifting lives in the usecase layer.
package http

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/sentiae/vigil/service/internal/infrastructure/scip"
	"github.com/sentiae/vigil/service/internal/usecase"
)

// EntryPointLister reads entry_points for a repo. Implemented by the
// postgres repo but accepted as a narrow interface here so the handler
// stays testable without hauling in the DB.
type EntryPointLister interface {
	List(ctx context.Context, tenantID, repoID uuid.UUID, kind string) ([]usecase.EntryPoint, error)
}

// SCIPStore persists raw SCIP proto bytes. The handler depends on the
// narrow interface so the real postgres repo can be swapped for a fake.
type SCIPStore interface {
	Save(ctx context.Context, tenantID, repoID uuid.UUID, commitSHA, language string, proto []byte) error
}

// CodeIntelligenceHandler groups the §11.2 endpoints so one container
// field can host them all. Any dep can be nil — the handler returns
// 501 for the corresponding routes when it is.
type CodeIntelligenceHandler struct {
	embeddings *usecase.EmbeddingIndexer
	detector   *usecase.EntryPointDetector
	lister     EntryPointLister
	scip       scip.Indexer
	scipStore  SCIPStore
}

// NewCodeIntelligenceHandler wires the deps.
func NewCodeIntelligenceHandler(embeddings *usecase.EmbeddingIndexer, detector *usecase.EntryPointDetector, lister EntryPointLister) *CodeIntelligenceHandler {
	return &CodeIntelligenceHandler{
		embeddings: embeddings,
		detector:   detector,
		lister:     lister,
	}
}

// WithSCIP wires the on-demand SCIP indexer + storage. Optional — when
// not set the /scip/index endpoint returns 501.
func (h *CodeIntelligenceHandler) WithSCIP(idx scip.Indexer, store SCIPStore) *CodeIntelligenceHandler {
	h.scip = idx
	h.scipStore = store
	return h
}

// EmbeddingSearchResponse is the wrapped search payload.
type EmbeddingSearchResponse struct {
	Hits []usecase.EmbeddingSearchHit `json:"hits"`
}

// HandleEmbeddingSearch implements GET /embeddings/search.
func (h *CodeIntelligenceHandler) HandleEmbeddingSearch(w http.ResponseWriter, r *http.Request) {
	if h.embeddings == nil {
		respondWithError(w, http.StatusNotImplemented, "embedding indexer not configured")
		return
	}
	q := r.URL.Query().Get("q")
	if q == "" {
		respondWithError(w, http.StatusBadRequest, "q query parameter is required")
		return
	}
	repoIDStr := r.URL.Query().Get("repo_id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid repo_id")
		return
	}
	limit := 20
	if n := r.URL.Query().Get("limit"); n != "" {
		if v, err := strconv.Atoi(n); err == nil && v > 0 {
			limit = v
		}
	}
	hits, err := h.embeddings.Search(r.Context(), usecase.SearchInput{
		RepoID: repoID,
		Query:  q,
		Limit:  limit,
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondWithJSON(w, http.StatusOK, EmbeddingSearchResponse{Hits: hits})
}

// EntryPointListResponse wraps the payload consistently with other GETs.
type EntryPointListResponse struct {
	EntryPoints []usecase.EntryPoint `json:"entry_points"`
}

// HandleListEntryPoints implements GET /entry-points.
func (h *CodeIntelligenceHandler) HandleListEntryPoints(w http.ResponseWriter, r *http.Request) {
	if h.lister == nil {
		respondWithError(w, http.StatusNotImplemented, "entry-point store not configured")
		return
	}
	repoIDStr := r.URL.Query().Get("repo_id")
	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid repo_id")
		return
	}
	kind := r.URL.Query().Get("kind")
	tenantIDStr := r.URL.Query().Get("tenant_id")
	tenantID, _ := uuid.Parse(tenantIDStr) // optional — many deployments query by repo only

	eps, err := h.lister.List(r.Context(), tenantID, repoID, kind)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondWithJSON(w, http.StatusOK, EntryPointListResponse{EntryPoints: eps})
}

// DetectEntryPointsRequest is the POST body for on-demand detection.
type DetectEntryPointsRequest struct {
	Path     string    `json:"path"`
	RepoID   uuid.UUID `json:"repo_id"`
	TenantID uuid.UUID `json:"tenant_id"`
}

// DetectEntryPointsResponse mirrors the list shape so consumers can
// pipe either endpoint into the same UI path.
type DetectEntryPointsResponse struct {
	EntryPoints []usecase.EntryPoint `json:"entry_points"`
}

// SCIPIndexRequest triggers an on-demand SCIP index for a single
// language. The worker binary clones the repo first and passes the
// local path.
type SCIPIndexRequest struct {
	Path      string    `json:"path"`
	Language  string    `json:"language"`
	TenantID  uuid.UUID `json:"tenant_id"`
	RepoID    uuid.UUID `json:"repo_id"`
	CommitSHA string    `json:"commit_sha"`
}

// SCIPIndexResponse summarizes the run — bytes generated, whether the
// CLI was even available locally, etc.
type SCIPIndexResponse struct {
	ByteSize int    `json:"byte_size"`
	Language string `json:"language"`
	Stored   bool   `json:"stored"`
}

// EmbedReindexRequest triggers an embedding reindex for a repo.
// Intended to be called by the ingest worker after tree-sitter
// parsing has persisted symbols. The worker must supply a lister
// override since the container wires a noop by default; for now we
// expose the entry-point detection as a quick follow-up hook.
type EmbedReindexRequest struct {
	TenantID  uuid.UUID `json:"tenant_id"`
	RepoID    uuid.UUID `json:"repo_id"`
	CommitSHA string    `json:"commit_sha"`
}

// EmbedReindexResponse confirms accept.
type EmbedReindexResponse struct {
	Accepted bool `json:"accepted"`
}

// HandleEmbeddingReindex implements POST /embeddings/reindex.
// It triggers the configured indexer's IndexRepository pass using the
// container-wired symbol source lister. With the default noop lister
// the call succeeds as a no-op — the worker binary is expected to
// override with a real lister.
func (h *CodeIntelligenceHandler) HandleEmbeddingReindex(w http.ResponseWriter, r *http.Request) {
	if h.embeddings == nil {
		respondWithError(w, http.StatusNotImplemented, "embedding indexer not configured")
		return
	}
	var req EmbedReindexRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := h.embeddings.IndexRepository(r.Context(), req.TenantID, req.RepoID, req.CommitSHA); err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondWithJSON(w, http.StatusAccepted, EmbedReindexResponse{Accepted: true})
}

// HandleSCIPIndex implements POST /scip/index.
func (h *CodeIntelligenceHandler) HandleSCIPIndex(w http.ResponseWriter, r *http.Request) {
	if h.scip == nil {
		respondWithError(w, http.StatusNotImplemented, "SCIP indexer not configured")
		return
	}
	var req SCIPIndexRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Path == "" || req.Language == "" {
		respondWithError(w, http.StatusBadRequest, "path and language are required")
		return
	}
	body, err := h.scip.Index(r.Context(), req.Path, req.Language)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	stored := false
	if h.scipStore != nil {
		if err := h.scipStore.Save(r.Context(), req.TenantID, req.RepoID, req.CommitSHA, req.Language, body); err != nil {
			respondWithError(w, http.StatusInternalServerError, err.Error())
			return
		}
		stored = true
	}
	respondWithJSON(w, http.StatusOK, SCIPIndexResponse{
		ByteSize: len(body),
		Language: req.Language,
		Stored:   stored,
	})
}

// HandleDetectEntryPoints implements POST /entry-points/detect.
func (h *CodeIntelligenceHandler) HandleDetectEntryPoints(w http.ResponseWriter, r *http.Request) {
	if h.detector == nil {
		respondWithError(w, http.StatusNotImplemented, "entry-point detector not configured")
		return
	}
	var req DetectEntryPointsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Path == "" {
		respondWithError(w, http.StatusBadRequest, "path is required")
		return
	}
	eps, err := h.detector.DetectEntryPoints(r.Context(), req.TenantID, req.RepoID, req.Path)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondWithJSON(w, http.StatusOK, DetectEntryPointsResponse{EntryPoints: eps})
}
