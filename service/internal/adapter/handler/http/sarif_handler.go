package http

import (
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/sentiae/vigil/service/internal/domain"
	"github.com/sentiae/vigil/service/internal/middleware"
	"github.com/sentiae/vigil/service/internal/port/repository"
	"github.com/sentiae/vigil/service/internal/usecase"
)

// SARIFHandler accepts raw SARIF v2.1.0 reports from CI and turns them
// into Finding records scoped to the authenticated tenant, tied to
// an implicit Scan record built from commit_sha + analysis_type.
type SARIFHandler struct {
	findings repository.FindingRepository
	scans    repository.ScanRepository
}

func NewSARIFHandler(findings repository.FindingRepository, scans repository.ScanRepository) *SARIFHandler {
	return &SARIFHandler{findings: findings, scans: scans}
}

// HandleIngest is POST /api/v1/security/sarif-reports
//
//	?analysis_type=<sast|dast|sca|secret|iac|…>
//
// Body: the raw SARIF JSON, up to 25 MiB.
func (h *SARIFHandler) HandleIngest(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantIDFromContext(r.Context())
	if tenantID == uuid.Nil {
		respondWithError(w, http.StatusUnauthorized, "tenant_id required")
		return
	}

	analysis := domain.AnalysisType(r.URL.Query().Get("analysis_type"))
	if analysis == "" {
		analysis = domain.AnalysisTypeSAST
	}

	r.Body = http.MaxBytesReader(w, r.Body, 25*1024*1024)
	defer r.Body.Close()
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}

	findings, err := usecase.ParseSARIF(raw, tenantID, analysis)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "parse sarif: "+err.Error())
		return
	}

	// Phase 8: implicit Scan record so findings can be traced back to
	// the CI run that produced them. Commit SHA + analysis type is the
	// minimum identity; branch/target are optional enrichment.
	scanID := uuid.New()
	now := time.Now().UTC()
	q := r.URL.Query()
	scan := &domain.Scan{
		ID:          scanID,
		TenantID:    tenantID,
		Type:        domain.ScanType(analysis),
		Target:      firstNonEmpty(q.Get("target"), q.Get("repo_id"), "sarif-upload"),
		Branch:      q.Get("branch"),
		CommitSHA:   q.Get("commit_sha"),
		Status:      domain.ScanStatusCompleted,
		TriggeredBy: "ci-sarif-upload",
		StartedAt:   &now,
		CompletedAt: &now,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	// Best-effort scan persistence — if the scans table isn't
	// available we still want the findings to land.
	if h.scans != nil {
		if err := h.scans.Create(r.Context(), scan); err != nil {
			scanID = uuid.Nil
		}
	}
	if scanID != uuid.Nil {
		sid := scanID
		for _, f := range findings {
			f.ScanID = &sid
		}
	}

	// De-dup happens in the repository layer via BulkUpsert's
	// fingerprint matching. Returns (created, updated) so the CI
	// uploader can distinguish new findings from repeat noise.
	created, updated, err := h.findings.BulkUpsert(r.Context(), findings)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "persist findings: "+err.Error())
		return
	}
	respondWithJSON(w, http.StatusCreated, map[string]any{
		"parsed":  len(findings),
		"created": created,
		"updated": updated,
		"scan_id": scanID,
	})
}

func firstNonEmpty(xs ...string) string {
	for _, s := range xs {
		if s != "" {
			return s
		}
	}
	return ""
}
