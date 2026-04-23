package scanner

import (
	"context"

	"github.com/sentiae/vigil/service/internal/domain"
)

// ScanTarget describes what should be scanned.
type ScanTarget struct {
	Type      string `json:"type"`       // repository, image, cloud_account
	URI       string `json:"uri"`        // repo URL, image ref, account ID
	Branch    string `json:"branch"`
	CommitSHA string `json:"commit_sha"`
	DiffOnly  bool   `json:"diff_only"`  // PR-scoped scan
	LocalPath string `json:"local_path"` // cloned repo path on worker
}

// Scanner is the interface that all analysis modules implement.
type Scanner interface {
	// Name returns the unique name of this scanner.
	Name() string

	// Type returns the analysis type this scanner produces.
	Type() domain.AnalysisType

	// Scan executes the analysis and returns discovered findings.
	Scan(ctx context.Context, target ScanTarget) ([]*domain.Finding, error)

	// Supports returns true if this scanner can handle the given target.
	Supports(target ScanTarget) bool
}
