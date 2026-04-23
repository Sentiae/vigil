package domain

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ScanType represents the type of security scan.
type ScanType string

const (
	ScanTypeSAST            ScanType = "sast"
	ScanTypeSCA             ScanType = "sca"
	ScanTypeSecretDetection ScanType = "secret_detection"
	ScanTypeIaC             ScanType = "iac"
	ScanTypeContainer       ScanType = "container"
	ScanTypeCloud           ScanType = "cloud"
	ScanTypeNetwork         ScanType = "network"
	ScanTypeCICD            ScanType = "cicd"
	ScanTypeDatabase          ScanType = "database"
	ScanTypeDAST              ScanType = "dast"
	ScanTypeEndpointDiscovery ScanType = "endpoint_discovery"
	ScanTypeAPITest           ScanType = "api_test"
	ScanTypeFull              ScanType = "full"
)

func (t ScanType) Valid() bool {
	switch t {
	case ScanTypeSAST, ScanTypeSCA, ScanTypeSecretDetection, ScanTypeIaC,
		ScanTypeContainer, ScanTypeCloud, ScanTypeNetwork, ScanTypeCICD,
		ScanTypeDatabase, ScanTypeDAST, ScanTypeEndpointDiscovery, ScanTypeAPITest,
		ScanTypeFull:
		return true
	}
	return false
}

// ScanStatus represents the lifecycle status of a scan job.
type ScanStatus string

const (
	ScanStatusQueued    ScanStatus = "queued"
	ScanStatusRunning   ScanStatus = "running"
	ScanStatusCompleted ScanStatus = "completed"
	ScanStatusFailed    ScanStatus = "failed"
)

func (s ScanStatus) Valid() bool {
	switch s {
	case ScanStatusQueued, ScanStatusRunning, ScanStatusCompleted, ScanStatusFailed:
		return true
	}
	return false
}

// Scan represents a security scan job.
type Scan struct {
	ID            uuid.UUID  `json:"id"`
	TenantID      uuid.UUID  `json:"tenant_id"`
	Type          ScanType   `json:"scan_type"`
	Target        string     `json:"target"`
	Branch        string     `json:"branch,omitempty"`
	CommitSHA     string     `json:"commit_sha,omitempty"`
	Status        ScanStatus `json:"status"`
	Priority      string     `json:"priority,omitempty"`
	FindingsNew   int        `json:"findings_new"`
	FindingsTotal int        `json:"findings_total"`
	DurationMs    int64      `json:"duration_ms"`
	Error         string     `json:"error,omitempty"`
	TriggeredBy   string     `json:"triggered_by"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// Validate checks that the scan has all required fields.
func (s *Scan) Validate() error {
	if s.TenantID == uuid.Nil {
		return fmt.Errorf("%w: tenant_id is required", ErrInvalidScan)
	}
	if !s.Type.Valid() {
		return fmt.Errorf("%w: invalid scan_type %q", ErrInvalidScan, s.Type)
	}
	if s.Target == "" {
		return fmt.Errorf("%w: target is required", ErrInvalidScan)
	}
	return nil
}

// MarkRunning transitions the scan to running state.
func (s *Scan) MarkRunning() {
	now := time.Now()
	s.Status = ScanStatusRunning
	s.StartedAt = &now
	s.UpdatedAt = now
}

// MarkCompleted transitions the scan to completed state.
func (s *Scan) MarkCompleted(findingsNew, findingsTotal int) {
	now := time.Now()
	s.Status = ScanStatusCompleted
	s.CompletedAt = &now
	s.FindingsNew = findingsNew
	s.FindingsTotal = findingsTotal
	if s.StartedAt != nil {
		s.DurationMs = now.Sub(*s.StartedAt).Milliseconds()
	}
	s.UpdatedAt = now
}

// MarkFailed transitions the scan to failed state.
func (s *Scan) MarkFailed(errMsg string) {
	now := time.Now()
	s.Status = ScanStatusFailed
	s.CompletedAt = &now
	s.Error = errMsg
	if s.StartedAt != nil {
		s.DurationMs = now.Sub(*s.StartedAt).Milliseconds()
	}
	s.UpdatedAt = now
}
