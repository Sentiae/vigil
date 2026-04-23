package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Severity represents the severity level of a finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

func (s Severity) Valid() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return true
	}
	return false
}

// FindingStatus represents the lifecycle status of a finding.
type FindingStatus string

const (
	FindingStatusNew          FindingStatus = "new"
	FindingStatusConfirmed    FindingStatus = "confirmed"
	FindingStatusInProgress   FindingStatus = "in_progress"
	FindingStatusResolved     FindingStatus = "resolved"
	FindingStatusFalsePositive FindingStatus = "false_positive"
	FindingStatusRiskAccepted FindingStatus = "risk_accepted"
)

func (s FindingStatus) Valid() bool {
	switch s {
	case FindingStatusNew, FindingStatusConfirmed, FindingStatusInProgress,
		FindingStatusResolved, FindingStatusFalsePositive, FindingStatusRiskAccepted:
		return true
	}
	return false
}

func (s FindingStatus) IsTerminal() bool {
	return s == FindingStatusResolved || s == FindingStatusFalsePositive || s == FindingStatusRiskAccepted
}

// AnalysisType represents the type of security analysis.
type AnalysisType string

const (
	AnalysisTypeSAST            AnalysisType = "sast"
	AnalysisTypeSCA             AnalysisType = "sca"
	AnalysisTypeSecretDetection AnalysisType = "secret_detection"
	AnalysisTypeIaC             AnalysisType = "iac"
	AnalysisTypeContainer       AnalysisType = "container"
	AnalysisTypeCloud           AnalysisType = "cloud"
	AnalysisTypeNetwork         AnalysisType = "network"
	AnalysisTypeRuntime         AnalysisType = "runtime"
	AnalysisTypeCICD            AnalysisType = "cicd"
	AnalysisTypeDatabase        AnalysisType = "database"
	AnalysisTypeCompliance      AnalysisType = "compliance"
	AnalysisTypeDAST            AnalysisType = "dast"
)

func (t AnalysisType) Valid() bool {
	switch t {
	case AnalysisTypeSAST, AnalysisTypeSCA, AnalysisTypeSecretDetection,
		AnalysisTypeIaC, AnalysisTypeContainer, AnalysisTypeCloud,
		AnalysisTypeNetwork, AnalysisTypeRuntime, AnalysisTypeCICD,
		AnalysisTypeDatabase, AnalysisTypeCompliance, AnalysisTypeDAST:
		return true
	}
	return false
}

// VEXState represents the CycloneDX-aligned vulnerability exploitation state.
type VEXState string

const (
	VEXExploitable  VEXState = "exploitable"
	VEXNotAffected  VEXState = "not_affected"
	VEXResolved     VEXState = "resolved"
	VEXFalsePositive VEXState = "false_positive"
)

// Finding represents a universal security finding from any analysis domain.
type Finding struct {
	// Identity
	ID            uuid.UUID  `json:"id"`
	TenantID      uuid.UUID  `json:"tenant_id"`
	ScanID        *uuid.UUID `json:"scan_id,omitempty"`
	Fingerprint   string     `json:"fingerprint"`
	CorrelationID *uuid.UUID `json:"correlation_id,omitempty"`

	// Classification
	Title           string        `json:"title"`
	Description     string        `json:"description"`
	Severity        Severity      `json:"severity"`
	NormalizedScore float64       `json:"normalized_score"`
	Status          FindingStatus `json:"status"`
	AnalysisType    AnalysisType  `json:"analysis_type"`
	Category        string        `json:"category"`

	// Source
	SourceScanner string   `json:"source_scanner"`
	SourceRuleID  string   `json:"source_rule_id"`
	FoundBy       []string `json:"found_by"`

	// Vulnerability references
	CVEs      []string `json:"cves"`
	CWEs      []int    `json:"cwes"`
	CVSSScore *float64 `json:"cvss_score,omitempty"`
	CVSSVector string  `json:"cvss_vector,omitempty"`
	EPSSScore *float64 `json:"epss_score,omitempty"`

	// Polymorphic location (stored as JSONB)
	Location FindingLocation `json:"location"`

	// Remediation
	Remediation string   `json:"remediation"`
	References  []string `json:"references"`

	// Compliance
	ComplianceMappings []ComplianceRef `json:"compliance_mappings"`

	// Lifecycle
	FirstSeenAt time.Time  `json:"first_seen_at"`
	LastSeenAt  time.Time  `json:"last_seen_at"`
	SLADeadline *time.Time `json:"sla_deadline,omitempty"`
	VEXState    *VEXState  `json:"vex_state,omitempty"`

	// Extensibility
	Metadata map[string]any `json:"metadata,omitempty"`
	Tags     []string       `json:"tags,omitempty"`
}

// FindingLocation is the polymorphic location field stored as JSONB.
type FindingLocation struct {
	// Code / SAST / Secrets
	FilePath    string `json:"file_path,omitempty"`
	LineStart   *int   `json:"line_start,omitempty"`
	LineEnd     *int   `json:"line_end,omitempty"`
	CodeSnippet string `json:"code_snippet,omitempty"`
	CommitSHA   string `json:"commit_sha,omitempty"`
	Repository  string `json:"repository,omitempty"`
	Branch      string `json:"branch,omitempty"`

	// Container / SCA
	ContainerImage string `json:"container_image,omitempty"`
	ImageDigest    string `json:"image_digest,omitempty"`
	PackageName    string `json:"package_name,omitempty"`
	PackageVersion string `json:"package_version,omitempty"`
	FixedInVersion string `json:"fixed_in_version,omitempty"`

	// Cloud / IaC / CSPM
	CloudProvider  string `json:"cloud_provider,omitempty"`
	CloudAccountID string `json:"cloud_account_id,omitempty"`
	CloudRegion    string `json:"cloud_region,omitempty"`
	ResourceARN    string `json:"resource_arn,omitempty"`
	ResourceType   string `json:"resource_type,omitempty"`

	// Network / Runtime
	Hostname  string `json:"hostname,omitempty"`
	IPAddress string `json:"ip_address,omitempty"`
	Port      *int   `json:"port,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	URLPath   string `json:"url_path,omitempty"`
}

// Validate checks that the finding has all required fields.
func (f *Finding) Validate() error {
	if f.TenantID == uuid.Nil {
		return fmt.Errorf("%w: tenant_id is required", ErrInvalidFinding)
	}
	if f.Title == "" {
		return fmt.Errorf("%w: title is required", ErrInvalidFinding)
	}
	if !f.Severity.Valid() {
		return fmt.Errorf("%w: invalid severity %q", ErrInvalidFinding, f.Severity)
	}
	if !f.AnalysisType.Valid() {
		return fmt.Errorf("%w: invalid analysis_type %q", ErrInvalidFinding, f.AnalysisType)
	}
	if f.SourceScanner == "" {
		return fmt.Errorf("%w: source_scanner is required", ErrInvalidFinding)
	}
	return nil
}

// ComputeFingerprint generates a deterministic dedup hash for this finding.
func (f *Finding) ComputeFingerprint() string {
	var input string
	switch f.AnalysisType {
	case AnalysisTypeSAST:
		input = fmt.Sprintf("%s|%s|%d|%s", f.SourceRuleID, f.Location.FilePath, ptrIntVal(f.Location.LineStart), f.Location.CodeSnippet)
	case AnalysisTypeSCA, AnalysisTypeContainer:
		cve := ""
		if len(f.CVEs) > 0 {
			cve = f.CVEs[0]
		}
		input = fmt.Sprintf("%s|%s|%s|%s", cve, f.Location.PackageName, f.Location.PackageVersion, f.Location.ImageDigest)
	case AnalysisTypeCloud, AnalysisTypeIaC:
		input = fmt.Sprintf("%s|%s|%s", f.SourceRuleID, f.Location.ResourceARN, f.Location.ResourceType)
	case AnalysisTypeNetwork, AnalysisTypeRuntime:
		input = fmt.Sprintf("%s|%s|%d|%s", f.SourceRuleID, f.Location.Hostname, ptrIntVal(f.Location.Port), f.Location.FilePath)
	case AnalysisTypeSecretDetection:
		input = fmt.Sprintf("%s|%s|%s|%d", f.SourceRuleID, f.Location.CommitSHA, f.Location.FilePath, ptrIntVal(f.Location.LineStart))
	default:
		input = fmt.Sprintf("%s|%s|%s", f.SourceRuleID, f.Title, f.Category)
	}

	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

func ptrIntVal(p *int) int {
	if p != nil {
		return *p
	}
	return 0
}
