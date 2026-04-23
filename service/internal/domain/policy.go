package domain

import (
	"time"

	"github.com/google/uuid"
)

// ComplianceFramework represents a supported compliance framework.
type ComplianceFramework string

const (
	FrameworkSOC2    ComplianceFramework = "soc2"
	FrameworkPCIDSS  ComplianceFramework = "pci_dss"
	FrameworkHIPAA   ComplianceFramework = "hipaa"
	FrameworkNIST    ComplianceFramework = "nist_800_53"
	FrameworkGDPR    ComplianceFramework = "gdpr"
	FrameworkISO27001 ComplianceFramework = "iso_27001"
	FrameworkCIS     ComplianceFramework = "cis"
)

// ComplianceRef maps a finding to a specific compliance framework control.
type ComplianceRef struct {
	Framework string `json:"framework"`
	Control   string `json:"control"`
}

// SLAPolicy defines the SLA deadlines for a given severity and environment.
type SLAPolicy struct {
	ID                    uuid.UUID `json:"id"`
	TenantID              uuid.UUID `json:"tenant_id"`
	Severity              Severity  `json:"severity"`
	ProductionDeadline    time.Duration `json:"production_deadline"`
	NonProductionDeadline time.Duration `json:"non_production_deadline"`
}

// DefaultSLAPolicies returns the default SLA deadlines.
func DefaultSLAPolicies() []SLAPolicy {
	return []SLAPolicy{
		{Severity: SeverityCritical, ProductionDeadline: 24 * time.Hour, NonProductionDeadline: 72 * time.Hour},
		{Severity: SeverityHigh, ProductionDeadline: 7 * 24 * time.Hour, NonProductionDeadline: 14 * 24 * time.Hour},
		{Severity: SeverityMedium, ProductionDeadline: 30 * 24 * time.Hour, NonProductionDeadline: 60 * 24 * time.Hour},
		{Severity: SeverityLow, ProductionDeadline: 90 * 24 * time.Hour, NonProductionDeadline: 180 * 24 * time.Hour},
	}
}

// ComplianceSummary represents the compliance posture for an organization.
type ComplianceSummary struct {
	OrganizationID uuid.UUID         `json:"organization_id"`
	OverallScore   float64           `json:"overall_score"`
	Frameworks     []FrameworkResult `json:"frameworks"`
	CriticalCount  int               `json:"critical_count"`
	HighCount      int               `json:"high_count"`
	SLABreaches    int               `json:"sla_breaches"`
	GeneratedAt    time.Time         `json:"generated_at"`
}

// FrameworkResult represents the compliance status for a single framework.
type FrameworkResult struct {
	Framework   string  `json:"framework"`
	PassRate    float64 `json:"pass_rate"`
	TotalChecks int     `json:"total_checks"`
	Passed      int     `json:"passed"`
	Failed      int     `json:"failed"`
}

// AssetSecurityPosture represents the security risk profile of an asset.
type AssetSecurityPosture struct {
	AssetID       *uuid.UUID `json:"asset_id,omitempty"`
	AssetType     string     `json:"asset_type,omitempty"`
	RiskScore     float64    `json:"risk_score"`
	CriticalCount int        `json:"critical_count"`
	HighCount     int        `json:"high_count"`
	MediumCount   int        `json:"medium_count"`
	LowCount      int        `json:"low_count"`
	TotalFindings int        `json:"total_findings"`
	LastScanAt    *time.Time `json:"last_scan_at,omitempty"`
	Trend         string     `json:"trend"`
}
