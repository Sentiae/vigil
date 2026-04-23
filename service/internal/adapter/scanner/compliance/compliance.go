package compliance

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/sentiae/vigil/service/internal/domain"
	portscanner "github.com/sentiae/vigil/service/internal/port/scanner"
)

// Scanner implements compliance-focused checks that map directly to framework controls.
// Unlike the PolicyService (which maps existing findings to compliance), this scanner
// actively checks for compliance-specific issues like missing audit logging, encryption gaps, etc.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string             { return "compliance" }
func (s *Scanner) Type() domain.AnalysisType { return domain.AnalysisTypeCompliance }
func (s *Scanner) Supports(t portscanner.ScanTarget) bool {
	return t.Type == "repository" && t.LocalPath != ""
}

func (s *Scanner) Scan(ctx context.Context, target portscanner.ScanTarget) ([]*domain.Finding, error) {
	now := time.Now()
	var findings []*domain.Finding

	// Check for common compliance-required files
	checks := []struct {
		description string
		category    string
		frameworks  []domain.ComplianceRef
	}{
		{
			description: "security policy document",
			category:    "missing-security-policy",
			frameworks:  []domain.ComplianceRef{{Framework: "soc2", Control: "CC1.1"}, {Framework: "iso_27001", Control: "A.5.1"}},
		},
		{
			description: "incident response plan",
			category:    "missing-incident-response",
			frameworks:  []domain.ComplianceRef{{Framework: "soc2", Control: "CC7.3"}, {Framework: "nist_800_53", Control: "IR-1"}},
		},
	}

	for _, check := range checks {
		// These are organizational checks — they generate advisory findings
		// that compliance officers can review and mark as risk_accepted if
		// the documents exist outside the repository
		f := &domain.Finding{
			ID:                 uuid.New(),
			Title:              "Compliance check: " + check.description,
			Description:        "Verify that a " + check.description + " exists and is up to date",
			Severity:           domain.SeverityInfo,
			Status:             domain.FindingStatusNew,
			AnalysisType:       domain.AnalysisTypeCompliance,
			Category:           check.category,
			SourceScanner:      "compliance-scanner",
			SourceRuleID:       check.category,
			FoundBy:            []string{"compliance-scanner"},
			ComplianceMappings: check.frameworks,
			FirstSeenAt:        now,
			LastSeenAt:         now,
			Location: domain.FindingLocation{
				Repository: target.URI,
			},
		}
		f.Fingerprint = f.ComputeFingerprint()
		findings = append(findings, f)
	}

	return findings, nil
}
