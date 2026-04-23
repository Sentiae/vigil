package usecase

import (
	"context"
	"sync"

	"github.com/sentiae/vigil/service/internal/domain"
	"github.com/sentiae/vigil/service/pkg/logger"
)

// PolicyService evaluates findings against compliance policies using OPA/Rego.
// In Phase 3, this uses a built-in rule set. Phase 4 will add embedded OPA (github.com/open-policy-agent/opa).
type PolicyService struct {
	mu              sync.RWMutex
	complianceRules map[string][]domain.ComplianceRef // category -> compliance mappings
}

func NewPolicyService() *PolicyService {
	ps := &PolicyService{
		complianceRules: make(map[string][]domain.ComplianceRef),
	}
	ps.loadDefaultRules()
	return ps
}

// EvaluateFinding applies compliance mappings to a finding based on its category.
func (ps *PolicyService) EvaluateFinding(ctx context.Context, f *domain.Finding) []domain.ComplianceRef {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	var mappings []domain.ComplianceRef

	// Match by category
	if refs, ok := ps.complianceRules[f.Category]; ok {
		mappings = append(mappings, refs...)
	}

	// Match by analysis type (broad mappings)
	if refs, ok := ps.complianceRules[string(f.AnalysisType)]; ok {
		mappings = append(mappings, refs...)
	}

	return mappings
}

// EvaluateFindings applies compliance mappings to a batch of findings.
func (ps *PolicyService) EvaluateFindings(ctx context.Context, findings []*domain.Finding) {
	for _, f := range findings {
		refs := ps.EvaluateFinding(ctx, f)
		if len(refs) > 0 {
			f.ComplianceMappings = refs
		}
	}
}

// loadDefaultRules populates the built-in compliance mapping rules.
// These map finding categories/types to compliance framework controls.
func (ps *PolicyService) loadDefaultRules() {
	rules := map[string][]domain.ComplianceRef{
		// Secret detection -> multiple frameworks
		"secret-detection": {
			{Framework: "soc2", Control: "CC6.1"},
			{Framework: "pci_dss", Control: "Req-3.4"},
			{Framework: "hipaa", Control: "164.312(a)(1)"},
			{Framework: "nist_800_53", Control: "SC-12"},
			{Framework: "gdpr", Control: "Art-32"},
		},

		// SQL injection
		"sql-injection": {
			{Framework: "soc2", Control: "CC6.1"},
			{Framework: "pci_dss", Control: "Req-6.5.1"},
			{Framework: "nist_800_53", Control: "SI-10"},
		},

		// XSS
		"xss": {
			{Framework: "pci_dss", Control: "Req-6.5.7"},
			{Framework: "nist_800_53", Control: "SI-10"},
		},

		// Insecure crypto
		"insecure-crypto": {
			{Framework: "pci_dss", Control: "Req-4.1"},
			{Framework: "nist_800_53", Control: "SC-13"},
			{Framework: "hipaa", Control: "164.312(e)(1)"},
		},

		// Vulnerability (SCA)
		"vulnerability": {
			{Framework: "soc2", Control: "CC7.1"},
			{Framework: "pci_dss", Control: "Req-6.2"},
			{Framework: "nist_800_53", Control: "RA-5"},
		},

		// IaC broad mappings
		string(domain.AnalysisTypeIaC): {
			{Framework: "soc2", Control: "CC6.1"},
			{Framework: "cis", Control: "5.1"},
			{Framework: "nist_800_53", Control: "CM-6"},
		},

		// Cloud misconfigurations
		"s3-public-access": {
			{Framework: "pci_dss", Control: "Req-1.3"},
			{Framework: "nist_800_53", Control: "AC-3"},
			{Framework: "cis", Control: "2.1.1"},
		},

		"open-port": {
			{Framework: "pci_dss", Control: "Req-1.2"},
			{Framework: "nist_800_53", Control: "SC-7"},
			{Framework: "cis", Control: "4.1"},
		},

		// Runtime / container
		"privileged-container": {
			{Framework: "cis", Control: "5.2.1"},
			{Framework: "nist_800_53", Control: "AC-6"},
		},

		"container-as-root": {
			{Framework: "cis", Control: "5.2.6"},
			{Framework: "nist_800_53", Control: "AC-6"},
		},
	}

	ps.mu.Lock()
	ps.complianceRules = rules
	ps.mu.Unlock()

	logger.Info(context.TODO(), "Compliance rules loaded", "rule_count", len(rules))
}

// GetFrameworkCoverage returns how many rules map to each framework.
func (ps *PolicyService) GetFrameworkCoverage() map[string]int {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	coverage := make(map[string]int)
	seen := make(map[string]map[string]bool) // framework -> control -> seen

	for _, refs := range ps.complianceRules {
		for _, ref := range refs {
			if seen[ref.Framework] == nil {
				seen[ref.Framework] = make(map[string]bool)
			}
			if !seen[ref.Framework][ref.Control] {
				seen[ref.Framework][ref.Control] = true
				coverage[ref.Framework]++
			}
		}
	}

	return coverage
}
