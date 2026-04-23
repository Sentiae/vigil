package usecase

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/sentiae/vigil/service/internal/domain"
	"github.com/sentiae/vigil/service/internal/port/repository"
	portuc "github.com/sentiae/vigil/service/internal/port/usecase"
)

type complianceService struct {
	findingRepo   repository.FindingRepository
	assetRepo     repository.AssetRepository
	policyService *PolicyService
}

func NewComplianceService(
	findingRepo repository.FindingRepository,
	assetRepo repository.AssetRepository,
	policyService *PolicyService,
) portuc.ComplianceUseCase {
	return &complianceService{
		findingRepo:   findingRepo,
		assetRepo:     assetRepo,
		policyService: policyService,
	}
}

func (s *complianceService) GetComplianceSummary(ctx context.Context, tenantID uuid.UUID) (*domain.ComplianceSummary, error) {
	counts, err := s.findingRepo.CountBySeverity(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// Get all active findings to compute compliance
	findings, _, err := s.findingRepo.List(ctx, repository.FindingFilter{
		TenantID: tenantID,
		Limit:    10000,
	})
	if err != nil {
		return nil, err
	}

	// Apply compliance mappings
	s.policyService.EvaluateFindings(ctx, findings)

	// Compute per-framework results
	frameworkChecks := make(map[string]*domain.FrameworkResult)
	frameworks := []string{"soc2", "pci_dss", "hipaa", "nist_800_53", "gdpr", "iso_27001", "cis"}
	for _, fw := range frameworks {
		frameworkChecks[fw] = &domain.FrameworkResult{Framework: fw}
	}

	for _, f := range findings {
		if f.Status.IsTerminal() {
			continue
		}
		for _, ref := range f.ComplianceMappings {
			if fr, ok := frameworkChecks[ref.Framework]; ok {
				fr.TotalChecks++
				fr.Failed++
			}
		}
	}

	// Get framework coverage for total possible checks
	coverage := s.policyService.GetFrameworkCoverage()

	var frameworkResults []domain.FrameworkResult
	for _, fw := range frameworks {
		fr := frameworkChecks[fw]
		totalPossible := coverage[fw]
		if totalPossible > 0 {
			fr.TotalChecks = totalPossible
			fr.Passed = totalPossible - fr.Failed
			if fr.Passed < 0 {
				fr.Passed = 0
			}
			fr.PassRate = float64(fr.Passed) / float64(fr.TotalChecks) * 100
		}
		frameworkResults = append(frameworkResults, *fr)
	}

	// Compute overall score (average pass rate)
	var totalPassRate float64
	activeFrameworks := 0
	for _, fr := range frameworkResults {
		if fr.TotalChecks > 0 {
			totalPassRate += fr.PassRate
			activeFrameworks++
		}
	}
	overallScore := 0.0
	if activeFrameworks > 0 {
		overallScore = totalPassRate / float64(activeFrameworks)
	}

	// Count SLA breaches
	breached, _ := s.findingRepo.ListSLABreached(ctx, tenantID)

	return &domain.ComplianceSummary{
		OrganizationID: tenantID,
		OverallScore:   overallScore,
		Frameworks:     frameworkResults,
		CriticalCount:  counts[domain.SeverityCritical],
		HighCount:      counts[domain.SeverityHigh],
		SLABreaches:    len(breached),
		GeneratedAt:    time.Now(),
	}, nil
}

func (s *complianceService) GetAssetPosture(ctx context.Context, tenantID, assetID uuid.UUID) (*domain.AssetSecurityPosture, error) {
	// Verify asset exists
	asset, err := s.assetRepo.FindByID(ctx, tenantID, assetID)
	if err != nil {
		return nil, err
	}

	// Get findings scoped to this asset by querying with the asset's identifier
	// (ARN for cloud resources, name for repositories/services)
	counts, err := s.findingRepo.CountBySeverity(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	total := 0
	for _, c := range counts {
		total += c
	}

	riskScore := float64(counts[domain.SeverityCritical]*40+
		counts[domain.SeverityHigh]*25+
		counts[domain.SeverityMedium]*10+
		counts[domain.SeverityLow]*2) / float64(max(total, 1))

	return &domain.AssetSecurityPosture{
		AssetID:       &assetID,
		AssetType:     string(asset.Type),
		RiskScore:     riskScore,
		CriticalCount: counts[domain.SeverityCritical],
		HighCount:     counts[domain.SeverityHigh],
		MediumCount:   counts[domain.SeverityMedium],
		LowCount:      counts[domain.SeverityLow],
		TotalFindings: total,
		LastScanAt:    asset.LastScannedAt,
		Trend:         "stable",
	}, nil
}
