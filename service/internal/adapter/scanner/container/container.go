package container

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/sentiae/vigil/service/internal/adapter/scanner"
	"github.com/sentiae/vigil/service/internal/domain"
	portscanner "github.com/sentiae/vigil/service/internal/port/scanner"
	"github.com/sentiae/vigil/service/internal/usecase"
	"github.com/sentiae/vigil/service/pkg/logger"
)

// Scanner implements container image scanning using Grype and Trivy.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string             { return "container" }
func (s *Scanner) Type() domain.AnalysisType { return domain.AnalysisTypeContainer }
func (s *Scanner) Supports(t portscanner.ScanTarget) bool {
	return t.Type == "image" || (t.Type == "repository" && t.LocalPath != "")
}

func (s *Scanner) Scan(ctx context.Context, target portscanner.ScanTarget) ([]*domain.Finding, error) {
	var allFindings []*domain.Finding

	scanTarget := target.URI
	if target.Type == "repository" {
		scanTarget = fmt.Sprintf("dir:%s", target.LocalPath)
	}

	// Grype for vulnerability matching on container images
	if scanner.CommandExists("grype") {
		findings, err := s.runGrype(ctx, scanTarget)
		if err != nil {
			logger.Warn(ctx, "Grype container scan failed", "error", err)
		} else {
			allFindings = append(allFindings, findings...)
		}
	}

	// Trivy for container-specific checks (secrets in layers, misconfigs)
	if scanner.CommandExists("trivy") {
		findings, err := s.runTrivy(ctx, scanTarget)
		if err != nil {
			logger.Warn(ctx, "Trivy container scan failed", "error", err)
		} else {
			allFindings = append(allFindings, findings...)
		}
	}

	return allFindings, nil
}

func (s *Scanner) runGrype(ctx context.Context, target string) ([]*domain.Finding, error) {
	result, err := scanner.RunSubprocess(ctx, "grype", target, "-o", "json", "--quiet")
	if err != nil {
		return nil, fmt.Errorf("grype: %w", err)
	}
	if len(result.Stdout) == 0 {
		return nil, nil
	}
	findings, err := usecase.ParseGrypeJSON(result.Stdout, uuid.Nil)
	if err != nil {
		return nil, err
	}
	// Re-tag as container analysis type
	for _, f := range findings {
		f.AnalysisType = domain.AnalysisTypeContainer
	}
	return findings, nil
}

func (s *Scanner) runTrivy(ctx context.Context, target string) ([]*domain.Finding, error) {
	result, err := scanner.RunSubprocess(ctx,
		"trivy", "image",
		"--scanners", "vuln,secret",
		"--format", "sarif",
		"--quiet",
		target,
	)
	if err != nil {
		return nil, fmt.Errorf("trivy: %w", err)
	}
	if len(result.Stdout) == 0 {
		return nil, nil
	}
	return usecase.ParseSARIF(result.Stdout, uuid.Nil, domain.AnalysisTypeContainer)
}
