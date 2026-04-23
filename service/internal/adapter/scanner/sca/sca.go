package sca

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

// Scanner implements Software Composition Analysis using Syft (SBOM) + Grype (vulns).
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string                 { return "sca" }
func (s *Scanner) Type() domain.AnalysisType     { return domain.AnalysisTypeSCA }
func (s *Scanner) Supports(t portscanner.ScanTarget) bool { return t.Type == "repository" && t.LocalPath != "" }

func (s *Scanner) Scan(ctx context.Context, target portscanner.ScanTarget) ([]*domain.Finding, error) {
	var allFindings []*domain.Finding

	// Step 1: Generate SBOM with Syft (optional — Grype can scan directly)
	// Step 2: Scan for vulnerabilities with Grype
	if scanner.CommandExists("grype") {
		findings, err := s.runGrype(ctx, target)
		if err != nil {
			logger.Warn(ctx, "Grype failed", "error", err)
		} else {
			allFindings = append(allFindings, findings...)
		}
	} else {
		logger.Warn(ctx, "Grype not found on PATH, skipping")
	}

	// Run Trivy as fallback/supplemental SCA
	if scanner.CommandExists("trivy") {
		findings, err := s.runTrivySCA(ctx, target)
		if err != nil {
			logger.Warn(ctx, "Trivy SCA failed", "error", err)
		} else {
			allFindings = append(allFindings, findings...)
		}
	}

	return allFindings, nil
}

func (s *Scanner) runGrype(ctx context.Context, target portscanner.ScanTarget) ([]*domain.Finding, error) {
	result, err := scanner.RunSubprocess(ctx,
		"grype",
		fmt.Sprintf("dir:%s", target.LocalPath),
		"-o", "json",
		"--quiet",
	)
	if err != nil {
		return nil, fmt.Errorf("grype: %w", err)
	}

	if len(result.Stdout) == 0 {
		return nil, nil
	}

	return usecase.ParseGrypeJSON(result.Stdout, uuid.Nil)
}

func (s *Scanner) runTrivySCA(ctx context.Context, target portscanner.ScanTarget) ([]*domain.Finding, error) {
	result, err := scanner.RunSubprocess(ctx,
		"trivy", "fs",
		"--scanners", "vuln",
		"--format", "sarif",
		"--quiet",
		target.LocalPath,
	)
	if err != nil {
		return nil, fmt.Errorf("trivy: %w", err)
	}

	if len(result.Stdout) == 0 {
		return nil, nil
	}

	return usecase.ParseSARIF(result.Stdout, uuid.Nil, domain.AnalysisTypeSCA)
}
