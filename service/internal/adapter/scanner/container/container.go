package container

import (
	"context"
	"fmt"
	"strings"

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

	// Track whether at least one tool ran successfully so we can fail closed
	// when no scanner produced a result (missing binaries or every tool errored).
	toolRan := false
	toolErrs := []string{}

	// Grype for vulnerability matching on container images
	if scanner.CommandExists("grype") {
		findings, err := s.runGrype(ctx, scanTarget)
		if err != nil {
			logger.Warn(ctx, "Grype container scan failed", "error", err)
			toolErrs = append(toolErrs, fmt.Sprintf("grype: %v", err))
		} else {
			toolRan = true
			allFindings = append(allFindings, findings...)
		}
	} else {
		toolErrs = append(toolErrs, "grype missing")
	}

	// Trivy for container-specific checks (secrets in layers, misconfigs)
	if scanner.CommandExists("trivy") {
		findings, err := s.runTrivy(ctx, scanTarget)
		if err != nil {
			logger.Warn(ctx, "Trivy container scan failed", "error", err)
			toolErrs = append(toolErrs, fmt.Sprintf("trivy: %v", err))
		} else {
			toolRan = true
			allFindings = append(allFindings, findings...)
		}
	} else {
		toolErrs = append(toolErrs, "trivy missing")
	}

	// Fail closed: if no tool ran successfully, the scan has no coverage —
	// return an error so the scan is marked failed rather than silently clean.
	if !toolRan {
		return nil, fmt.Errorf("container scan produced no result: %s", strings.Join(toolErrs, "; "))
	}

	return allFindings, nil
}

func (s *Scanner) runGrype(ctx context.Context, target string) ([]*domain.Finding, error) {
	result, err := scanner.RunSubprocess(ctx, "grype", target, "-o", "json", "--quiet")
	if err != nil {
		return nil, fmt.Errorf("grype: %w", err)
	}
	// grype exits non-zero ONLY on error (image pull failure, etc.) — we set no
	// --fail-on, so a non-zero code is never "findings". Surface it so the scan
	// fails closed instead of being counted as a clean zero-finding result.
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("grype exit %d: %s", result.ExitCode, strings.TrimSpace(string(result.Stderr)))
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
	// trivy exits non-zero ONLY on error (image pull failure, etc.) — we set no
	// --exit-code, so a non-zero code is never "findings". Surface it so the scan
	// fails closed instead of being counted as a clean zero-finding result.
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("trivy exit %d: %s", result.ExitCode, strings.TrimSpace(string(result.Stderr)))
	}
	if len(result.Stdout) == 0 {
		return nil, nil
	}
	return usecase.ParseSARIF(result.Stdout, uuid.Nil, domain.AnalysisTypeContainer)
}
