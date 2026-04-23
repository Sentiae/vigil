package web

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

// Scanner implements web vulnerability scanning using Nuclei.
// Nuclei has 12k+ community templates covering CVEs, misconfigurations,
// exposures, default credentials, and technology detection.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string             { return "web-nuclei" }
func (s *Scanner) Type() domain.AnalysisType { return domain.AnalysisTypeDAST }
func (s *Scanner) Supports(t portscanner.ScanTarget) bool {
	return t.Type == "url" || t.Type == "host"
}

func (s *Scanner) Scan(ctx context.Context, target portscanner.ScanTarget) ([]*domain.Finding, error) {
	if !scanner.CommandExists("nuclei") {
		logger.Warn(ctx, "Nuclei not found on PATH, skipping web vulnerability scan")
		return nil, nil
	}

	targetURL := target.URI
	if targetURL == "" {
		return nil, fmt.Errorf("target URL is required for web scanning")
	}

	var allFindings []*domain.Finding

	// Run Nuclei with multiple template categories
	findings, err := s.runNuclei(ctx, targetURL)
	if err != nil {
		logger.Warn(ctx, "Nuclei scan failed", "error", err)
	} else {
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

func (s *Scanner) runNuclei(ctx context.Context, targetURL string) ([]*domain.Finding, error) {
	result, err := scanner.RunSubprocess(ctx,
		"nuclei",
		"-u", targetURL,
		"-t", "cves/",
		"-t", "exposures/",
		"-t", "misconfiguration/",
		"-t", "default-logins/",
		"-t", "vulnerabilities/",
		"-severity", "critical,high,medium",
		"-jsonl",
		"-silent",
		"-rate-limit", "100",
		"-concurrency", "25",
		"-timeout", "10",
		"-no-update-templates",
	)
	if err != nil {
		return nil, fmt.Errorf("nuclei: %w", err)
	}

	if len(result.Stdout) == 0 {
		return nil, nil
	}

	return usecase.ParseNucleiJSON(result.Stdout, uuid.Nil)
}
