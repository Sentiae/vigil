package secrets

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

// Scanner implements secret detection using Gitleaks and TruffleHog.
type Scanner struct{}

func New() *Scanner {
	return &Scanner{}
}

func (s *Scanner) Name() string                 { return "secrets" }
func (s *Scanner) Type() domain.AnalysisType     { return domain.AnalysisTypeSecretDetection }
func (s *Scanner) Supports(t portscanner.ScanTarget) bool { return t.Type == "repository" && t.LocalPath != "" }

func (s *Scanner) Scan(ctx context.Context, target portscanner.ScanTarget) ([]*domain.Finding, error) {
	var allFindings []*domain.Finding

	// Run Gitleaks
	if scanner.CommandExists("gitleaks") {
		findings, err := s.runGitleaks(ctx, target)
		if err != nil {
			logger.Warn(ctx, "Gitleaks failed", "error", err)
		} else {
			allFindings = append(allFindings, findings...)
		}
	} else {
		logger.Warn(ctx, "Gitleaks not found on PATH, skipping")
	}

	// Run TruffleHog
	if scanner.CommandExists("trufflehog") {
		findings, err := s.runTruffleHog(ctx, target)
		if err != nil {
			logger.Warn(ctx, "TruffleHog failed", "error", err)
		} else {
			allFindings = append(allFindings, findings...)
		}
	} else {
		logger.Warn(ctx, "TruffleHog not found on PATH, skipping")
	}

	// Verified secret events are published by the finding service during ingestion
	// (after tenant ID is set), not here in the scanner.

	return allFindings, nil
}

func (s *Scanner) runGitleaks(ctx context.Context, target portscanner.ScanTarget) ([]*domain.Finding, error) {
	result, err := scanner.RunSubprocess(ctx,
		"gitleaks", "detect",
		"--source", target.LocalPath,
		"--report-format", "json",
		"--report-path", "/dev/stdout",
		"--no-banner",
	)
	if err != nil {
		return nil, fmt.Errorf("gitleaks: %w", err)
	}

	// Exit code 1 = leaks found (not an error)
	if result.ExitCode > 1 {
		return nil, fmt.Errorf("gitleaks exit %d: %s", result.ExitCode, string(result.Stderr))
	}

	if len(result.Stdout) == 0 {
		return nil, nil
	}

	return usecase.ParseGitleaksJSON(result.Stdout, uuid.Nil) // tenant set later by ingestion
}

func (s *Scanner) runTruffleHog(ctx context.Context, target portscanner.ScanTarget) ([]*domain.Finding, error) {
	result, err := scanner.RunSubprocess(ctx,
		"trufflehog", "filesystem",
		target.LocalPath,
		"--json",
		"--only-verified",
	)
	if err != nil {
		return nil, fmt.Errorf("trufflehog: %w", err)
	}

	if len(result.Stdout) == 0 {
		return nil, nil
	}

	return usecase.ParseTruffleHogJSON(result.Stdout, uuid.Nil)
}

