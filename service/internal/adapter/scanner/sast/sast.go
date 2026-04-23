package sast

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

// Scanner implements static application security testing using Semgrep and gosec.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string                 { return "sast" }
func (s *Scanner) Type() domain.AnalysisType     { return domain.AnalysisTypeSAST }
func (s *Scanner) Supports(t portscanner.ScanTarget) bool { return t.Type == "repository" && t.LocalPath != "" }

func (s *Scanner) Scan(ctx context.Context, target portscanner.ScanTarget) ([]*domain.Finding, error) {
	var allFindings []*domain.Finding

	// Run Semgrep (multi-language SAST with taint analysis)
	if scanner.CommandExists("semgrep") {
		findings, err := s.runSemgrep(ctx, target)
		if err != nil {
			logger.Warn(ctx, "Semgrep failed", "error", err)
		} else {
			allFindings = append(allFindings, findings...)
		}
	} else {
		logger.Warn(ctx, "Semgrep not found on PATH, skipping")
	}

	// Run gosec (Go-specific security linter)
	if scanner.CommandExists("gosec") {
		findings, err := s.runGosec(ctx, target)
		if err != nil {
			logger.Warn(ctx, "gosec failed", "error", err)
		} else {
			allFindings = append(allFindings, findings...)
		}
	}

	return allFindings, nil
}

func (s *Scanner) runSemgrep(ctx context.Context, target portscanner.ScanTarget) ([]*domain.Finding, error) {
	args := []string{
		"scan",
		"--config", "p/default",
		"--config", "p/security-audit",
		"--config", "p/command-injection",
		"--config", "p/sql-injection",
		"--config", "p/secrets",
		"--json",
		"--metrics", "off",
		"--quiet",
	}

	if target.DiffOnly {
		args = append(args, "--baseline-commit", "HEAD~1")
	}

	args = append(args, target.LocalPath)

	result, err := scanner.RunSubprocess(ctx, "semgrep", args...)
	if err != nil {
		return nil, fmt.Errorf("semgrep: %w", err)
	}

	if len(result.Stdout) == 0 {
		return nil, nil
	}

	return usecase.ParseSemgrepJSON(result.Stdout, uuid.Nil)
}

func (s *Scanner) runGosec(ctx context.Context, target portscanner.ScanTarget) ([]*domain.Finding, error) {
	result, err := scanner.RunSubprocess(ctx,
		"gosec",
		"-fmt", "sarif",
		"-stdout",
		"-quiet",
		target.LocalPath+"/...",
	)
	if err != nil {
		return nil, fmt.Errorf("gosec: %w", err)
	}

	if len(result.Stdout) == 0 {
		return nil, nil
	}

	return usecase.ParseSARIF(result.Stdout, uuid.Nil, domain.AnalysisTypeSAST)
}
