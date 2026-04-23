package iac

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

// Scanner implements Infrastructure-as-Code security scanning using KICS and Trivy.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string                 { return "iac" }
func (s *Scanner) Type() domain.AnalysisType     { return domain.AnalysisTypeIaC }
func (s *Scanner) Supports(t portscanner.ScanTarget) bool { return t.Type == "repository" && t.LocalPath != "" }

func (s *Scanner) Scan(ctx context.Context, target portscanner.ScanTarget) ([]*domain.Finding, error) {
	var allFindings []*domain.Finding

	// Run KICS (1,900+ IaC queries for Terraform, K8s, Docker, Ansible, CloudFormation)
	if scanner.CommandExists("kics") {
		findings, err := s.runKICS(ctx, target)
		if err != nil {
			logger.Warn(ctx, "KICS failed", "error", err)
		} else {
			allFindings = append(allFindings, findings...)
		}
	} else {
		logger.Warn(ctx, "KICS not found on PATH, skipping")
	}

	// Run Trivy IaC misconfiguration scanner
	if scanner.CommandExists("trivy") {
		findings, err := s.runTrivyIaC(ctx, target)
		if err != nil {
			logger.Warn(ctx, "Trivy IaC failed", "error", err)
		} else {
			allFindings = append(allFindings, findings...)
		}
	}

	return allFindings, nil
}

func (s *Scanner) runKICS(ctx context.Context, target portscanner.ScanTarget) ([]*domain.Finding, error) {
	result, err := scanner.RunSubprocess(ctx,
		"kics", "scan",
		"--path", target.LocalPath,
		"--type", "Terraform,Kubernetes,Dockerfile,CloudFormation,Ansible",
		"--report-formats", "sarif",
		"--output-path", "/dev/stdout",
		"--no-progress",
		"--silent",
	)
	if err != nil {
		return nil, fmt.Errorf("kics: %w", err)
	}

	// KICS uses exit codes: 0=no results, 50=results found, 40+=errors
	if result.ExitCode > 50 {
		return nil, fmt.Errorf("kics exit %d: %s", result.ExitCode, string(result.Stderr))
	}

	if len(result.Stdout) == 0 {
		return nil, nil
	}

	return usecase.ParseSARIF(result.Stdout, uuid.Nil, domain.AnalysisTypeIaC)
}

func (s *Scanner) runTrivyIaC(ctx context.Context, target portscanner.ScanTarget) ([]*domain.Finding, error) {
	result, err := scanner.RunSubprocess(ctx,
		"trivy", "fs",
		"--scanners", "misconfig",
		"--format", "sarif",
		"--quiet",
		target.LocalPath,
	)
	if err != nil {
		return nil, fmt.Errorf("trivy iac: %w", err)
	}

	if len(result.Stdout) == 0 {
		return nil, nil
	}

	return usecase.ParseSARIF(result.Stdout, uuid.Nil, domain.AnalysisTypeIaC)
}
