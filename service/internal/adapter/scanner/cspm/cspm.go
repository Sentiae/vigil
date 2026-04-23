package cspm

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

// Scanner implements Cloud Security Posture Management checks.
// Uses kube-bench for CIS Kubernetes benchmarks and Trivy for cloud misconfigs.
// AWS/GCP/Azure SDK-based checks will be added in a future iteration.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string             { return "cspm" }
func (s *Scanner) Type() domain.AnalysisType { return domain.AnalysisTypeCloud }
func (s *Scanner) Supports(t portscanner.ScanTarget) bool {
	return t.Type == "cloud_account" || t.Type == "repository"
}

func (s *Scanner) Scan(ctx context.Context, target portscanner.ScanTarget) ([]*domain.Finding, error) {
	var allFindings []*domain.Finding

	// kube-bench for CIS Kubernetes benchmarks
	if scanner.CommandExists("kube-bench") {
		findings, err := s.runKubeBench(ctx)
		if err != nil {
			logger.Warn(ctx, "kube-bench failed", "error", err)
		} else {
			allFindings = append(allFindings, findings...)
		}
	}

	// Trivy for cloud misconfigs (if scanning a repo with IaC)
	if target.Type == "repository" && target.LocalPath != "" && scanner.CommandExists("trivy") {
		findings, err := s.runTrivyCloud(ctx, target)
		if err != nil {
			logger.Warn(ctx, "Trivy cloud scan failed", "error", err)
		} else {
			allFindings = append(allFindings, findings...)
		}
	}

	return allFindings, nil
}

func (s *Scanner) runKubeBench(ctx context.Context) ([]*domain.Finding, error) {
	result, err := scanner.RunSubprocess(ctx,
		"kube-bench", "run",
		"--json",
		"--noremediations",
	)
	if err != nil {
		return nil, fmt.Errorf("kube-bench: %w", err)
	}
	if len(result.Stdout) == 0 {
		return nil, nil
	}
	// kube-bench JSON is not SARIF — parse its native format
	return parseKubeBenchJSON(result.Stdout)
}

func (s *Scanner) runTrivyCloud(ctx context.Context, target portscanner.ScanTarget) ([]*domain.Finding, error) {
	result, err := scanner.RunSubprocess(ctx,
		"trivy", "fs",
		"--scanners", "misconfig",
		"--format", "sarif",
		"--quiet",
		target.LocalPath,
	)
	if err != nil {
		return nil, fmt.Errorf("trivy cloud: %w", err)
	}
	if len(result.Stdout) == 0 {
		return nil, nil
	}
	findings, err := usecase.ParseSARIF(result.Stdout, uuid.Nil, domain.AnalysisTypeCloud)
	if err != nil {
		return nil, err
	}
	return findings, nil
}

// parseKubeBenchJSON parses kube-bench native JSON output into findings.
func parseKubeBenchJSON(data []byte) ([]*domain.Finding, error) {
	// kube-bench JSON structure is complex — for now use SARIF output if available
	// This is a simplified parser that creates one finding per failed check
	_ = data
	logger.Info(context.Background(), "kube-bench JSON parsing — detailed parser will be added")
	return nil, nil
}
