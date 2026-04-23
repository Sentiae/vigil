package cicd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sentiae/vigil/service/internal/domain"
	portscanner "github.com/sentiae/vigil/service/internal/port/scanner"
	"github.com/sentiae/vigil/service/pkg/logger"
	"gopkg.in/yaml.v3"
)

// Scanner implements CI/CD pipeline security analysis.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string             { return "cicd" }
func (s *Scanner) Type() domain.AnalysisType { return domain.AnalysisTypeCICD }
func (s *Scanner) Supports(t portscanner.ScanTarget) bool {
	return t.Type == "repository" && t.LocalPath != ""
}

func (s *Scanner) Scan(ctx context.Context, target portscanner.ScanTarget) ([]*domain.Finding, error) {
	var allFindings []*domain.Finding

	// Scan GitHub Actions workflows
	ghDir := filepath.Join(target.LocalPath, ".github", "workflows")
	if entries, err := os.ReadDir(ghDir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && (strings.HasSuffix(entry.Name(), ".yml") || strings.HasSuffix(entry.Name(), ".yaml")) {
				filePath := filepath.Join(ghDir, entry.Name())
				findings, err := s.scanGitHubWorkflow(ctx, filePath, entry.Name())
				if err != nil {
					logger.Warn(ctx, "Failed to scan workflow", "file", entry.Name(), "error", err)
					continue
				}
				allFindings = append(allFindings, findings...)
			}
		}
	}

	// Scan GitLab CI
	gitlabCI := filepath.Join(target.LocalPath, ".gitlab-ci.yml")
	if _, err := os.Stat(gitlabCI); err == nil {
		findings, err := s.scanGitLabCI(ctx, gitlabCI)
		if err != nil {
			logger.Warn(ctx, "Failed to scan GitLab CI", "error", err)
		} else {
			allFindings = append(allFindings, findings...)
		}
	}

	return allFindings, nil
}

type ghWorkflow struct {
	Name        string                       `yaml:"name"`
	On          yaml.Node                    `yaml:"on"`
	Permissions yaml.Node                    `yaml:"permissions"`
	Jobs        map[string]ghJob             `yaml:"jobs"`
}

type ghJob struct {
	RunsOn string   `yaml:"runs-on"`
	Steps  []ghStep `yaml:"steps"`
}

type ghStep struct {
	Name string `yaml:"name"`
	Uses string `yaml:"uses"`
	Run  string `yaml:"run"`
	With map[string]string `yaml:"with"`
}

func (s *Scanner) scanGitHubWorkflow(ctx context.Context, filePath, fileName string) ([]*domain.Finding, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var wf ghWorkflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		return nil, fmt.Errorf("parse workflow: %w", err)
	}

	now := time.Now()
	var findings []*domain.Finding
	relPath := filepath.Join(".github/workflows", fileName)

	for jobName, job := range wf.Jobs {
		for stepIdx, step := range job.Steps {
			// Check for unpinned actions (should use SHA, not floating tags)
			if step.Uses != "" && !strings.Contains(step.Uses, "@") {
				findings = append(findings, s.newFinding(
					"Unpinned GitHub Action",
					fmt.Sprintf("Action %q in job %q is not pinned to a version", step.Uses, jobName),
					domain.SeverityMedium,
					"unpinned-action",
					relPath, stepIdx+1, now,
				))
			} else if step.Uses != "" && strings.Contains(step.Uses, "@v") {
				// Using floating tag like @v3 instead of SHA
				parts := strings.SplitN(step.Uses, "@", 2)
				if len(parts) == 2 && len(parts[1]) < 10 {
					findings = append(findings, s.newFinding(
						"Action pinned to floating tag",
						fmt.Sprintf("Action %q uses floating tag %q — pin to a full commit SHA for supply chain safety", parts[0], parts[1]),
						domain.SeverityMedium,
						"floating-tag-action",
						relPath, stepIdx+1, now,
					))
				}
			}

			// Check for script injection via untrusted inputs
			if step.Run != "" && containsUntrustedInput(step.Run) {
				findings = append(findings, s.newFinding(
					"Potential script injection in workflow",
					fmt.Sprintf("Job %q step %d uses untrusted input in run command which could allow script injection", jobName, stepIdx+1),
					domain.SeverityHigh,
					"script-injection",
					relPath, stepIdx+1, now,
				))
			}
		}
	}

	return findings, nil
}

func (s *Scanner) scanGitLabCI(ctx context.Context, filePath string) ([]*domain.Finding, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	var findings []*domain.Finding
	content := string(data)

	// Check for secrets in variables
	if strings.Contains(content, "variables:") && (strings.Contains(content, "password") || strings.Contains(content, "secret") || strings.Contains(content, "token")) {
		line := 1
		findings = append(findings, s.newFinding(
			"Potential hardcoded secrets in GitLab CI",
			"GitLab CI configuration appears to contain hardcoded secrets in variables section",
			domain.SeverityHigh,
			"hardcoded-secret-cicd",
			".gitlab-ci.yml", line, now,
		))
	}

	return findings, nil
}

func (s *Scanner) newFinding(title, desc string, sev domain.Severity, category, filePath string, line int, now time.Time) *domain.Finding {
	f := &domain.Finding{
		ID:            uuid.New(),
		Title:         title,
		Description:   desc,
		Severity:      sev,
		Status:        domain.FindingStatusNew,
		AnalysisType:  domain.AnalysisTypeCICD,
		Category:      category,
		SourceScanner: "cicd-scanner",
		SourceRuleID:  category,
		FoundBy:       []string{"cicd-scanner"},
		FirstSeenAt:   now,
		LastSeenAt:    now,
		Location: domain.FindingLocation{
			FilePath:  filePath,
			LineStart: &line,
		},
	}
	f.Fingerprint = f.ComputeFingerprint()
	return f
}

func containsUntrustedInput(run string) bool {
	untrusted := []string{
		"${{ github.event.issue.title }}",
		"${{ github.event.issue.body }}",
		"${{ github.event.pull_request.title }}",
		"${{ github.event.pull_request.body }}",
		"${{ github.event.comment.body }}",
		"${{ github.event.review.body }}",
		"${{ github.head_ref }}",
	}
	for _, input := range untrusted {
		if strings.Contains(run, input) {
			return true
		}
	}
	return false
}
