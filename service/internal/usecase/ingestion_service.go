package usecase

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sentiae/vigil/service/internal/domain"
)

// =============================================================================
// SARIF v2.1.0 Parser
// =============================================================================

// SARIFReport represents a SARIF v2.1.0 report (subset of fields we use).
type SARIFReport struct {
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name  string      `json:"name"`
	Rules []SARIFRule `json:"rules,omitempty"`
}

type SARIFRule struct {
	ID               string              `json:"id"`
	ShortDescription *SARIFMessage       `json:"shortDescription,omitempty"`
	DefaultConfig    *SARIFRuleConfig    `json:"defaultConfiguration,omitempty"`
	Properties       map[string]any      `json:"properties,omitempty"`
}

type SARIFRuleConfig struct {
	Level string `json:"level"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFResult struct {
	RuleID    string           `json:"ruleId"`
	Level     string           `json:"level"`
	Message   SARIFMessage     `json:"message"`
	Locations []SARIFLocation  `json:"locations,omitempty"`
	Fixes     []any            `json:"fixes,omitempty"`
}

type SARIFLocation struct {
	PhysicalLocation *SARIFPhysicalLocation `json:"physicalLocation,omitempty"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation *SARIFArtifactLocation `json:"artifactLocation,omitempty"`
	Region           *SARIFRegion           `json:"region,omitempty"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine   int `json:"startLine"`
	EndLine     int `json:"endLine"`
	StartColumn int `json:"startColumn"`
	EndColumn   int `json:"endColumn"`
}

// ParseSARIF converts a SARIF report into universal findings.
func ParseSARIF(data []byte, tenantID uuid.UUID, analysisType domain.AnalysisType) ([]*domain.Finding, error) {
	var report SARIFReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("unmarshal SARIF: %w", err)
	}

	now := time.Now()
	var findings []*domain.Finding

	for _, run := range report.Runs {
		scanner := run.Tool.Driver.Name
		ruleMap := make(map[string]SARIFRule)
		for _, r := range run.Tool.Driver.Rules {
			ruleMap[r.ID] = r
		}

		for _, result := range run.Results {
			f := &domain.Finding{
				ID:            uuid.New(),
				TenantID:      tenantID,
				Title:         result.Message.Text,
				Description:   result.Message.Text,
				Severity:      sarifLevelToSeverity(result.Level),
				Status:        domain.FindingStatusNew,
				AnalysisType:  analysisType,
				SourceScanner: scanner,
				SourceRuleID:  result.RuleID,
				FoundBy:       []string{scanner},
				FirstSeenAt:   now,
				LastSeenAt:    now,
			}

			// Extract category from rule properties
			if rule, ok := ruleMap[result.RuleID]; ok {
				if tags, ok := rule.Properties["tags"].([]any); ok && len(tags) > 0 {
					if s, ok := tags[0].(string); ok {
						f.Category = s
					}
				}
			}

			// Extract location
			if len(result.Locations) > 0 {
				loc := result.Locations[0]
				if pl := loc.PhysicalLocation; pl != nil {
					if al := pl.ArtifactLocation; al != nil {
						f.Location.FilePath = al.URI
					}
					if reg := pl.Region; reg != nil {
						f.Location.LineStart = &reg.StartLine
						if reg.EndLine > 0 {
							f.Location.LineEnd = &reg.EndLine
						}
					}
				}
			}

			f.Fingerprint = f.ComputeFingerprint()
			findings = append(findings, f)
		}
	}

	return findings, nil
}

func sarifLevelToSeverity(level string) domain.Severity {
	switch level {
	case "error":
		return domain.SeverityHigh
	case "warning":
		return domain.SeverityMedium
	case "note":
		return domain.SeverityLow
	case "none":
		return domain.SeverityInfo
	default:
		return domain.SeverityMedium
	}
}

// =============================================================================
// Gitleaks JSON Parser
// =============================================================================

type GitleaksResult struct {
	Description string `json:"Description"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
	File        string `json:"File"`
	Commit      string `json:"Commit"`
	Author      string `json:"Author"`
	Date        string `json:"Date"`
	RuleID      string `json:"RuleID"`
	Fingerprint string `json:"Fingerprint"`
	Match       string `json:"Match"`
}

// ParseGitleaksJSON converts Gitleaks JSON output into findings.
func ParseGitleaksJSON(data []byte, tenantID uuid.UUID) ([]*domain.Finding, error) {
	var results []GitleaksResult
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("unmarshal gitleaks: %w", err)
	}

	now := time.Now()
	findings := make([]*domain.Finding, 0, len(results))

	for _, r := range results {
		f := &domain.Finding{
			ID:            uuid.New(),
			TenantID:      tenantID,
			Title:         fmt.Sprintf("Secret detected: %s", r.Description),
			Description:   fmt.Sprintf("Potential secret found by rule %s in %s", r.RuleID, r.File),
			Severity:      domain.SeverityHigh,
			Status:        domain.FindingStatusNew,
			AnalysisType:  domain.AnalysisTypeSecretDetection,
			Category:      "secret-detection",
			SourceScanner: "gitleaks",
			SourceRuleID:  r.RuleID,
			FoundBy:       []string{"gitleaks"},
			FirstSeenAt:   now,
			LastSeenAt:    now,
			Location: domain.FindingLocation{
				FilePath:  r.File,
				LineStart: &r.StartLine,
				LineEnd:   &r.EndLine,
				CommitSHA: r.Commit,
			},
		}
		f.Fingerprint = f.ComputeFingerprint()
		findings = append(findings, f)
	}

	return findings, nil
}

// =============================================================================
// Semgrep JSON Parser
// =============================================================================

type SemgrepOutput struct {
	Results []SemgrepResult `json:"results"`
}

type SemgrepResult struct {
	CheckID string           `json:"check_id"`
	Path    string           `json:"path"`
	Start   SemgrepPosition  `json:"start"`
	End     SemgrepPosition  `json:"end"`
	Extra   SemgrepExtra     `json:"extra"`
}

type SemgrepPosition struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

type SemgrepExtra struct {
	Message  string            `json:"message"`
	Severity string            `json:"severity"`
	Metadata map[string]any    `json:"metadata,omitempty"`
	Lines    string            `json:"lines"`
}

// ParseSemgrepJSON converts Semgrep JSON output into findings.
func ParseSemgrepJSON(data []byte, tenantID uuid.UUID) ([]*domain.Finding, error) {
	var output SemgrepOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("unmarshal semgrep: %w", err)
	}

	now := time.Now()
	findings := make([]*domain.Finding, 0, len(output.Results))

	for _, r := range output.Results {
		f := &domain.Finding{
			ID:            uuid.New(),
			TenantID:      tenantID,
			Title:         r.Extra.Message,
			Description:   r.Extra.Message,
			Severity:      semgrepSeverity(r.Extra.Severity),
			Status:        domain.FindingStatusNew,
			AnalysisType:  domain.AnalysisTypeSAST,
			Category:      r.CheckID,
			SourceScanner: "semgrep",
			SourceRuleID:  r.CheckID,
			FoundBy:       []string{"semgrep"},
			FirstSeenAt:   now,
			LastSeenAt:    now,
			Location: domain.FindingLocation{
				FilePath:    r.Path,
				LineStart:   &r.Start.Line,
				LineEnd:     &r.End.Line,
				CodeSnippet: r.Extra.Lines,
			},
		}

		// Extract CWE from metadata
		if meta := r.Extra.Metadata; meta != nil {
			if cwe, ok := meta["cwe"].([]any); ok {
				for _, c := range cwe {
					if s, ok := c.(string); ok {
						f.CWEs = append(f.CWEs, parseCWEID(s))
					}
				}
			}
		}

		f.Fingerprint = f.ComputeFingerprint()
		findings = append(findings, f)
	}

	return findings, nil
}

func semgrepSeverity(s string) domain.Severity {
	switch s {
	case "ERROR":
		return domain.SeverityHigh
	case "WARNING":
		return domain.SeverityMedium
	case "INFO":
		return domain.SeverityLow
	default:
		return domain.SeverityMedium
	}
}

// parseCWEID extracts the numeric ID from strings like "CWE-89"
func parseCWEID(s string) int {
	var id int
	fmt.Sscanf(s, "CWE-%d", &id)
	return id
}

// =============================================================================
// Grype JSON Parser
// =============================================================================

type GrypeOutput struct {
	Matches []GrypeMatch `json:"matches"`
}

type GrypeMatch struct {
	Vulnerability GrypeVulnerability `json:"vulnerability"`
	Artifact      GrypeArtifact      `json:"artifact"`
}

type GrypeVulnerability struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Fix         GrypeFix `json:"fix"`
	URLs        []string `json:"urls"`
	Cvss        []struct {
		Metrics struct {
			BaseScore float64 `json:"baseScore"`
		} `json:"metrics"`
		Vector string `json:"vector"`
	} `json:"cvss"`
}

type GrypeFix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}

type GrypeArtifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}

// ParseGrypeJSON converts Grype JSON output into findings.
func ParseGrypeJSON(data []byte, tenantID uuid.UUID) ([]*domain.Finding, error) {
	var output GrypeOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("unmarshal grype: %w", err)
	}

	now := time.Now()
	findings := make([]*domain.Finding, 0, len(output.Matches))

	for _, m := range output.Matches {
		sev := grypeSeverity(m.Vulnerability.Severity)

		f := &domain.Finding{
			ID:            uuid.New(),
			TenantID:      tenantID,
			Title:         fmt.Sprintf("%s in %s@%s", m.Vulnerability.ID, m.Artifact.Name, m.Artifact.Version),
			Description:   m.Vulnerability.Description,
			Severity:      sev,
			Status:        domain.FindingStatusNew,
			AnalysisType:  domain.AnalysisTypeSCA,
			Category:      "vulnerability",
			SourceScanner: "grype",
			SourceRuleID:  m.Vulnerability.ID,
			FoundBy:       []string{"grype"},
			CVEs:          []string{m.Vulnerability.ID},
			References:    m.Vulnerability.URLs,
			FirstSeenAt:   now,
			LastSeenAt:    now,
			Location: domain.FindingLocation{
				PackageName:    m.Artifact.Name,
				PackageVersion: m.Artifact.Version,
			},
		}

		if len(m.Vulnerability.Fix.Versions) > 0 {
			f.Location.FixedInVersion = m.Vulnerability.Fix.Versions[0]
		}
		if len(m.Vulnerability.Cvss) > 0 {
			score := m.Vulnerability.Cvss[0].Metrics.BaseScore
			f.CVSSScore = &score
			f.CVSSVector = m.Vulnerability.Cvss[0].Vector
		}

		f.Fingerprint = f.ComputeFingerprint()
		findings = append(findings, f)
	}

	return findings, nil
}

func grypeSeverity(s string) domain.Severity {
	switch s {
	case "Critical":
		return domain.SeverityCritical
	case "High":
		return domain.SeverityHigh
	case "Medium":
		return domain.SeverityMedium
	case "Low":
		return domain.SeverityLow
	case "Negligible":
		return domain.SeverityInfo
	default:
		return domain.SeverityMedium
	}
}

// =============================================================================
// TruffleHog JSON Parser
// =============================================================================

type TruffleHogResult struct {
	SourceMetadata struct {
		Data struct {
			Filesystem *struct {
				File string `json:"file"`
				Line int    `json:"line"`
			} `json:"Filesystem"`
			Git *struct {
				Commit   string `json:"commit"`
				File     string `json:"file"`
				Line     int    `json:"line"`
				Email    string `json:"email"`
			} `json:"Git"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
	DetectorName string `json:"DetectorName"`
	Verified     bool   `json:"Verified"`
	RawV2        string `json:"RawV2"`
	ExtraData    map[string]string `json:"ExtraData"`
}

// ParseTruffleHogJSON converts TruffleHog JSON lines output into findings.
func ParseTruffleHogJSON(data []byte, tenantID uuid.UUID) ([]*domain.Finding, error) {
	// TruffleHog outputs JSON lines (one JSON object per line)
	var results []TruffleHogResult
	// Try array first, then JSON lines
	if err := json.Unmarshal(data, &results); err != nil {
		// Parse as newline-delimited JSON
		results = nil
		for _, line := range splitLines(data) {
			if len(line) == 0 {
				continue
			}
			var r TruffleHogResult
			if err := json.Unmarshal(line, &r); err != nil {
				continue
			}
			results = append(results, r)
		}
	}

	now := time.Now()
	findings := make([]*domain.Finding, 0, len(results))

	for _, r := range results {
		sev := domain.SeverityHigh
		if r.Verified {
			sev = domain.SeverityCritical
		}

		f := &domain.Finding{
			ID:            uuid.New(),
			TenantID:      tenantID,
			Title:         fmt.Sprintf("Secret detected: %s", r.DetectorName),
			Description:   fmt.Sprintf("Credential found by %s detector (verified: %v)", r.DetectorName, r.Verified),
			Severity:      sev,
			Status:        domain.FindingStatusNew,
			AnalysisType:  domain.AnalysisTypeSecretDetection,
			Category:      "secret-detection",
			SourceScanner: "trufflehog",
			SourceRuleID:  r.DetectorName,
			FoundBy:       []string{"trufflehog"},
			FirstSeenAt:   now,
			LastSeenAt:    now,
			Metadata:      map[string]any{"verified": r.Verified},
		}

		if git := r.SourceMetadata.Data.Git; git != nil {
			f.Location.FilePath = git.File
			f.Location.CommitSHA = git.Commit
			f.Location.LineStart = &git.Line
		} else if fs := r.SourceMetadata.Data.Filesystem; fs != nil {
			f.Location.FilePath = fs.File
			f.Location.LineStart = &fs.Line
		}

		f.Fingerprint = f.ComputeFingerprint()
		findings = append(findings, f)
	}

	return findings, nil
}

// =============================================================================
// Nuclei JSON Lines Parser (DAST)
// =============================================================================

type NucleiResult struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name        string   `json:"name"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Tags        []string `json:"tags"`
		Reference   []string `json:"reference"`
		Classification struct {
			CVEID []string `json:"cve-id"`
			CWEID []int    `json:"cwe-id"`
			CVSS  float64  `json:"cvss-score"`
		} `json:"classification"`
	} `json:"info"`
	MatcherName string `json:"matcher-name"`
	Host        string `json:"host"`
	MatchedAt   string `json:"matched-at"`
	CurlCommand string `json:"curl-command"`
	Timestamp   string `json:"timestamp"`
}

// ParseNucleiJSON converts Nuclei JSON lines output into findings.
func ParseNucleiJSON(data []byte, tenantID uuid.UUID) ([]*domain.Finding, error) {
	now := time.Now()
	var findings []*domain.Finding

	for _, line := range splitLines(data) {
		if len(line) == 0 {
			continue
		}
		var r NucleiResult
		if err := json.Unmarshal(line, &r); err != nil {
			continue
		}

		sev := nucleiSeverity(r.Info.Severity)

		f := &domain.Finding{
			ID:            uuid.New(),
			TenantID:      tenantID,
			Title:         r.Info.Name,
			Description:   r.Info.Description,
			Severity:      sev,
			Status:        domain.FindingStatusNew,
			AnalysisType:  domain.AnalysisTypeDAST,
			Category:      nucleiCategory(r.Info.Tags),
			SourceScanner: "nuclei",
			SourceRuleID:  r.TemplateID,
			FoundBy:       []string{"nuclei"},
			References:    r.Info.Reference,
			FirstSeenAt:   now,
			LastSeenAt:    now,
			Location: domain.FindingLocation{
				Hostname: r.Host,
				URLPath:  r.MatchedAt,
			},
			Metadata: map[string]any{
				"template_id":  r.TemplateID,
				"matcher_name": r.MatcherName,
				"curl_command": r.CurlCommand,
				"tags":         r.Info.Tags,
			},
		}

		if len(r.Info.Classification.CVEID) > 0 {
			f.CVEs = r.Info.Classification.CVEID
		}
		if len(r.Info.Classification.CWEID) > 0 {
			f.CWEs = r.Info.Classification.CWEID
		}
		if r.Info.Classification.CVSS > 0 {
			cvss := r.Info.Classification.CVSS
			f.CVSSScore = &cvss
		}

		f.Fingerprint = f.ComputeFingerprint()
		findings = append(findings, f)
	}

	return findings, nil
}

func nucleiSeverity(s string) domain.Severity {
	switch s {
	case "critical":
		return domain.SeverityCritical
	case "high":
		return domain.SeverityHigh
	case "medium":
		return domain.SeverityMedium
	case "low":
		return domain.SeverityLow
	case "info":
		return domain.SeverityInfo
	default:
		return domain.SeverityMedium
	}
}

func nucleiCategory(tags []string) string {
	// Map Nuclei tags to finding categories
	priorityTags := map[string]string{
		"sqli": "sql-injection", "xss": "xss", "ssrf": "ssrf",
		"rce": "remote-code-execution", "lfi": "local-file-inclusion",
		"redirect": "open-redirect", "cors": "insecure-cors",
		"cve": "vulnerability-cve", "default-login": "default-credential",
		"exposure": "exposure-data", "misconfig": "misconfiguration",
		"tech": "technology-detection",
	}
	for _, tag := range tags {
		if cat, ok := priorityTags[tag]; ok {
			return cat
		}
	}
	if len(tags) > 0 {
		return tags[0]
	}
	return "web-vulnerability"
}

// =============================================================================
// ffuf JSON Parser (Endpoint Discovery)
// =============================================================================

type FfufOutput struct {
	Results []FfufResult `json:"results"`
}

type FfufResult struct {
	Input    map[string]string `json:"input"`
	Position int               `json:"position"`
	Status   int               `json:"status"`
	Length   int               `json:"length"`
	Words    int               `json:"words"`
	Lines    int               `json:"lines"`
	URL      string            `json:"url"`
	Host     string            `json:"host"`
}

// ParseFfufJSON converts ffuf JSON output into findings.
func ParseFfufJSON(data []byte, tenantID uuid.UUID, targetHost string) ([]*domain.Finding, error) {
	var output FfufOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("unmarshal ffuf: %w", err)
	}

	now := time.Now()
	findings := make([]*domain.Finding, 0, len(output.Results))

	highRiskPaths := map[string]bool{
		"admin": true, "administrator": true, "panel": true, "dashboard": true,
		"debug": true, "actuator": true, "swagger": true, "api-docs": true,
		"graphql": true, "graphiql": true, "console": true, "phpmyadmin": true,
		".env": true, ".git": true, "backup": true, "config": true,
		"wp-admin": true, "wp-login": true, "server-status": true,
	}

	for _, r := range output.Results {
		path := ""
		if v, ok := r.Input["FUZZ"]; ok {
			path = v
		}

		sev := domain.SeverityInfo
		category := "discovered-endpoint"

		if highRiskPaths[path] {
			sev = domain.SeverityMedium
			category = "high-risk-endpoint"
		}

		// 401/403 on sensitive paths = they exist but are protected (still worth noting)
		if r.Status == 200 && highRiskPaths[path] {
			sev = domain.SeverityHigh
			category = "exposed-admin-endpoint"
		}

		f := &domain.Finding{
			ID:            uuid.New(),
			TenantID:      tenantID,
			Title:         fmt.Sprintf("Endpoint discovered: /%s (HTTP %d)", path, r.Status),
			Description:   fmt.Sprintf("Endpoint /%s returned HTTP %d (%d bytes). Review if this should be publicly accessible.", path, r.Status, r.Length),
			Severity:      sev,
			Status:        domain.FindingStatusNew,
			AnalysisType:  domain.AnalysisTypeDAST,
			Category:      category,
			SourceScanner: "ffuf",
			SourceRuleID:  fmt.Sprintf("endpoint-%d", r.Status),
			FoundBy:       []string{"ffuf"},
			FirstSeenAt:   now,
			LastSeenAt:    now,
			Location: domain.FindingLocation{
				Hostname: targetHost,
				URLPath:  r.URL,
			},
			Metadata: map[string]any{
				"status_code": r.Status,
				"length":      r.Length,
				"words":       r.Words,
				"lines":       r.Lines,
			},
		}

		f.Fingerprint = f.ComputeFingerprint()
		findings = append(findings, f)
	}

	return findings, nil
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}
