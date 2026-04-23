package usecase_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sentiae/vigil/service/internal/domain"
	"github.com/sentiae/vigil/service/internal/usecase"
)

func TestParseSARIF(t *testing.T) {
	sarif := `{
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {"name": "test-scanner", "rules": []}},
			"results": [
				{
					"ruleId": "sql-injection",
					"level": "error",
					"message": {"text": "SQL injection detected"},
					"locations": [{
						"physicalLocation": {
							"artifactLocation": {"uri": "app/main.py"},
							"region": {"startLine": 10, "endLine": 12}
						}
					}]
				},
				{
					"ruleId": "xss",
					"level": "warning",
					"message": {"text": "Potential XSS"},
					"locations": [{
						"physicalLocation": {
							"artifactLocation": {"uri": "app/views.py"},
							"region": {"startLine": 25}
						}
					}]
				}
			]
		}]
	}`

	tenantID := uuid.New()
	findings, err := usecase.ParseSARIF([]byte(sarif), tenantID, domain.AnalysisTypeSAST)
	require.NoError(t, err)
	assert.Len(t, findings, 2)

	assert.Equal(t, "SQL injection detected", findings[0].Title)
	assert.Equal(t, domain.SeverityHigh, findings[0].Severity) // "error" → high
	assert.Equal(t, "app/main.py", findings[0].Location.FilePath)
	assert.Equal(t, 10, *findings[0].Location.LineStart)
	assert.Equal(t, "test-scanner", findings[0].SourceScanner)
	assert.NotEmpty(t, findings[0].Fingerprint)

	assert.Equal(t, domain.SeverityMedium, findings[1].Severity) // "warning" → medium
	assert.Equal(t, "app/views.py", findings[1].Location.FilePath)
}

func TestParseGitleaksJSON(t *testing.T) {
	gitleaks := `[
		{
			"Description": "GitHub Personal Access Token",
			"StartLine": 5,
			"EndLine": 5,
			"File": "config.yml",
			"Commit": "abc123def456",
			"Author": "dev@example.com",
			"RuleID": "github-pat",
			"Fingerprint": "config.yml:github-pat:5"
		}
	]`

	tenantID := uuid.New()
	findings, err := usecase.ParseGitleaksJSON([]byte(gitleaks), tenantID)
	require.NoError(t, err)
	assert.Len(t, findings, 1)

	f := findings[0]
	assert.Contains(t, f.Title, "GitHub Personal Access Token")
	assert.Equal(t, domain.SeverityHigh, f.Severity)
	assert.Equal(t, domain.AnalysisTypeSecretDetection, f.AnalysisType)
	assert.Equal(t, "config.yml", f.Location.FilePath)
	assert.Equal(t, "abc123def456", f.Location.CommitSHA)
	assert.Equal(t, "gitleaks", f.SourceScanner)
}

func TestParseSemgrepJSON(t *testing.T) {
	semgrep := `{
		"results": [
			{
				"check_id": "python.flask.sql-injection",
				"path": "app/db.py",
				"start": {"line": 15, "col": 1},
				"end": {"line": 15, "col": 60},
				"extra": {
					"message": "Detected SQL injection via string concatenation",
					"severity": "ERROR",
					"metadata": {"cwe": ["CWE-89"]},
					"lines": "query = \"SELECT * FROM users WHERE id=\" + user_id"
				}
			}
		]
	}`

	tenantID := uuid.New()
	findings, err := usecase.ParseSemgrepJSON([]byte(semgrep), tenantID)
	require.NoError(t, err)
	assert.Len(t, findings, 1)

	f := findings[0]
	assert.Contains(t, f.Title, "SQL injection")
	assert.Equal(t, domain.SeverityHigh, f.Severity) // "ERROR" → high
	assert.Equal(t, "app/db.py", f.Location.FilePath)
	assert.Equal(t, 15, *f.Location.LineStart)
	assert.Contains(t, f.Location.CodeSnippet, "SELECT * FROM users")
	assert.Equal(t, "semgrep", f.SourceScanner)
	assert.Contains(t, f.CWEs, 89)
}

func TestParseGrypeJSON(t *testing.T) {
	grype := `{
		"matches": [
			{
				"vulnerability": {
					"id": "CVE-2024-1234",
					"severity": "Critical",
					"description": "Remote code execution in libfoo",
					"fix": {"versions": ["1.2.4"], "state": "fixed"},
					"urls": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
					"cvss": [{"metrics": {"baseScore": 9.8}, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
				},
				"artifact": {
					"name": "libfoo",
					"version": "1.2.3",
					"type": "python"
				}
			}
		]
	}`

	tenantID := uuid.New()
	findings, err := usecase.ParseGrypeJSON([]byte(grype), tenantID)
	require.NoError(t, err)
	assert.Len(t, findings, 1)

	f := findings[0]
	assert.Contains(t, f.Title, "CVE-2024-1234")
	assert.Contains(t, f.Title, "libfoo@1.2.3")
	assert.Equal(t, domain.SeverityCritical, f.Severity)
	assert.Equal(t, "libfoo", f.Location.PackageName)
	assert.Equal(t, "1.2.3", f.Location.PackageVersion)
	assert.Equal(t, "1.2.4", f.Location.FixedInVersion)
	assert.Contains(t, f.CVEs, "CVE-2024-1234")
	require.NotNil(t, f.CVSSScore)
	assert.Equal(t, 9.8, *f.CVSSScore)
}

func TestParseTruffleHogJSON(t *testing.T) {
	trufflehog := `{"SourceMetadata":{"Data":{"Git":{"commit":"def789","file":"secrets.py","line":3}}},"DetectorName":"AWS","Verified":true}
{"SourceMetadata":{"Data":{"Git":{"commit":"abc123","file":"config.py","line":7}}},"DetectorName":"GitHub","Verified":false}`

	tenantID := uuid.New()
	findings, err := usecase.ParseTruffleHogJSON([]byte(trufflehog), tenantID)
	require.NoError(t, err)
	assert.Len(t, findings, 2)

	// Verified credential → critical
	assert.Equal(t, domain.SeverityCritical, findings[0].Severity)
	assert.Equal(t, true, findings[0].Metadata["verified"])
	assert.Equal(t, "secrets.py", findings[0].Location.FilePath)

	// Unverified → high
	assert.Equal(t, domain.SeverityHigh, findings[1].Severity)
}
