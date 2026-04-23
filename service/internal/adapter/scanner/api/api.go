package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sentiae/vigil/service/internal/adapter/scanner"
	"github.com/sentiae/vigil/service/internal/domain"
	portscanner "github.com/sentiae/vigil/service/internal/port/scanner"
	"github.com/sentiae/vigil/service/internal/usecase"
	"github.com/sentiae/vigil/service/pkg/logger"
)

// Scanner implements API security testing using Nuclei API templates + custom probes.
type Scanner struct {
	client *http.Client
}

func New() *Scanner {
	return &Scanner{
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *Scanner) Name() string             { return "api-security" }
func (s *Scanner) Type() domain.AnalysisType { return domain.AnalysisTypeDAST }
func (s *Scanner) Supports(t portscanner.ScanTarget) bool {
	return t.Type == "url" || t.Type == "api"
}

func (s *Scanner) Scan(ctx context.Context, target portscanner.ScanTarget) ([]*domain.Finding, error) {
	url := target.URI
	if url == "" {
		return nil, nil
	}

	now := time.Now()
	var allFindings []*domain.Finding

	// 1. Run Nuclei with API-specific templates (if available)
	if scanner.CommandExists("nuclei") {
		findings, err := s.runNucleiAPI(ctx, url)
		if err != nil {
			logger.Warn(ctx, "Nuclei API scan failed", "error", err)
		} else {
			allFindings = append(allFindings, findings...)
		}
	}

	// 2. Custom probes (pure Go — always available)

	// Verbose error message detection
	if finding := s.checkVerboseErrors(ctx, url, now); finding != nil {
		allFindings = append(allFindings, finding)
	}

	// Rate limiting check
	if finding := s.checkRateLimiting(ctx, url, now); finding != nil {
		allFindings = append(allFindings, finding)
	}

	// CORS preflight check
	if finding := s.checkCORSPreflight(ctx, url, now); finding != nil {
		allFindings = append(allFindings, finding)
	}

	return allFindings, nil
}

func (s *Scanner) runNucleiAPI(ctx context.Context, url string) ([]*domain.Finding, error) {
	result, err := scanner.RunSubprocess(ctx,
		"nuclei",
		"-u", url,
		"-t", "http/technologies/",
		"-t", "http/misconfiguration/",
		"-severity", "critical,high,medium",
		"-jsonl",
		"-silent",
		"-rate-limit", "50",
		"-no-update-templates",
	)
	if err != nil {
		return nil, err
	}
	if len(result.Stdout) == 0 {
		return nil, nil
	}
	return usecase.ParseNucleiJSON(result.Stdout, uuid.Nil)
}

// checkVerboseErrors sends a malformed request and checks if the response leaks stack traces.
func (s *Scanner) checkVerboseErrors(ctx context.Context, baseURL string, now time.Time) *domain.Finding {
	// Send request with invalid parameter to trigger error
	testURL := baseURL + "?id=<invalid>"
	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return nil
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 10*1024))
	content := string(body)

	// Check for stack trace indicators
	errorPatterns := []string{
		"Traceback (most recent call last)", // Python
		"at java.",                          // Java
		"goroutine ",                        // Go
		"panic:",                            // Go
		"<b>Warning</b>:",                   // PHP
		"SQLSTATE[",                         // SQL error
		"Microsoft OLE DB",                  // ASP
		"stack trace:",                      // Generic
	}

	for _, pattern := range errorPatterns {
		if strings.Contains(content, pattern) {
			hostname := req.URL.Hostname()
			f := &domain.Finding{
				ID:            uuid.New(),
				Title:         "Verbose error messages expose internal details",
				Description:   fmt.Sprintf("The application returns detailed error information including stack traces. Pattern found: %q", pattern),
				Severity:      domain.SeverityMedium,
				Status:        domain.FindingStatusNew,
				AnalysisType:  domain.AnalysisTypeDAST,
				Category:      "verbose-error",
				SourceScanner: "api-security",
				SourceRuleID:  "verbose-error-disclosure",
				FoundBy:       []string{"api-security"},
				FirstSeenAt:   now,
				LastSeenAt:    now,
				Location:      domain.FindingLocation{Hostname: hostname, URLPath: testURL},
			}
			f.Fingerprint = f.ComputeFingerprint()
			return f
		}
	}

	return nil
}

// checkRateLimiting sends rapid requests to test if rate limiting is in place.
func (s *Scanner) checkRateLimiting(ctx context.Context, baseURL string, now time.Time) *domain.Finding {
	successCount := 0
	for i := 0; i < 50; i++ {
		req, err := http.NewRequestWithContext(ctx, "GET", baseURL, nil)
		if err != nil {
			break
		}
		resp, err := s.client.Do(req)
		if err != nil {
			break
		}
		resp.Body.Close()

		if resp.StatusCode == 429 {
			return nil // Rate limiting is working
		}
		if resp.StatusCode < 500 {
			successCount++
		}
	}

	if successCount >= 50 {
		hostname := strings.Split(strings.TrimPrefix(strings.TrimPrefix(baseURL, "https://"), "http://"), "/")[0]
		f := &domain.Finding{
			ID:            uuid.New(),
			Title:         "No rate limiting detected",
			Description:   "50 rapid requests were all accepted without rate limiting (no HTTP 429 response). This allows brute force and DoS attacks.",
			Severity:      domain.SeverityMedium,
			Status:        domain.FindingStatusNew,
			AnalysisType:  domain.AnalysisTypeDAST,
			Category:      "missing-rate-limit",
			SourceScanner: "api-security",
			SourceRuleID:  "no-rate-limit",
			FoundBy:       []string{"api-security"},
			FirstSeenAt:   now,
			LastSeenAt:    now,
			Location:      domain.FindingLocation{Hostname: hostname, URLPath: baseURL},
		}
		f.Fingerprint = f.ComputeFingerprint()
		return f
	}

	return nil
}

// checkCORSPreflight sends an OPTIONS request with a malicious origin.
func (s *Scanner) checkCORSPreflight(ctx context.Context, baseURL string, now time.Time) *domain.Finding {
	req, err := http.NewRequestWithContext(ctx, "OPTIONS", baseURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Origin", "https://evil-attacker.com")
	req.Header.Set("Access-Control-Request-Method", "POST")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	if allowOrigin == "https://evil-attacker.com" || allowOrigin == "*" {
		hostname := req.URL.Hostname()
		f := &domain.Finding{
			ID:            uuid.New(),
			Title:         "CORS allows arbitrary origins",
			Description:   fmt.Sprintf("The server reflected the attacker's origin in Access-Control-Allow-Origin: %s. This allows cross-origin data theft.", allowOrigin),
			Severity:      domain.SeverityHigh,
			Status:        domain.FindingStatusNew,
			AnalysisType:  domain.AnalysisTypeDAST,
			Category:      "insecure-cors",
			SourceScanner: "api-security",
			SourceRuleID:  "cors-origin-reflection",
			FoundBy:       []string{"api-security"},
			FirstSeenAt:   now,
			LastSeenAt:    now,
			Location:      domain.FindingLocation{Hostname: hostname, URLPath: baseURL},
		}
		f.Fingerprint = f.ComputeFingerprint()
		return f
	}

	return nil
}
