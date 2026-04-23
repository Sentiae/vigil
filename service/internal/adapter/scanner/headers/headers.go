package headers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sentiae/vigil/service/internal/domain"
	portscanner "github.com/sentiae/vigil/service/internal/port/scanner"
)

// Scanner checks HTTP security headers on a target URL. Pure Go — no external tools.
type Scanner struct {
	client *http.Client
}

func New() *Scanner {
	return &Scanner{
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

func (s *Scanner) Name() string             { return "security-headers" }
func (s *Scanner) Type() domain.AnalysisType { return domain.AnalysisTypeDAST }
func (s *Scanner) Supports(t portscanner.ScanTarget) bool {
	return t.Type == "url" || t.Type == "host"
}

type headerCheck struct {
	header      string
	severity    domain.Severity
	category    string
	description string
}

func (s *Scanner) Scan(ctx context.Context, target portscanner.ScanTarget) ([]*domain.Finding, error) {
	url := target.URI
	if url == "" {
		return nil, nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	now := time.Now()
	var findings []*domain.Finding
	hostname := req.URL.Hostname()

	// Check required security headers
	checks := []headerCheck{
		{"Content-Security-Policy", domain.SeverityMedium, "security-header-missing", "Content-Security-Policy header is missing — allows XSS and data injection attacks"},
		{"X-Frame-Options", domain.SeverityMedium, "security-header-missing", "X-Frame-Options header is missing — vulnerable to clickjacking"},
		{"X-Content-Type-Options", domain.SeverityLow, "security-header-missing", "X-Content-Type-Options header is missing — allows MIME type sniffing"},
		{"Strict-Transport-Security", domain.SeverityHigh, "security-header-missing", "Strict-Transport-Security (HSTS) header is missing — allows downgrade attacks"},
		{"Referrer-Policy", domain.SeverityLow, "security-header-missing", "Referrer-Policy header is missing — may leak sensitive URL information"},
		{"Permissions-Policy", domain.SeverityLow, "security-header-missing", "Permissions-Policy header is missing — browser features not restricted"},
	}

	for _, check := range checks {
		if resp.Header.Get(check.header) == "" {
			f := s.newFinding(
				fmt.Sprintf("Missing security header: %s", check.header),
				check.description,
				check.severity,
				check.category,
				hostname, url, now,
			)
			findings = append(findings, f)
		}
	}

	// Check for overly permissive CORS
	if cors := resp.Header.Get("Access-Control-Allow-Origin"); cors == "*" {
		findings = append(findings, s.newFinding(
			"Overly permissive CORS: Access-Control-Allow-Origin: *",
			"The server allows requests from any origin. This may expose sensitive data to untrusted sites.",
			domain.SeverityMedium,
			"insecure-cors",
			hostname, url, now,
		))
	}

	// Check server banner information disclosure
	if server := resp.Header.Get("Server"); server != "" && (strings.Contains(server, "/") || strings.Contains(server, ".")) {
		findings = append(findings, s.newFinding(
			fmt.Sprintf("Server version disclosed: %s", server),
			"The Server header reveals version information that helps attackers target known vulnerabilities.",
			domain.SeverityLow,
			"information-disclosure",
			hostname, url, now,
		))
	}

	// Check X-Powered-By information disclosure
	if powered := resp.Header.Get("X-Powered-By"); powered != "" {
		findings = append(findings, s.newFinding(
			fmt.Sprintf("Technology disclosed via X-Powered-By: %s", powered),
			"The X-Powered-By header reveals the server technology stack.",
			domain.SeverityLow,
			"information-disclosure",
			hostname, url, now,
		))
	}

	// Check cookie security
	for _, cookie := range resp.Cookies() {
		if !cookie.Secure && strings.HasPrefix(url, "https") {
			findings = append(findings, s.newFinding(
				fmt.Sprintf("Cookie without Secure flag: %s", cookie.Name),
				"Cookie is transmitted over HTTPS but lacks the Secure flag, allowing interception over HTTP.",
				domain.SeverityMedium,
				"insecure-cookie",
				hostname, url, now,
			))
		}
		if !cookie.HttpOnly && (strings.Contains(strings.ToLower(cookie.Name), "session") || strings.Contains(strings.ToLower(cookie.Name), "token")) {
			findings = append(findings, s.newFinding(
				fmt.Sprintf("Session cookie without HttpOnly flag: %s", cookie.Name),
				"Session cookie is accessible to JavaScript, enabling theft via XSS attacks.",
				domain.SeverityHigh,
				"insecure-cookie",
				hostname, url, now,
			))
		}
	}

	return findings, nil
}

func (s *Scanner) newFinding(title, desc string, sev domain.Severity, category, hostname, url string, now time.Time) *domain.Finding {
	f := &domain.Finding{
		ID:            uuid.New(),
		Title:         title,
		Description:   desc,
		Severity:      sev,
		Status:        domain.FindingStatusNew,
		AnalysisType:  domain.AnalysisTypeDAST,
		Category:      category,
		SourceScanner: "security-headers",
		SourceRuleID:  category,
		FoundBy:       []string{"security-headers"},
		FirstSeenAt:   now,
		LastSeenAt:    now,
		Location: domain.FindingLocation{
			Hostname: hostname,
			URLPath:  url,
		},
	}
	f.Fingerprint = f.ComputeFingerprint()
	return f
}
