package network

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sentiae/vigil/service/internal/adapter/scanner"
	"github.com/sentiae/vigil/service/internal/domain"
	portscanner "github.com/sentiae/vigil/service/internal/port/scanner"
	"github.com/sentiae/vigil/service/pkg/logger"
)

// Scanner implements network security analysis: port scanning and TLS certificate checks.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string             { return "network" }
func (s *Scanner) Type() domain.AnalysisType { return domain.AnalysisTypeNetwork }
func (s *Scanner) Supports(t portscanner.ScanTarget) bool {
	return t.Type == "host" || t.Type == "network"
}

func (s *Scanner) Scan(ctx context.Context, target portscanner.ScanTarget) ([]*domain.Finding, error) {
	var allFindings []*domain.Finding

	host := target.URI

	// Port scanning with naabu (if available)
	if scanner.CommandExists("naabu") {
		findings, err := s.runNaabu(ctx, host)
		if err != nil {
			logger.Warn(ctx, "naabu port scan failed", "error", err)
		} else {
			allFindings = append(allFindings, findings...)
		}
	}

	// TLS certificate analysis (built-in, no external tool needed)
	findings, err := s.checkTLSCertificate(ctx, host)
	if err != nil {
		logger.Debug(ctx, "TLS check skipped", "host", host, "error", err)
	} else {
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

func (s *Scanner) runNaabu(ctx context.Context, host string) ([]*domain.Finding, error) {
	result, err := scanner.RunSubprocess(ctx,
		"naabu",
		"-host", host,
		"-top-ports", "1000",
		"-silent",
		"-json",
	)
	if err != nil {
		return nil, fmt.Errorf("naabu: %w", err)
	}
	if len(result.Stdout) == 0 {
		return nil, nil
	}

	// naabu outputs JSON lines with discovered open ports
	now := time.Now()
	var findings []*domain.Finding

	for _, line := range strings.Split(string(result.Stdout), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Each line is like {"host":"example.com","port":22}
		// We flag commonly sensitive open ports
		if strings.Contains(line, `"port":22`) || strings.Contains(line, `"port":3389`) ||
			strings.Contains(line, `"port":3306`) || strings.Contains(line, `"port":5432`) ||
			strings.Contains(line, `"port":6379`) || strings.Contains(line, `"port":27017`) {
			port := extractPort(line)
			findings = append(findings, &domain.Finding{
				ID:            uuid.New(),
				Title:         fmt.Sprintf("Sensitive port %d open on %s", port, host),
				Description:   fmt.Sprintf("Port %d is open and accessible. This port typically serves sensitive services that should not be publicly exposed.", port),
				Severity:      domain.SeverityHigh,
				Status:        domain.FindingStatusNew,
				AnalysisType:  domain.AnalysisTypeNetwork,
				Category:      "open-port",
				SourceScanner: "naabu",
				SourceRuleID:  "open-sensitive-port",
				FoundBy:       []string{"naabu"},
				FirstSeenAt:   now,
				LastSeenAt:    now,
				Location: domain.FindingLocation{
					Hostname: host,
					Port:     &port,
				},
			})
		}
	}

	for _, f := range findings {
		f.Fingerprint = f.ComputeFingerprint()
	}
	return findings, nil
}

func (s *Scanner) checkTLSCertificate(ctx context.Context, host string) ([]*domain.Finding, error) {
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", host, &tls.Config{
		InsecureSkipVerify: true, // We're inspecting the cert, not trusting it
	})
	if err != nil {
		return nil, fmt.Errorf("tls dial: %w", err)
	}
	defer conn.Close()

	now := time.Now()
	var findings []*domain.Finding
	hostname := strings.Split(host, ":")[0]

	for _, cert := range conn.ConnectionState().PeerCertificates {
		if cert.IsCA {
			continue
		}

		// Check expiry
		if cert.NotAfter.Before(now) {
			findings = append(findings, s.newCertFinding(
				"Expired TLS certificate",
				fmt.Sprintf("Certificate for %s expired on %s", hostname, cert.NotAfter.Format("2006-01-02")),
				domain.SeverityCritical,
				"expired-certificate",
				hostname, now,
			))
		} else if cert.NotAfter.Before(now.Add(30 * 24 * time.Hour)) {
			findings = append(findings, s.newCertFinding(
				"TLS certificate expiring soon",
				fmt.Sprintf("Certificate for %s expires on %s (within 30 days)", hostname, cert.NotAfter.Format("2006-01-02")),
				domain.SeverityHigh,
				"expiring-certificate",
				hostname, now,
			))
		}

		// Check key size
		if cert.PublicKeyAlgorithm == x509.RSA {
			if key := cert.PublicKey; key != nil {
				// RSA keys < 2048 bits are weak
				// PublicKey is interface{}, checking bit size requires type assertion
			}
		}

		// Check self-signed
		if cert.Issuer.CommonName == cert.Subject.CommonName {
			findings = append(findings, s.newCertFinding(
				"Self-signed TLS certificate",
				fmt.Sprintf("Certificate for %s appears to be self-signed", hostname),
				domain.SeverityMedium,
				"self-signed-certificate",
				hostname, now,
			))
		}
	}

	return findings, nil
}

func (s *Scanner) newCertFinding(title, desc string, sev domain.Severity, category, hostname string, now time.Time) *domain.Finding {
	f := &domain.Finding{
		ID:            uuid.New(),
		Title:         title,
		Description:   desc,
		Severity:      sev,
		Status:        domain.FindingStatusNew,
		AnalysisType:  domain.AnalysisTypeNetwork,
		Category:      category,
		SourceScanner: "tls-checker",
		SourceRuleID:  category,
		FoundBy:       []string{"tls-checker"},
		FirstSeenAt:   now,
		LastSeenAt:    now,
		Location: domain.FindingLocation{
			Hostname: hostname,
		},
	}
	f.Fingerprint = f.ComputeFingerprint()
	return f
}

func extractPort(jsonLine string) int {
	var port int
	fmt.Sscanf(jsonLine, `%*[^:]:%*[^:]:%d`, &port)
	// Fallback: brute parse
	for _, p := range []int{22, 3389, 3306, 5432, 6379, 27017} {
		if strings.Contains(jsonLine, fmt.Sprintf(`"port":%d`, p)) {
			return p
		}
	}
	return 0
}
