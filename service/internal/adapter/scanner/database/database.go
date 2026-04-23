package database

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/sentiae/vigil/service/internal/domain"
	portscanner "github.com/sentiae/vigil/service/internal/port/scanner"
	"github.com/sentiae/vigil/service/pkg/logger"
)

// Scanner implements database security checks.
// Checks for weak auth, unencrypted connections, and publicly accessible instances.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string             { return "database" }
func (s *Scanner) Type() domain.AnalysisType { return domain.AnalysisTypeDatabase }
func (s *Scanner) Supports(t portscanner.ScanTarget) bool {
	return t.Type == "database" || t.Type == "host"
}

func (s *Scanner) Scan(ctx context.Context, target portscanner.ScanTarget) ([]*domain.Finding, error) {
	var allFindings []*domain.Finding
	now := time.Now()
	host := target.URI

	// Check PostgreSQL (port 5432)
	if findings := s.checkPostgres(ctx, host, now); len(findings) > 0 {
		allFindings = append(allFindings, findings...)
	}

	// Check MySQL (port 3306)
	if findings := s.checkMySQL(ctx, host, now); len(findings) > 0 {
		allFindings = append(allFindings, findings...)
	}

	// Check Redis (port 6379)
	if findings := s.checkRedis(ctx, host, now); len(findings) > 0 {
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

func (s *Scanner) checkPostgres(ctx context.Context, host string, now time.Time) []*domain.Finding {
	addr := host + ":5432"
	var findings []*domain.Finding

	// Check if port is open
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil // Port not open, skip
	}
	conn.Close()

	// Check if TLS is available
	tlsConn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp", addr,
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		findings = append(findings, s.newFinding(
			"PostgreSQL without TLS",
			fmt.Sprintf("PostgreSQL on %s does not support TLS connections", host),
			domain.SeverityHigh,
			"db-no-tls",
			host, 5432, now,
		))
	} else {
		tlsConn.Close()
	}

	logger.Debug(ctx, "PostgreSQL check complete", "host", host, "findings", len(findings))
	return findings
}

func (s *Scanner) checkMySQL(ctx context.Context, host string, now time.Time) []*domain.Finding {
	addr := host + ":3306"

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil
	}
	conn.Close()

	// MySQL publicly accessible is a finding
	logger.Debug(ctx, "MySQL check complete", "host", host)
	return []*domain.Finding{
		s.newFinding(
			"MySQL publicly accessible",
			fmt.Sprintf("MySQL on %s:3306 is accepting connections — verify access controls", host),
			domain.SeverityMedium,
			"db-public-access",
			host, 3306, now,
		),
	}
}

func (s *Scanner) checkRedis(ctx context.Context, host string, now time.Time) []*domain.Finding {
	addr := host + ":6379"
	var findings []*domain.Finding

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil
	}

	// Try sending PING without auth — if we get PONG, Redis has no auth
	_, err = conn.Write([]byte("PING\r\n"))
	if err != nil {
		conn.Close()
		return nil
	}

	buf := make([]byte, 64)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _ := conn.Read(buf)
	conn.Close()

	response := string(buf[:n])
	if response == "+PONG\r\n" {
		findings = append(findings, s.newFinding(
			"Redis without authentication",
			fmt.Sprintf("Redis on %s:6379 accepts connections without authentication", host),
			domain.SeverityCritical,
			"db-no-auth",
			host, 6379, now,
		))
	}

	logger.Debug(ctx, "Redis check complete", "host", host, "findings", len(findings))
	return findings
}

func (s *Scanner) newFinding(title, desc string, sev domain.Severity, category, host string, port int, now time.Time) *domain.Finding {
	f := &domain.Finding{
		ID:            uuid.New(),
		Title:         title,
		Description:   desc,
		Severity:      sev,
		Status:        domain.FindingStatusNew,
		AnalysisType:  domain.AnalysisTypeDatabase,
		Category:      category,
		SourceScanner: "db-scanner",
		SourceRuleID:  category,
		FoundBy:       []string{"db-scanner"},
		FirstSeenAt:   now,
		LastSeenAt:    now,
		Location: domain.FindingLocation{
			Hostname: host,
			Port:     &port,
		},
	}
	f.Fingerprint = f.ComputeFingerprint()
	return f
}
