package discovery

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

// Scanner implements endpoint discovery using ffuf.
type Scanner struct {
	wordlistPath string
}

func New() *Scanner {
	// Default wordlist paths (checked in order)
	paths := []string{
		"/usr/share/wordlists/common.txt",
		"/usr/share/wordlists/dirb/common.txt",
		"/usr/share/seclists/Discovery/Web-Content/common.txt",
	}
	for _, p := range paths {
		if scanner.CommandExists("test") { // Just use first available
			return &Scanner{wordlistPath: p}
		}
	}
	return &Scanner{wordlistPath: paths[0]}
}

func (s *Scanner) Name() string             { return "endpoint-discovery" }
func (s *Scanner) Type() domain.AnalysisType { return domain.AnalysisTypeDAST }
func (s *Scanner) Supports(t portscanner.ScanTarget) bool {
	return t.Type == "url" || t.Type == "host"
}

func (s *Scanner) Scan(ctx context.Context, target portscanner.ScanTarget) ([]*domain.Finding, error) {
	if !scanner.CommandExists("ffuf") {
		logger.Warn(ctx, "ffuf not found on PATH, skipping endpoint discovery")
		return nil, nil
	}

	targetURL := target.URI
	if targetURL == "" {
		return nil, fmt.Errorf("target URL is required for endpoint discovery")
	}

	result, err := scanner.RunSubprocess(ctx,
		"ffuf",
		"-u", targetURL+"/FUZZ",
		"-w", s.wordlistPath,
		"-mc", "200,301,302,401,403",
		"-o", "/dev/stdout",
		"-of", "json",
		"-t", "50",
		"-rate", "100",
		"-s",
	)
	if err != nil {
		return nil, fmt.Errorf("ffuf: %w", err)
	}

	if len(result.Stdout) == 0 {
		return nil, nil
	}

	return usecase.ParseFfufJSON(result.Stdout, uuid.Nil, target.URI)
}
