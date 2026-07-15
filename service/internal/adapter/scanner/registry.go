package scanner

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/sentiae/vigil/service/internal/domain"
	portscanner "github.com/sentiae/vigil/service/internal/port/scanner"
	"github.com/sentiae/vigil/service/pkg/logger"
)

// Registry maps scan types to their scanner implementations.
type Registry struct {
	mu       sync.RWMutex
	scanners map[domain.ScanType][]portscanner.Scanner
}

// NewRegistry creates an empty scanner registry.
func NewRegistry() *Registry {
	return &Registry{
		scanners: make(map[domain.ScanType][]portscanner.Scanner),
	}
}

// Register adds a scanner to the registry for the given scan type.
func (r *Registry) Register(scanType domain.ScanType, s portscanner.Scanner) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scanners[scanType] = append(r.scanners[scanType], s)
	logger.Info(context.TODO(), "Scanner registered", "scan_type", scanType, "scanner", s.Name())
}

// GetScanners returns all scanners registered for the given scan type.
func (r *Registry) GetScanners(scanType domain.ScanType) []portscanner.Scanner {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if scanType == domain.ScanTypeFull {
		var all []portscanner.Scanner
		for _, scanners := range r.scanners {
			all = append(all, scanners...)
		}
		return all
	}

	return r.scanners[scanType]
}

// RunScan executes all scanners for the given type against the target.
func (r *Registry) RunScan(ctx context.Context, scanType domain.ScanType, target portscanner.ScanTarget) ([]*domain.Finding, error) {
	scanners := r.GetScanners(scanType)
	if len(scanners) == 0 {
		return nil, fmt.Errorf("no scanners registered for type %s", scanType)
	}

	var allFindings []*domain.Finding
	var failures []string
	for _, s := range scanners {
		if !s.Supports(target) {
			logger.Debug(ctx, "Scanner does not support target, skipping", "scanner", s.Name())
			continue
		}

		logger.Info(ctx, "Running scanner", "scanner", s.Name(), "target", target.URI)
		findings, err := s.Scan(ctx, target)
		if err != nil {
			logger.Error(ctx, "Scanner failed", "scanner", s.Name(), "error", err)
			failures = append(failures, fmt.Sprintf("%s: %v", s.Name(), err))
			continue
		}
		logger.Info(ctx, "Scanner completed", "scanner", s.Name(), "findings", len(findings))
		allFindings = append(allFindings, findings...)
	}

	// Fail closed: if any supported scanner errored, surface it so the scan is
	// marked failed rather than silently reporting partial/zero coverage as clean.
	if len(failures) > 0 {
		return allFindings, fmt.Errorf("scanner(s) failed: %s", strings.Join(failures, "; "))
	}

	return allFindings, nil
}

// ScanTypeFromDomain maps domain.ScanType to the scanner registry key.
func ScanTypeFromDomain(st domain.ScanType) domain.ScanType {
	switch st {
	case domain.ScanTypeSAST:
		return domain.ScanTypeSAST
	case domain.ScanTypeSCA:
		return domain.ScanTypeSCA
	case domain.ScanTypeSecretDetection:
		return domain.ScanTypeSecretDetection
	case domain.ScanTypeIaC:
		return domain.ScanTypeIaC
	case domain.ScanTypeContainer:
		return domain.ScanTypeContainer
	case domain.ScanTypeFull:
		return domain.ScanTypeFull
	default:
		return st
	}
}
