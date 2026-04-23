package usecase

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sentiae/vigil/service/internal/domain"
	"github.com/sentiae/vigil/service/internal/port/repository"
	"github.com/sentiae/vigil/service/pkg/logger"
	"github.com/sentiae/vigil/service/pkg/telemetry"
)

// ScoringService computes composite scores for findings using external threat intel.
type ScoringService struct {
	findingRepo repository.FindingRepository
	assetRepo   repository.AssetRepository

	mu       sync.RWMutex
	epssData map[string]float64 // CVE -> EPSS probability (0-1)
	kevSet   map[string]bool    // CVE -> true if in CISA KEV

	httpClient *http.Client
}

func NewScoringService(
	findingRepo repository.FindingRepository,
	assetRepo repository.AssetRepository,
) *ScoringService {
	return &ScoringService{
		findingRepo: findingRepo,
		assetRepo:   assetRepo,
		epssData:    make(map[string]float64),
		kevSet:      make(map[string]bool),
		httpClient:  &http.Client{Timeout: 30 * time.Second},
	}
}

// ScoreFinding computes the normalized composite score for a single finding.
func (s *ScoringService) ScoreFinding(ctx context.Context, f *domain.Finding, asset *domain.Asset) float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Enrich EPSS from cache
	if f.EPSSScore == nil {
		for _, cve := range f.CVEs {
			if epss, ok := s.epssData[cve]; ok {
				f.EPSSScore = &epss
				break
			}
		}
	}

	weights := domain.DefaultScoringWeights()
	return domain.CompositeScore(f, asset, s.kevSet, weights)
}

// ScoreAndUpdateFindings scores all active findings for a tenant.
func (s *ScoringService) ScoreAndUpdateFindings(ctx context.Context, tenantID uuid.UUID) error {
	findings, _, err := s.findingRepo.List(ctx, repository.FindingFilter{
		TenantID: tenantID,
		Limit:    10000,
	})
	if err != nil {
		return fmt.Errorf("list findings: %w", err)
	}

	for _, f := range findings {
		if f.Status.IsTerminal() {
			continue
		}

		// Try to find the associated asset
		var asset *domain.Asset
		if f.Location.ResourceARN != "" {
			asset, _ = s.assetRepo.FindByARN(ctx, tenantID, f.Location.ResourceARN)
		}

		score := s.ScoreFinding(ctx, f, asset)
		if score != f.NormalizedScore {
			f.NormalizedScore = score
			if err := s.findingRepo.Update(ctx, f); err != nil {
				logger.Warn(ctx, "Failed to update finding score", "finding_id", f.ID, "error", err)
			}
		}
	}

	return nil
}

// SyncEPSS fetches all EPSS scores from FIRST.org using pagination.
// The API returns ~240,000 CVEs, paginated at 100 per request by default.
// We use limit=10000 to reduce the number of round-trips.
func (s *ScoringService) SyncEPSS(ctx context.Context) error {
	logger.Info(ctx, "Syncing EPSS data from FIRST.org")

	newData := make(map[string]float64, 250000)
	offset := 0
	pageSize := 10000

	for {
		url := fmt.Sprintf("https://api.first.org/data/v1/epss?envelope=true&pretty=false&limit=%d&offset=%d", pageSize, offset)

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return fmt.Errorf("create EPSS request: %w", err)
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			if offset > 0 {
				// Partial data is better than none — keep what we have
				logger.Warn(ctx, "EPSS sync interrupted, using partial data", "fetched", len(newData), "error", err)
				break
			}
			return fmt.Errorf("fetch EPSS: %w", err)
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024))
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			if offset > 0 {
				break // Use partial data
			}
			return fmt.Errorf("EPSS API returned %d", resp.StatusCode)
		}

		if err != nil {
			break
		}

		var epssResp struct {
			Total int `json:"total"`
			Data  []struct {
				CVE  string `json:"cve"`
				EPSS string `json:"epss"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &epssResp); err != nil {
			break
		}

		for _, entry := range epssResp.Data {
			var score float64
			fmt.Sscanf(entry.EPSS, "%f", &score)
			newData[entry.CVE] = score
		}

		// Check if we've fetched all pages
		if len(epssResp.Data) < pageSize || (epssResp.Total > 0 && offset+pageSize >= epssResp.Total) {
			break
		}

		offset += pageSize

		// Log progress every 50k entries
		if len(newData)%50000 < pageSize {
			logger.Info(ctx, "EPSS sync progress", "fetched", len(newData))
		}
	}

	s.mu.Lock()
	s.epssData = newData
	s.mu.Unlock()

	telemetry.EPSSCVECount.Set(float64(len(newData)))
	logger.Info(ctx, "EPSS sync complete", "cve_count", len(newData))
	return nil
}

// SyncCISAKEV fetches the CISA Known Exploited Vulnerabilities catalog.
func (s *ScoringService) SyncCISAKEV(ctx context.Context) error {
	logger.Info(ctx, "Syncing CISA KEV catalog")

	req, err := http.NewRequestWithContext(ctx, "GET",
		"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", nil)
	if err != nil {
		return fmt.Errorf("create KEV request: %w", err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch KEV: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("KEV API returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024)) // 50MB limit
	if err != nil {
		return fmt.Errorf("read KEV response: %w", err)
	}

	var kevResp struct {
		Vulnerabilities []struct {
			CVEID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &kevResp); err != nil {
		return fmt.Errorf("unmarshal KEV: %w", err)
	}

	newSet := make(map[string]bool, len(kevResp.Vulnerabilities))
	for _, v := range kevResp.Vulnerabilities {
		newSet[strings.TrimSpace(v.CVEID)] = true
	}

	s.mu.Lock()
	s.kevSet = newSet
	s.mu.Unlock()

	telemetry.KEVCVECount.Set(float64(len(newSet)))
	logger.Info(ctx, "CISA KEV sync complete", "cve_count", len(newSet))
	return nil
}

// GetEPSSScore returns the cached EPSS score for a CVE.
func (s *ScoringService) GetEPSSScore(cve string) (float64, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	score, ok := s.epssData[cve]
	return score, ok
}

// IsInKEV returns whether a CVE is in the CISA KEV catalog.
func (s *ScoringService) IsInKEV(cve string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.kevSet[cve]
}
