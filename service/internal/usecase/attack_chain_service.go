package usecase

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/sentiae/vigil/service/internal/domain"
	"github.com/sentiae/vigil/service/internal/port/repository"
	"github.com/sentiae/vigil/service/pkg/events"
	"github.com/sentiae/vigil/service/pkg/logger"
)

// AttackChain represents a multi-step attack scenario composed of correlated findings.
type AttackChain struct {
	ID          uuid.UUID        `json:"id"`
	Description string           `json:"description"`
	Severity    domain.Severity  `json:"severity"`
	Steps       []AttackChainStep `json:"steps"`
	Likelihood  string           `json:"likelihood"`
	FindingIDs  []uuid.UUID      `json:"finding_ids"`
}

// AttackChainStep is a single step in an attack chain.
type AttackChainStep struct {
	Order       int       `json:"order"`
	FindingID   uuid.UUID `json:"finding_id"`
	Description string    `json:"description"`
	Category    string    `json:"category"`
}

// AttackChainService correlates findings into multi-step attack scenarios.
type AttackChainService struct {
	findingRepo repository.FindingRepository
	publisher   events.Publisher
}

func NewAttackChainService(findingRepo repository.FindingRepository, publisher events.Publisher) *AttackChainService {
	return &AttackChainService{
		findingRepo: findingRepo,
		publisher:   publisher,
	}
}

// Analyze examines all active findings for a tenant and identifies attack chains.
func (s *AttackChainService) Analyze(ctx context.Context, tenantID uuid.UUID) ([]AttackChain, error) {
	findings, _, err := s.findingRepo.List(ctx, repository.FindingFilter{
		TenantID: tenantID,
		Limit:    10000,
	})
	if err != nil {
		return nil, err
	}

	if len(findings) < 2 {
		return nil, nil // Need at least 2 findings for a chain
	}

	// Index findings by category for fast lookup
	byCategory := make(map[string][]*domain.Finding)
	for _, f := range findings {
		if !f.Status.IsTerminal() {
			byCategory[f.Category] = append(byCategory[f.Category], f)
		}
	}

	var chains []AttackChain

	// Rule 1: Secret leak + open database port = direct data access
	secrets := append(byCategory["secret-detection"], byCategory["default-credential"]...)
	dbPorts := byCategory["open-port"]
	if len(secrets) > 0 && len(dbPorts) > 0 {
		chain := AttackChain{
			ID:          uuid.New(),
			Description: "Credential leak + open database port enables direct data access",
			Severity:    domain.SeverityCritical,
			Likelihood:  "high",
		}
		chain.Steps = append(chain.Steps, AttackChainStep{
			Order: 1, FindingID: secrets[0].ID, Description: "Leaked credential found", Category: secrets[0].Category,
		})
		chain.Steps = append(chain.Steps, AttackChainStep{
			Order: 2, FindingID: dbPorts[0].ID, Description: "Database port exposed", Category: dbPorts[0].Category,
		})
		chain.FindingIDs = []uuid.UUID{secrets[0].ID, dbPorts[0].ID}
		chains = append(chains, chain)
	}

	// Rule 2: SQL injection + PII endpoint = data breach
	sqli := byCategory["sql-injection"]
	if len(sqli) > 0 {
		chain := AttackChain{
			ID:          uuid.New(),
			Description: "SQL injection on application endpoint enables data exfiltration",
			Severity:    domain.SeverityCritical,
			Likelihood:  "high",
		}
		for i, f := range sqli {
			chain.Steps = append(chain.Steps, AttackChainStep{
				Order: i + 1, FindingID: f.ID, Description: f.Title, Category: f.Category,
			})
			chain.FindingIDs = append(chain.FindingIDs, f.ID)
		}
		chains = append(chains, chain)
	}

	// Rule 3: Exposed admin panel + missing auth headers = unauthenticated admin access
	adminEndpoints := byCategory["exposed-admin-endpoint"]
	missingHeaders := byCategory["security-header-missing"]
	if len(adminEndpoints) > 0 {
		chain := AttackChain{
			ID:          uuid.New(),
			Description: "Exposed admin panel without adequate security controls",
			Severity:    domain.SeverityCritical,
			Likelihood:  "high",
		}
		chain.Steps = append(chain.Steps, AttackChainStep{
			Order: 1, FindingID: adminEndpoints[0].ID, Description: "Admin panel publicly accessible", Category: "exposed-admin-endpoint",
		})
		if len(missingHeaders) > 0 {
			chain.Steps = append(chain.Steps, AttackChainStep{
				Order: 2, FindingID: missingHeaders[0].ID, Description: "Missing security headers", Category: "security-header-missing",
			})
			chain.FindingIDs = append(chain.FindingIDs, missingHeaders[0].ID)
		}
		chain.FindingIDs = append([]uuid.UUID{adminEndpoints[0].ID}, chain.FindingIDs...)
		chains = append(chains, chain)
	}

	// Rule 4: XSS + insecure cookies = session hijacking
	xss := byCategory["xss"]
	insecureCookies := byCategory["insecure-cookie"]
	if len(xss) > 0 && len(insecureCookies) > 0 {
		chain := AttackChain{
			ID:          uuid.New(),
			Description: "XSS vulnerability + insecure session cookies enables session hijacking",
			Severity:    domain.SeverityCritical,
			Likelihood:  "high",
		}
		chain.Steps = append(chain.Steps, AttackChainStep{
			Order: 1, FindingID: xss[0].ID, Description: "XSS vulnerability found", Category: "xss",
		})
		chain.Steps = append(chain.Steps, AttackChainStep{
			Order: 2, FindingID: insecureCookies[0].ID, Description: "Session cookie lacks HttpOnly flag", Category: "insecure-cookie",
		})
		chain.FindingIDs = []uuid.UUID{xss[0].ID, insecureCookies[0].ID}
		chains = append(chains, chain)
	}

	// Rule 5: CORS misconfiguration + sensitive API = cross-origin data theft
	corsIssues := byCategory["insecure-cors"]
	apiEndpoints := byCategory["discovered-endpoint"]
	if len(corsIssues) > 0 && len(apiEndpoints) > 0 {
		chain := AttackChain{
			ID:          uuid.New(),
			Description: "Permissive CORS + exposed API endpoints enables cross-origin data theft",
			Severity:    domain.SeverityHigh,
			Likelihood:  "medium",
		}
		chain.Steps = append(chain.Steps, AttackChainStep{
			Order: 1, FindingID: corsIssues[0].ID, Description: "CORS allows arbitrary origins", Category: "insecure-cors",
		})
		chain.Steps = append(chain.Steps, AttackChainStep{
			Order: 2, FindingID: apiEndpoints[0].ID, Description: "API endpoint discovered", Category: "discovered-endpoint",
		})
		chain.FindingIDs = []uuid.UUID{corsIssues[0].ID, apiEndpoints[0].ID}
		chains = append(chains, chain)
	}

	// Publish attack chain events
	if len(chains) > 0 && s.publisher != nil {
		for _, chain := range chains {
			go func(c AttackChain) {
				publishCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = s.publisher.Publish(publishCtx, events.EventAttackChainFound, events.EventData{
					ActorType:    "system",
					ResourceType: "attack_chain",
					ResourceID:   c.ID.String(),
					Metadata: map[string]any{
						"description":   c.Description,
						"severity":      string(c.Severity),
						"likelihood":    c.Likelihood,
						"finding_count": len(c.FindingIDs),
						"steps":         len(c.Steps),
					},
					Timestamp: time.Now(),
				})
			}(chain)
		}
		logger.Info(ctx, "Attack chains detected", "count", len(chains))
	}

	return chains, nil
}
