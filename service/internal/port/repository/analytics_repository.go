package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/sentiae/vigil/service/internal/domain"
)

// FindingTrend represents a time-bucketed count of findings.
type FindingTrend struct {
	Date         time.Time        `json:"date"`
	Severity     domain.Severity  `json:"severity"`
	AnalysisType domain.AnalysisType `json:"analysis_type"`
	Count        int              `json:"count"`
}

// AnalyticsRepository defines the interface for the ClickHouse analytics layer.
type AnalyticsRepository interface {
	InsertFinding(ctx context.Context, finding *domain.Finding) error
	InsertFindings(ctx context.Context, findings []*domain.Finding) error
	FindingTrends(ctx context.Context, tenantID uuid.UUID, from, to time.Time) ([]FindingTrend, error)
	SearchFindings(ctx context.Context, tenantID uuid.UUID, query string, limit int) ([]*domain.Finding, error)
	ScanMetrics(ctx context.Context, tenantID uuid.UUID, from, to time.Time) ([]map[string]any, error)
}
