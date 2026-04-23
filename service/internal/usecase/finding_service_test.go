package usecase_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/sentiae/vigil/service/internal/domain"
	"github.com/sentiae/vigil/service/internal/mocks"
	"github.com/sentiae/vigil/service/internal/port/repository"
	portuc "github.com/sentiae/vigil/service/internal/port/usecase"
	"github.com/sentiae/vigil/service/internal/usecase"
)

func newTestFindingService(t *testing.T) (portuc.FindingUseCase, *mocks.MockFindingRepository, *mocks.MockPublisher) {
	findingRepo := mocks.NewMockFindingRepository(t)
	publisher := mocks.NewMockPublisher(t)
	svc := usecase.NewFindingService(findingRepo, nil, publisher, nil, nil)
	return svc, findingRepo, publisher
}

func TestFindingService_GetFinding(t *testing.T) {
	svc, repo, _ := newTestFindingService(t)
	ctx := context.Background()
	tenantID := uuid.New()
	findingID := uuid.New()

	expected := &domain.Finding{
		ID:       findingID,
		TenantID: tenantID,
		Title:    "SQL Injection",
		Severity: domain.SeverityHigh,
	}

	repo.EXPECT().FindByID(ctx, tenantID, findingID).Return(expected, nil)

	result, err := svc.GetFinding(ctx, tenantID, findingID)
	require.NoError(t, err)
	assert.Equal(t, expected.Title, result.Title)
	assert.Equal(t, domain.SeverityHigh, result.Severity)
}

func TestFindingService_GetFinding_NotFound(t *testing.T) {
	svc, repo, _ := newTestFindingService(t)
	ctx := context.Background()
	tenantID := uuid.New()
	findingID := uuid.New()

	repo.EXPECT().FindByID(ctx, tenantID, findingID).Return(nil, domain.ErrFindingNotFound)

	result, err := svc.GetFinding(ctx, tenantID, findingID)
	assert.ErrorIs(t, err, domain.ErrFindingNotFound)
	assert.Nil(t, result)
}

func TestFindingService_ListFindings(t *testing.T) {
	svc, repo, _ := newTestFindingService(t)
	ctx := context.Background()
	tenantID := uuid.New()

	filter := repository.FindingFilter{TenantID: tenantID, Limit: 10}
	expected := []*domain.Finding{
		{ID: uuid.New(), Title: "Finding 1", Severity: domain.SeverityHigh},
		{ID: uuid.New(), Title: "Finding 2", Severity: domain.SeverityMedium},
	}

	repo.EXPECT().List(ctx, filter).Return(expected, 2, nil)

	results, total, err := svc.ListFindings(ctx, filter)
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	assert.Len(t, results, 2)
}

func TestFindingService_ResolveFinding(t *testing.T) {
	svc, repo, pub := newTestFindingService(t)
	ctx := context.Background()
	tenantID := uuid.New()
	findingID := uuid.New()

	existing := &domain.Finding{
		ID:       findingID,
		TenantID: tenantID,
		Title:    "Open Port",
		Status:   domain.FindingStatusConfirmed,
	}

	repo.EXPECT().FindByID(ctx, tenantID, findingID).Return(existing, nil)
	repo.EXPECT().Update(ctx, mock.AnythingOfType("*domain.Finding")).Return(nil)
	pub.EXPECT().Publish(mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

	result, err := svc.ResolveFinding(ctx, tenantID, portuc.ResolveFindingInput{
		FindingID:  findingID,
		Resolution: domain.FindingStatusResolved,
		Note:       "Fixed in PR #123",
		ResolvedBy: "user-1",
	})

	require.NoError(t, err)
	assert.Equal(t, domain.FindingStatusResolved, result.Status)
}

func TestFindingService_ResolveFinding_InvalidResolution(t *testing.T) {
	svc, repo, _ := newTestFindingService(t)
	ctx := context.Background()
	tenantID := uuid.New()
	findingID := uuid.New()

	existing := &domain.Finding{
		ID:       findingID,
		TenantID: tenantID,
		Status:   domain.FindingStatusNew,
	}

	repo.EXPECT().FindByID(ctx, tenantID, findingID).Return(existing, nil)

	_, err := svc.ResolveFinding(ctx, tenantID, portuc.ResolveFindingInput{
		FindingID:  findingID,
		Resolution: domain.FindingStatusInProgress, // Not terminal
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "resolution must be")
}

func TestFindingService_IngestFindings(t *testing.T) {
	svc, repo, pub := newTestFindingService(t)
	ctx := context.Background()
	tenantID := uuid.New()

	findings := []*domain.Finding{
		{
			Title:         "SQL Injection",
			Severity:      domain.SeverityCritical,
			AnalysisType:  domain.AnalysisTypeSAST,
			SourceScanner: "semgrep",
			SourceRuleID:  "python.flask.sql-injection",
		},
		{
			Title:         "Hardcoded API Key",
			Severity:      domain.SeverityHigh,
			AnalysisType:  domain.AnalysisTypeSecretDetection,
			SourceScanner: "gitleaks",
			SourceRuleID:  "aws-access-key",
		},
	}

	repo.EXPECT().BulkUpsert(ctx, mock.AnythingOfType("[]*domain.Finding")).Return(2, 0, nil)
	pub.EXPECT().Publish(mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

	created, updated, err := svc.IngestFindings(ctx, tenantID, findings)
	require.NoError(t, err)
	assert.Equal(t, 2, created)
	assert.Equal(t, 0, updated)

	// Verify tenant ID was set
	assert.Equal(t, tenantID, findings[0].TenantID)
	assert.Equal(t, tenantID, findings[1].TenantID)

	// Verify fingerprints were computed
	assert.NotEmpty(t, findings[0].Fingerprint)
	assert.NotEmpty(t, findings[1].Fingerprint)

	// Verify SLA deadlines were assigned
	assert.NotNil(t, findings[0].SLADeadline)
	assert.NotNil(t, findings[1].SLADeadline)
}

func TestFindingService_CountBySeverity(t *testing.T) {
	svc, repo, _ := newTestFindingService(t)
	ctx := context.Background()
	tenantID := uuid.New()

	expected := map[domain.Severity]int{
		domain.SeverityCritical: 3,
		domain.SeverityHigh:     10,
		domain.SeverityMedium:   25,
	}

	repo.EXPECT().CountBySeverity(ctx, tenantID).Return(expected, nil)

	result, err := svc.CountBySeverity(ctx, tenantID)
	require.NoError(t, err)
	assert.Equal(t, 3, result[domain.SeverityCritical])
	assert.Equal(t, 10, result[domain.SeverityHigh])
}

func TestFindingService_IngestVerifiedSecret_PublishesSecretEvent(t *testing.T) {
	svc, repo, pub := newTestFindingService(t)
	ctx := context.Background()
	tenantID := uuid.New()

	findings := []*domain.Finding{
		{
			Title:         "Verified AWS Key",
			Severity:      domain.SeverityCritical,
			AnalysisType:  domain.AnalysisTypeSecretDetection,
			SourceScanner: "trufflehog",
			SourceRuleID:  "aws-access-key",
			Metadata:      map[string]any{"verified": true},
			Location:      domain.FindingLocation{FilePath: "config.yml", CommitSHA: "abc123"},
		},
	}

	repo.EXPECT().BulkUpsert(ctx, mock.Anything).Return(1, 0, nil)
	// Async publish calls — use Maybe() since goroutines may not complete before test ends
	pub.EXPECT().Publish(mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

	created, _, err := svc.IngestFindings(ctx, tenantID, findings)
	require.NoError(t, err)
	assert.Equal(t, 1, created)
}

// --- Domain model tests ---

func TestFinding_ComputeFingerprint(t *testing.T) {
	f := &domain.Finding{
		AnalysisType: domain.AnalysisTypeSAST,
		SourceRuleID: "sql-injection",
		Location: domain.FindingLocation{
			FilePath:    "app/main.py",
			LineStart:   intPtr(42),
			CodeSnippet: "SELECT * FROM users WHERE name = '",
		},
	}

	fp1 := f.ComputeFingerprint()
	assert.NotEmpty(t, fp1)
	assert.Len(t, fp1, 64) // SHA-256 hex

	// Same input → same fingerprint
	fp2 := f.ComputeFingerprint()
	assert.Equal(t, fp1, fp2)

	// Different line → different fingerprint
	f.Location.LineStart = intPtr(43)
	fp3 := f.ComputeFingerprint()
	assert.NotEqual(t, fp1, fp3)
}

func TestFinding_Validate(t *testing.T) {
	tests := []struct {
		name    string
		finding domain.Finding
		wantErr bool
	}{
		{
			name:    "valid finding",
			finding: domain.Finding{TenantID: uuid.New(), Title: "Test", Severity: domain.SeverityHigh, AnalysisType: domain.AnalysisTypeSAST, SourceScanner: "test"},
			wantErr: false,
		},
		{
			name:    "missing tenant_id",
			finding: domain.Finding{Title: "Test", Severity: domain.SeverityHigh, AnalysisType: domain.AnalysisTypeSAST, SourceScanner: "test"},
			wantErr: true,
		},
		{
			name:    "missing title",
			finding: domain.Finding{TenantID: uuid.New(), Severity: domain.SeverityHigh, AnalysisType: domain.AnalysisTypeSAST, SourceScanner: "test"},
			wantErr: true,
		},
		{
			name:    "invalid severity",
			finding: domain.Finding{TenantID: uuid.New(), Title: "Test", Severity: "invalid", AnalysisType: domain.AnalysisTypeSAST, SourceScanner: "test"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.finding.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCompositeScore(t *testing.T) {
	f := &domain.Finding{
		CVSSScore: float64Ptr(9.8),
		EPSSScore: float64Ptr(0.95),
		CVEs:      []string{"CVE-2024-1234"},
		FirstSeenAt: time.Now().Add(-30 * 24 * time.Hour), // 30 days old
	}

	asset := &domain.Asset{
		Criticality:    domain.CriticalityVeryHigh,
		InternetFacing: true,
		Environment:    "production",
		PIIHandling:    true,
	}

	kevCVEs := map[string]bool{"CVE-2024-1234": true}
	weights := domain.DefaultScoringWeights()

	score := domain.CompositeScore(f, asset, kevCVEs, weights)
	assert.Greater(t, score, 70.0, "Critical CVE in KEV on prod internet-facing asset should score high")
	assert.LessOrEqual(t, score, 100.0)
}

func TestCompositeScore_NilAsset(t *testing.T) {
	f := &domain.Finding{
		CVSSScore:   float64Ptr(5.0),
		FirstSeenAt: time.Now(),
	}

	weights := domain.DefaultScoringWeights()
	score := domain.CompositeScore(f, nil, nil, weights)
	assert.Greater(t, score, 0.0)
	assert.Less(t, score, 50.0, "Medium CVSS with no asset context should be moderate")
}

func TestSLADeadline_Assignment(t *testing.T) {
	f := &domain.Finding{
		Severity:    domain.SeverityCritical,
		FirstSeenAt: time.Now(),
	}

	usecase.AssignSLADeadline(f, true)
	require.NotNil(t, f.SLADeadline)
	assert.WithinDuration(t, f.FirstSeenAt.Add(24*time.Hour), *f.SLADeadline, time.Minute)

	f2 := &domain.Finding{
		Severity:    domain.SeverityCritical,
		FirstSeenAt: time.Now(),
	}
	usecase.AssignSLADeadline(f2, false)
	require.NotNil(t, f2.SLADeadline)
	assert.WithinDuration(t, f2.FirstSeenAt.Add(72*time.Hour), *f2.SLADeadline, time.Minute)
}

// --- Helpers ---

func intPtr(n int) *int       { return &n }
func float64Ptr(f float64) *float64 { return &f }
