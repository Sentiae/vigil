package usecase_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/sentiae/vigil/service/internal/domain"
	"github.com/sentiae/vigil/service/internal/mocks"
	portuc "github.com/sentiae/vigil/service/internal/port/usecase"
	"github.com/sentiae/vigil/service/internal/usecase"
)

func TestScanService_TriggerScan(t *testing.T) {
	scanRepo := mocks.NewMockScanRepository(t)
	publisher := mocks.NewMockPublisher(t)
	svc := usecase.NewScanService(scanRepo, publisher, nil)

	ctx := context.Background()
	tenantID := uuid.New()

	scanRepo.EXPECT().Create(ctx, mock.AnythingOfType("*domain.Scan")).Return(nil)
	publisher.EXPECT().Publish(mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

	scan, err := svc.TriggerScan(ctx, portuc.TriggerScanInput{
		TenantID:    tenantID,
		ScanType:    domain.ScanTypeSAST,
		Target:      "https://github.com/test/repo",
		Branch:      "main",
		TriggeredBy: "user-1",
	})

	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, scan.ID)
	assert.Equal(t, tenantID, scan.TenantID)
	assert.Equal(t, domain.ScanTypeSAST, scan.Type)
	assert.Equal(t, domain.ScanStatusQueued, scan.Status)
	assert.Equal(t, "https://github.com/test/repo", scan.Target)
}

func TestScanService_TriggerScan_InvalidType(t *testing.T) {
	scanRepo := mocks.NewMockScanRepository(t)
	svc := usecase.NewScanService(scanRepo, nil, nil)
	ctx := context.Background()

	_, err := svc.TriggerScan(ctx, portuc.TriggerScanInput{
		TenantID: uuid.New(),
		ScanType: "invalid_type",
		Target:   "https://github.com/test/repo",
	})

	assert.Error(t, err)
}

func TestScanService_TriggerScan_MissingTarget(t *testing.T) {
	scanRepo := mocks.NewMockScanRepository(t)
	svc := usecase.NewScanService(scanRepo, nil, nil)
	ctx := context.Background()

	_, err := svc.TriggerScan(ctx, portuc.TriggerScanInput{
		TenantID: uuid.New(),
		ScanType: domain.ScanTypeSAST,
		Target:   "",
	})

	assert.Error(t, err)
}

func TestScanService_GetScan(t *testing.T) {
	scanRepo := mocks.NewMockScanRepository(t)
	svc := usecase.NewScanService(scanRepo, nil, nil)
	ctx := context.Background()
	tenantID := uuid.New()
	scanID := uuid.New()

	expected := &domain.Scan{
		ID:       scanID,
		TenantID: tenantID,
		Type:     domain.ScanTypeSAST,
		Status:   domain.ScanStatusCompleted,
	}

	scanRepo.EXPECT().FindByID(ctx, tenantID, scanID).Return(expected, nil)

	result, err := svc.GetScan(ctx, tenantID, scanID)
	require.NoError(t, err)
	assert.Equal(t, domain.ScanStatusCompleted, result.Status)
}

func TestScanService_GetScan_NotFound(t *testing.T) {
	scanRepo := mocks.NewMockScanRepository(t)
	svc := usecase.NewScanService(scanRepo, nil, nil)
	ctx := context.Background()

	scanRepo.EXPECT().FindByID(ctx, mock.Anything, mock.Anything).Return(nil, domain.ErrScanNotFound)

	_, err := svc.GetScan(ctx, uuid.New(), uuid.New())
	assert.ErrorIs(t, err, domain.ErrScanNotFound)
}

func TestScan_Lifecycle(t *testing.T) {
	scan := &domain.Scan{
		ID:       uuid.New(),
		TenantID: uuid.New(),
		Type:     domain.ScanTypeSAST,
		Target:   "https://github.com/test/repo",
		Status:   domain.ScanStatusQueued,
	}

	// Queued → Running
	scan.MarkRunning()
	assert.Equal(t, domain.ScanStatusRunning, scan.Status)
	assert.NotNil(t, scan.StartedAt)

	// Running → Completed
	scan.MarkCompleted(5, 10)
	assert.Equal(t, domain.ScanStatusCompleted, scan.Status)
	assert.Equal(t, 5, scan.FindingsNew)
	assert.Equal(t, 10, scan.FindingsTotal)
	assert.NotNil(t, scan.CompletedAt)
	assert.GreaterOrEqual(t, scan.DurationMs, int64(0))
}

func TestScan_MarkFailed(t *testing.T) {
	scan := &domain.Scan{Status: domain.ScanStatusRunning}
	scan.MarkRunning()
	scan.MarkFailed("connection timeout")
	assert.Equal(t, domain.ScanStatusFailed, scan.Status)
	assert.Equal(t, "connection timeout", scan.Error)
}
