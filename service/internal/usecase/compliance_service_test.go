package usecase_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"

	"github.com/sentiae/vigil/service/internal/domain"
	"github.com/sentiae/vigil/service/internal/mocks"
	"github.com/sentiae/vigil/service/internal/usecase"
)

var errSLACount = errors.New("sla count unavailable")

// TestComplianceSummary_SLABreachCount: the summary reads the SLA breach count
// through a read-only count (never the claiming transition) and surfaces a
// count failure instead of reporting zero breaches.
func TestComplianceSummary_SLABreachCount(t *testing.T) {
	tenant := uuid.New()
	tests := []struct {
		name     string
		count    int
		countErr error
		wantErr  error
		wantSLA  int
	}{
		{"count reported", 7, nil, nil, 7},
		{"count failure propagates", 0, errSLACount, errSLACount, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := mocks.NewMockFindingRepository(t)
			findings.EXPECT().CountBySeverity(mock.Anything, tenant).Return(map[domain.Severity]int{}, nil)
			findings.EXPECT().List(mock.Anything, mock.Anything).Return(nil, 0, nil)
			findings.EXPECT().CountSLABreached(mock.Anything, tenant).Return(tt.count, tt.countErr)

			svc := usecase.NewComplianceService(findings, mocks.NewMockAssetRepository(t), usecase.NewPolicyService())
			got, err := svc.GetComplianceSummary(context.Background(), tenant)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got.SLABreaches != tt.wantSLA {
				t.Errorf("SLABreaches = %d, want %d", got.SLABreaches, tt.wantSLA)
			}
		})
	}
}
