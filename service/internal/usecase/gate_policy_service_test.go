package usecase_test

import (
	"context"
	"errors"
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

// errRepo is a non-sentinel failure: the usecase must surface it, never swallow
// it the way it swallows the NotFound sentinels.
var errRepo = errors.New("boom")

func newTestGatePolicyService(t *testing.T) (portuc.GatePolicyUseCase, *mocks.MockGatePolicyRepository) {
	repo := mocks.NewMockGatePolicyRepository(t)
	return usecase.NewGatePolicyService(repo), repo
}

// The pure precedence matrix lives in domain/gate_policy_test.go. These tests
// cover only what the usecase itself owns: which lookups it performs, which
// errors it treats as "absent", and what it stamps before writing.

func TestGatePolicyService_Resolve_NilUserSkipsPrefLookup(t *testing.T) {
	svc, repo := newTestGatePolicyService(t)
	ctx := context.Background()
	tenantID := uuid.New()

	// Only FindPolicy is expected. mockery fails the test if FindUserPref is
	// called at all — that is the assertion that the lookup is skipped.
	repo.EXPECT().FindPolicy(ctx, tenantID).Return(&domain.GatePolicy{
		TenantID:          tenantID,
		Mode:              domain.GateModeEnforce,
		SeverityThreshold: domain.SeverityHigh,
		Locked:            true,
	}, nil)

	got, err := svc.Resolve(ctx, tenantID, uuid.Nil)

	require.NoError(t, err)
	assert.True(t, got.Set)
	assert.Equal(t, domain.GateModeEnforce, got.Mode)
	assert.Equal(t, domain.GateSourceOrg, got.Source)
}

func TestGatePolicyService_Resolve_NilUserAndNoOrgPolicy(t *testing.T) {
	svc, repo := newTestGatePolicyService(t)
	ctx := context.Background()
	tenantID := uuid.New()

	repo.EXPECT().FindPolicy(ctx, tenantID).Return(nil, domain.ErrGatePolicyNotFound)

	got, err := svc.Resolve(ctx, tenantID, uuid.Nil)

	require.NoError(t, err)
	assert.False(t, got.Set)
	assert.Equal(t, domain.GateSourceUnset, got.Source)
}

func TestGatePolicyService_Resolve_NotFoundSentinelsAreAbsenceNotError(t *testing.T) {
	svc, repo := newTestGatePolicyService(t)
	ctx := context.Background()
	tenantID, userID := uuid.New(), uuid.New()

	repo.EXPECT().FindPolicy(ctx, tenantID).Return(nil, domain.ErrGatePolicyNotFound)
	repo.EXPECT().FindUserPref(ctx, tenantID, userID).Return(nil, domain.ErrGateUserPrefNotFound)

	got, err := svc.Resolve(ctx, tenantID, userID)

	require.NoError(t, err)
	assert.False(t, got.Set)
	assert.Equal(t, domain.GateSourceUnset, got.Source)
}

func TestGatePolicyService_Resolve_UserPrefLookedUpForRealUser(t *testing.T) {
	svc, repo := newTestGatePolicyService(t)
	ctx := context.Background()
	tenantID, userID := uuid.New(), uuid.New()

	repo.EXPECT().FindPolicy(ctx, tenantID).Return(nil, domain.ErrGatePolicyNotFound)
	repo.EXPECT().FindUserPref(ctx, tenantID, userID).Return(&domain.GateUserPref{
		TenantID:          tenantID,
		UserID:            userID,
		Mode:              domain.GateModeWarn,
		SeverityThreshold: domain.SeverityLow,
	}, nil)

	got, err := svc.Resolve(ctx, tenantID, userID)

	require.NoError(t, err)
	assert.True(t, got.Set)
	assert.Equal(t, domain.GateModeWarn, got.Mode)
	assert.Equal(t, domain.GateSourceUser, got.Source)
}

func TestGatePolicyService_Resolve_PolicyRepoErrorPropagates(t *testing.T) {
	svc, repo := newTestGatePolicyService(t)
	ctx := context.Background()
	tenantID := uuid.New()

	repo.EXPECT().FindPolicy(ctx, tenantID).Return(nil, errRepo)

	_, err := svc.Resolve(ctx, tenantID, uuid.New())

	require.Error(t, err)
	assert.ErrorIs(t, err, errRepo)
}

func TestGatePolicyService_Resolve_UserPrefRepoErrorPropagates(t *testing.T) {
	svc, repo := newTestGatePolicyService(t)
	ctx := context.Background()
	tenantID, userID := uuid.New(), uuid.New()

	repo.EXPECT().FindPolicy(ctx, tenantID).Return(nil, domain.ErrGatePolicyNotFound)
	repo.EXPECT().FindUserPref(ctx, tenantID, userID).Return(nil, errRepo)

	_, err := svc.Resolve(ctx, tenantID, userID)

	require.Error(t, err)
	assert.ErrorIs(t, err, errRepo)
}

func TestGatePolicyService_SetPolicy_FirstWriteStampsUpdatedBy(t *testing.T) {
	svc, repo := newTestGatePolicyService(t)
	ctx := context.Background()
	tenantID, actor := uuid.New(), uuid.New()

	repo.EXPECT().FindPolicy(ctx, tenantID).Return(nil, domain.ErrGatePolicyNotFound)
	repo.EXPECT().UpsertPolicy(ctx, mock.MatchedBy(func(p *domain.GatePolicy) bool {
		return p.UpdatedBy == actor && !p.UpdatedAt.IsZero()
	})).Return(nil)

	got, err := svc.SetPolicy(ctx, portuc.SetGatePolicyInput{
		TenantID:  tenantID,
		UpdatedBy: actor,
		SetMode:   true,
		Mode:      domain.GateModeEnforce,
	})

	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, actor, got.UpdatedBy)
	assert.False(t, got.UpdatedAt.IsZero())
	// Defaults the usecase invents for a first write.
	assert.Equal(t, domain.SeverityCritical, got.SeverityThreshold)
	assert.True(t, got.Locked)
}

func TestGatePolicyService_SetPolicy_RestampsUpdatedByOnExisting(t *testing.T) {
	svc, repo := newTestGatePolicyService(t)
	ctx := context.Background()
	tenantID, original, actor := uuid.New(), uuid.New(), uuid.New()

	repo.EXPECT().FindPolicy(ctx, tenantID).Return(&domain.GatePolicy{
		TenantID:          tenantID,
		Mode:              domain.GateModeEnforce,
		SeverityThreshold: domain.SeverityHigh,
		Locked:            true,
		UpdatedBy:         original,
	}, nil)
	repo.EXPECT().UpsertPolicy(ctx, mock.AnythingOfType("*domain.GatePolicy")).Return(nil)

	// Partial update: only Locked is set, so Mode/threshold must survive.
	got, err := svc.SetPolicy(ctx, portuc.SetGatePolicyInput{
		TenantID:  tenantID,
		UpdatedBy: actor,
		SetLocked: true,
		Locked:    false,
	})

	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, actor, got.UpdatedBy, "updated_by must be re-stamped to the new actor")
	assert.False(t, got.Locked)
	assert.Equal(t, domain.GateModeEnforce, got.Mode, "unset field must be preserved")
	assert.Equal(t, domain.SeverityHigh, got.SeverityThreshold, "unset field must be preserved")
}

func TestGatePolicyService_SetPolicy_FirstWriteWithoutModeRejected(t *testing.T) {
	svc, repo := newTestGatePolicyService(t)
	ctx := context.Background()
	tenantID := uuid.New()

	repo.EXPECT().FindPolicy(ctx, tenantID).Return(nil, domain.ErrGatePolicyNotFound)

	_, err := svc.SetPolicy(ctx, portuc.SetGatePolicyInput{
		TenantID:  tenantID,
		UpdatedBy: uuid.New(),
		SetLocked: true,
		Locked:    true,
	})

	assert.ErrorIs(t, err, domain.ErrInvalidGatePolicy)
}

func TestGatePolicyService_SetPolicy_ZeroUpdatedByRejectedByValidate(t *testing.T) {
	svc, repo := newTestGatePolicyService(t)
	ctx := context.Background()
	tenantID := uuid.New()

	repo.EXPECT().FindPolicy(ctx, tenantID).Return(nil, domain.ErrGatePolicyNotFound)

	// No UpsertPolicy expectation: Validate must reject before the write.
	_, err := svc.SetPolicy(ctx, portuc.SetGatePolicyInput{
		TenantID: tenantID,
		SetMode:  true,
		Mode:     domain.GateModeEnforce,
	})

	assert.ErrorIs(t, err, domain.ErrInvalidGatePolicy)
}

func TestGatePolicyService_SetPolicy_ClearDeletesAndSkipsUpsert(t *testing.T) {
	svc, repo := newTestGatePolicyService(t)
	ctx := context.Background()
	tenantID := uuid.New()

	repo.EXPECT().DeletePolicy(ctx, tenantID).Return(nil)

	got, err := svc.SetPolicy(ctx, portuc.SetGatePolicyInput{
		TenantID:  tenantID,
		UpdatedBy: uuid.New(),
		Clear:     true,
		SetMode:   true,
		Mode:      domain.GateModeOff,
	})

	require.NoError(t, err)
	assert.Nil(t, got, "Clear returns a nil policy")
}

func TestGatePolicyService_SetUserPref_FirstWriteWithoutModeRejected(t *testing.T) {
	svc, repo := newTestGatePolicyService(t)
	ctx := context.Background()
	tenantID, userID := uuid.New(), uuid.New()

	repo.EXPECT().FindUserPref(ctx, tenantID, userID).Return(nil, domain.ErrGateUserPrefNotFound)

	_, err := svc.SetUserPref(ctx, portuc.SetGateUserPrefInput{
		TenantID:             tenantID,
		UserID:               userID,
		SetSeverityThreshold: true,
		SeverityThreshold:    domain.SeverityLow,
	})

	assert.ErrorIs(t, err, domain.ErrInvalidGatePolicy)
}

func TestGatePolicyService_SetUserPref_FirstWriteDefaultsThreshold(t *testing.T) {
	svc, repo := newTestGatePolicyService(t)
	ctx := context.Background()
	tenantID, userID := uuid.New(), uuid.New()

	repo.EXPECT().FindUserPref(ctx, tenantID, userID).Return(nil, domain.ErrGateUserPrefNotFound)
	repo.EXPECT().UpsertUserPref(ctx, mock.MatchedBy(func(p *domain.GateUserPref) bool {
		return p.UserID == userID && !p.UpdatedAt.IsZero()
	})).Return(nil)

	got, err := svc.SetUserPref(ctx, portuc.SetGateUserPrefInput{
		TenantID: tenantID,
		UserID:   userID,
		SetMode:  true,
		Mode:     domain.GateModeWarn,
	})

	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, domain.GateModeWarn, got.Mode)
	assert.Equal(t, domain.SeverityCritical, got.SeverityThreshold)
}

func TestGatePolicyService_SetUserPref_ClearDeletesAndSkipsUpsert(t *testing.T) {
	svc, repo := newTestGatePolicyService(t)
	ctx := context.Background()
	tenantID, userID := uuid.New(), uuid.New()

	repo.EXPECT().DeleteUserPref(ctx, tenantID, userID).Return(nil)

	got, err := svc.SetUserPref(ctx, portuc.SetGateUserPrefInput{
		TenantID: tenantID,
		UserID:   userID,
		Clear:    true,
	})

	require.NoError(t, err)
	assert.Nil(t, got, "Clear returns a nil pref")
}

// The usecase is the port boundary and defends itself: the gRPC handler's
// parseUserID guard only holds while the handler is the sole caller.

func TestGatePolicyService_GetUserPref_NilUserRejected(t *testing.T) {
	svc, repo := newTestGatePolicyService(t)
	ctx := context.Background()

	// No repo expectation: the guard must reject before any lookup.
	_, err := svc.GetUserPref(ctx, uuid.New(), uuid.Nil)

	assert.ErrorIs(t, err, domain.ErrInvalidGatePolicy)
	repo.AssertNotCalled(t, "FindUserPref", mock.Anything, mock.Anything, mock.Anything)
}

func TestGatePolicyService_SetUserPref_NilUserRejected(t *testing.T) {
	svc, repo := newTestGatePolicyService(t)
	ctx := context.Background()

	// No repo expectation: a Nil-keyed row must never be upserted, because
	// Resolve skips uuid.Nil and could never read it back.
	_, err := svc.SetUserPref(ctx, portuc.SetGateUserPrefInput{
		TenantID: uuid.New(),
		UserID:   uuid.Nil,
		SetMode:  true,
		Mode:     domain.GateModeWarn,
	})

	assert.ErrorIs(t, err, domain.ErrInvalidGatePolicy)
	repo.AssertNotCalled(t, "UpsertUserPref", mock.Anything, mock.Anything)
}

func TestGatePolicyService_SetUserPref_NilUserRejectedEvenOnClear(t *testing.T) {
	svc, repo := newTestGatePolicyService(t)
	ctx := context.Background()

	// The guard precedes the Clear branch, so a Nil id cannot reach DeleteUserPref.
	_, err := svc.SetUserPref(ctx, portuc.SetGateUserPrefInput{
		TenantID: uuid.New(),
		UserID:   uuid.Nil,
		Clear:    true,
	})

	assert.ErrorIs(t, err, domain.ErrInvalidGatePolicy)
	repo.AssertNotCalled(t, "DeleteUserPref", mock.Anything, mock.Anything, mock.Anything)
}

func TestGatePolicyService_Resolve_NilUserStillResolvesAfterGuard(t *testing.T) {
	svc, repo := newTestGatePolicyService(t)
	ctx := context.Background()
	tenantID := uuid.New()

	// Resolve must NOT inherit the Get/SetUserPref guard: uuid.Nil is its
	// deliberate "no user layer" contract (delivery's codegen path).
	repo.EXPECT().FindPolicy(ctx, tenantID).Return(&domain.GatePolicy{
		TenantID:          tenantID,
		Mode:              domain.GateModeWarn,
		SeverityThreshold: domain.SeverityMedium,
		Locked:            false,
	}, nil)

	got, err := svc.Resolve(ctx, tenantID, uuid.Nil)

	require.NoError(t, err, "Resolve must not reject uuid.Nil")
	assert.True(t, got.Set)
	assert.Equal(t, domain.GateSourceOrgDefault, got.Source)
}

func TestGatePolicyService_GetPolicy_PropagatesNotFound(t *testing.T) {
	svc, repo := newTestGatePolicyService(t)
	ctx := context.Background()
	tenantID := uuid.New()

	repo.EXPECT().FindPolicy(ctx, tenantID).Return(nil, domain.ErrGatePolicyNotFound)

	_, err := svc.GetPolicy(ctx, tenantID)

	assert.ErrorIs(t, err, domain.ErrGatePolicyNotFound)
}

func TestGatePolicyService_GetUserPref_PropagatesNotFound(t *testing.T) {
	svc, repo := newTestGatePolicyService(t)
	ctx := context.Background()
	tenantID, userID := uuid.New(), uuid.New()

	repo.EXPECT().FindUserPref(ctx, tenantID, userID).Return(nil, domain.ErrGateUserPrefNotFound)

	_, err := svc.GetUserPref(ctx, tenantID, userID)

	assert.ErrorIs(t, err, domain.ErrGateUserPrefNotFound)
}
