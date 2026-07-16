package usecase

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/sentiae/vigil/service/internal/domain"
	"github.com/sentiae/vigil/service/internal/port/repository"
	portuc "github.com/sentiae/vigil/service/internal/port/usecase"
)

type gatePolicyService struct {
	repo repository.GatePolicyRepository
}

func NewGatePolicyService(repo repository.GatePolicyRepository) portuc.GatePolicyUseCase {
	return &gatePolicyService{repo: repo}
}

// Resolve reads both layers and applies the pure precedence function. A missing
// row is a nil pointer, never an error — absence is a normal state here.
func (s *gatePolicyService) Resolve(ctx context.Context, tenantID, userID uuid.UUID) (domain.ResolvedGatePolicy, error) {
	org, err := s.repo.FindPolicy(ctx, tenantID)
	if err != nil {
		if !errors.Is(err, domain.ErrGatePolicyNotFound) {
			return domain.ResolvedGatePolicy{}, fmt.Errorf("find gate policy: %w", err)
		}
		org = nil
	}

	// uuid.Nil means the caller has no user layer (delivery's codegen-consumer
	// path runs pipelines with an empty RequestedBy) — skip the lookup.
	var user *domain.GateUserPref
	if userID != uuid.Nil {
		user, err = s.repo.FindUserPref(ctx, tenantID, userID)
		if err != nil {
			if !errors.Is(err, domain.ErrGateUserPrefNotFound) {
				return domain.ResolvedGatePolicy{}, fmt.Errorf("find gate user pref: %w", err)
			}
			user = nil
		}
	}

	return domain.ResolveGatePolicy(org, user), nil
}

func (s *gatePolicyService) GetPolicy(ctx context.Context, tenantID uuid.UUID) (*domain.GatePolicy, error) {
	return s.repo.FindPolicy(ctx, tenantID)
}

func (s *gatePolicyService) SetPolicy(ctx context.Context, in portuc.SetGatePolicyInput) (*domain.GatePolicy, error) {
	if in.Clear {
		if err := s.repo.DeletePolicy(ctx, in.TenantID); err != nil {
			return nil, fmt.Errorf("clear gate policy: %w", err)
		}
		return nil, nil
	}

	existing, err := s.repo.FindPolicy(ctx, in.TenantID)
	if err != nil && !errors.Is(err, domain.ErrGatePolicyNotFound) {
		return nil, fmt.Errorf("find gate policy: %w", err)
	}

	var policy *domain.GatePolicy
	if existing != nil {
		policy = existing
	} else {
		// First write: mode is required — there is no safe mode to invent.
		if !in.SetMode {
			return nil, domain.ErrInvalidGatePolicy
		}
		policy = &domain.GatePolicy{
			TenantID:          in.TenantID,
			SeverityThreshold: domain.SeverityCritical,
			Locked:            true,
		}
	}

	if in.SetMode {
		policy.Mode = in.Mode
	}
	if in.SetSeverityThreshold {
		policy.SeverityThreshold = in.SeverityThreshold
	}
	if in.SetLocked {
		policy.Locked = in.Locked
	}
	policy.UpdatedBy = in.UpdatedBy
	policy.UpdatedAt = time.Now().UTC()

	if err := policy.Validate(); err != nil {
		return nil, err
	}
	if err := s.repo.UpsertPolicy(ctx, policy); err != nil {
		return nil, fmt.Errorf("upsert gate policy: %w", err)
	}
	return policy, nil
}

func (s *gatePolicyService) GetUserPref(ctx context.Context, tenantID, userID uuid.UUID) (*domain.GateUserPref, error) {
	if userID == uuid.Nil {
		return nil, domain.ErrInvalidGatePolicy
	}
	return s.repo.FindUserPref(ctx, tenantID, userID)
}

func (s *gatePolicyService) SetUserPref(ctx context.Context, in portuc.SetGateUserPrefInput) (*domain.GateUserPref, error) {
	// Resolve skips the pref lookup for uuid.Nil (that is its "no user layer"
	// contract), so a Nil-keyed row could never be read back — reject the write
	// here rather than let it become a silent write-only row.
	if in.UserID == uuid.Nil {
		return nil, domain.ErrInvalidGatePolicy
	}

	if in.Clear {
		if err := s.repo.DeleteUserPref(ctx, in.TenantID, in.UserID); err != nil {
			return nil, fmt.Errorf("clear gate user pref: %w", err)
		}
		return nil, nil
	}

	existing, err := s.repo.FindUserPref(ctx, in.TenantID, in.UserID)
	if err != nil && !errors.Is(err, domain.ErrGateUserPrefNotFound) {
		return nil, fmt.Errorf("find gate user pref: %w", err)
	}

	var pref *domain.GateUserPref
	if existing != nil {
		pref = existing
	} else {
		if !in.SetMode {
			return nil, domain.ErrInvalidGatePolicy
		}
		pref = &domain.GateUserPref{
			TenantID:          in.TenantID,
			UserID:            in.UserID,
			SeverityThreshold: domain.SeverityCritical,
		}
	}

	if in.SetMode {
		pref.Mode = in.Mode
	}
	if in.SetSeverityThreshold {
		pref.SeverityThreshold = in.SeverityThreshold
	}
	pref.UpdatedAt = time.Now().UTC()

	if err := pref.Validate(); err != nil {
		return nil, err
	}
	if err := s.repo.UpsertUserPref(ctx, pref); err != nil {
		return nil, fmt.Errorf("upsert gate user pref: %w", err)
	}
	return pref, nil
}
