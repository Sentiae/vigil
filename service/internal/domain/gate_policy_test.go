package domain

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestGateModeValid(t *testing.T) {
	tests := []struct {
		name string
		mode GateMode
		want bool
	}{
		{"enforce", GateModeEnforce, true},
		{"warn", GateModeWarn, true},
		{"off", GateModeOff, true},
		{"empty", GateMode(""), false},
		{"unknown", GateMode("yolo"), false},
		{"case sensitive", GateMode("Enforce"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.mode.Valid(); got != tt.want {
				t.Fatalf("GateMode(%q).Valid() = %v, want %v", tt.mode, got, tt.want)
			}
		})
	}
}

func TestValidGateThreshold(t *testing.T) {
	tests := []struct {
		name string
		sev  Severity
		want bool
	}{
		{"critical", SeverityCritical, true},
		{"high", SeverityHigh, true},
		{"medium", SeverityMedium, true},
		{"low", SeverityLow, true},
		// info is a valid finding Severity but never gates a deploy.
		{"info never gates", SeverityInfo, false},
		{"empty", Severity(""), false},
		{"unknown", Severity("catastrophic"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidGateThreshold(tt.sev); got != tt.want {
				t.Fatalf("ValidGateThreshold(%q) = %v, want %v", tt.sev, got, tt.want)
			}
		})
	}
}

func TestGatePolicyValidate(t *testing.T) {
	someone := uuid.New()
	tests := []struct {
		name    string
		policy  GatePolicy
		wantErr error
	}{
		{"valid", GatePolicy{Mode: GateModeEnforce, SeverityThreshold: SeverityCritical, UpdatedBy: someone}, nil},
		{"valid off/low", GatePolicy{Mode: GateModeOff, SeverityThreshold: SeverityLow, UpdatedBy: someone}, nil},
		{"bad mode", GatePolicy{Mode: GateMode("yolo"), SeverityThreshold: SeverityCritical, UpdatedBy: someone}, ErrInvalidGatePolicy},
		{"empty mode", GatePolicy{SeverityThreshold: SeverityCritical, UpdatedBy: someone}, ErrInvalidGatePolicy},
		{"info threshold", GatePolicy{Mode: GateModeWarn, SeverityThreshold: SeverityInfo, UpdatedBy: someone}, ErrInvalidGatePolicy},
		{"bad threshold", GatePolicy{Mode: GateModeWarn, SeverityThreshold: Severity("nope"), UpdatedBy: someone}, ErrInvalidGatePolicy},
		{"zero updated_by", GatePolicy{Mode: GateModeWarn, SeverityThreshold: SeverityCritical}, ErrInvalidGatePolicy},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.Validate()
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestGateUserPrefValidate(t *testing.T) {
	tests := []struct {
		name    string
		pref    GateUserPref
		wantErr error
	}{
		{"valid", GateUserPref{Mode: GateModeOff, SeverityThreshold: SeverityHigh}, nil},
		{"bad mode", GateUserPref{Mode: GateMode("yolo"), SeverityThreshold: SeverityHigh}, ErrInvalidGatePolicy},
		{"empty mode", GateUserPref{SeverityThreshold: SeverityHigh}, ErrInvalidGatePolicy},
		{"info threshold", GateUserPref{Mode: GateModeWarn, SeverityThreshold: SeverityInfo}, ErrInvalidGatePolicy},
		{"empty threshold", GateUserPref{Mode: GateModeWarn}, ErrInvalidGatePolicy},
		// A user pref carries no UpdatedBy — a zero UserID is not a validation
		// concern here (the repo key supplies it).
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.pref.Validate()
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestResolveGatePolicy walks the full precedence matrix (design §4):
// org-locked → user → org-default → unset.
func TestResolveGatePolicy(t *testing.T) {
	orgLocked := &GatePolicy{Mode: GateModeEnforce, SeverityThreshold: SeverityCritical, Locked: true}
	orgUnlocked := &GatePolicy{Mode: GateModeWarn, SeverityThreshold: SeverityHigh, Locked: false}
	userPref := &GateUserPref{Mode: GateModeOff, SeverityThreshold: SeverityLow}

	tests := []struct {
		name          string
		org           *GatePolicy
		user          *GateUserPref
		wantSet       bool
		wantMode      GateMode
		wantThreshold Severity
		wantSource    GatePolicySource
	}{
		{
			name: "org locked + user set → org wins, user inert",
			org:  orgLocked, user: userPref,
			wantSet: true, wantMode: GateModeEnforce, wantThreshold: SeverityCritical, wantSource: GateSourceOrg,
		},
		{
			name: "org locked + no user → org",
			org:  orgLocked, user: nil,
			wantSet: true, wantMode: GateModeEnforce, wantThreshold: SeverityCritical, wantSource: GateSourceOrg,
		},
		{
			name: "org unlocked + user set → user wins",
			org:  orgUnlocked, user: userPref,
			wantSet: true, wantMode: GateModeOff, wantThreshold: SeverityLow, wantSource: GateSourceUser,
		},
		{
			name: "org unlocked + no user → org_default",
			org:  orgUnlocked, user: nil,
			wantSet: true, wantMode: GateModeWarn, wantThreshold: SeverityHigh, wantSource: GateSourceOrgDefault,
		},
		{
			name: "no org + user set → user",
			org:  nil, user: userPref,
			wantSet: true, wantMode: GateModeOff, wantThreshold: SeverityLow, wantSource: GateSourceUser,
		},
		{
			// The empty-user_id / codegen path: delivery resolves with no user
			// layer and nothing configured — must yield unset, not an error.
			name: "neither → unset, caller applies its platform default",
			org:  nil, user: nil,
			wantSet: false, wantMode: "", wantThreshold: "", wantSource: GateSourceUnset,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveGatePolicy(tt.org, tt.user)
			if got.Set != tt.wantSet {
				t.Errorf("Set = %v, want %v", got.Set, tt.wantSet)
			}
			if got.Mode != tt.wantMode {
				t.Errorf("Mode = %q, want %q", got.Mode, tt.wantMode)
			}
			if got.SeverityThreshold != tt.wantThreshold {
				t.Errorf("SeverityThreshold = %q, want %q", got.SeverityThreshold, tt.wantThreshold)
			}
			if got.Source != tt.wantSource {
				t.Errorf("Source = %q, want %q", got.Source, tt.wantSource)
			}
		})
	}
}

// ResolveGatePolicy must not mutate its inputs — callers pass stored rows.
func TestResolveGatePolicyDoesNotMutateInputs(t *testing.T) {
	org := &GatePolicy{Mode: GateModeEnforce, SeverityThreshold: SeverityCritical, Locked: true}
	user := &GateUserPref{Mode: GateModeOff, SeverityThreshold: SeverityLow}
	orgCopy, userCopy := *org, *user

	ResolveGatePolicy(org, user)

	if *org != orgCopy {
		t.Errorf("org mutated: %+v", *org)
	}
	if *user != userCopy {
		t.Errorf("user mutated: %+v", *user)
	}
}
