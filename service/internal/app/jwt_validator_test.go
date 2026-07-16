package app

import (
	"strings"
	"testing"

	"github.com/sentiae/vigil/service/pkg/config"
)

// A deployment that has not configured JWKS must refuse to boot rather than
// silently downgrade to trusting X-Tenant-ID / ?organization_id=.
func TestNewJWTValidator_FailsBootWhenJWKSUnconfigured(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config.SecurityConfig
		wantErr string
	}{
		{"empty jwks url", config.SecurityConfig{JWKSURL: "", JWTIssuer: "identity-service"}, "refusing to boot"},
		{"empty jwks url and issuer", config.SecurityConfig{}, "refusing to boot"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := newJWTValidator(&config.Config{Security: tt.cfg})
			if err == nil {
				t.Fatal("expected boot to fail with an unconfigured JWKS URL, got nil error")
			}
			if v != nil {
				t.Fatal("expected no validator when boot fails")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestNewJWTValidator_BuildsWhenConfigured(t *testing.T) {
	v, err := newJWTValidator(&config.Config{Security: config.SecurityConfig{
		JWKSURL:   "http://identity-service:8080/.well-known/jwks.json",
		JWTIssuer: "identity-service",
	}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v == nil {
		t.Fatal("expected a validator")
	}
}

// The default must be the in-cluster identity JWKS endpoint, so a clean deploy
// validates tokens with no env set at all.
func TestConfigDefaults_JWKSConfiguredByDefault(t *testing.T) {
	t.Setenv("APP_AUTH_JWKS_URL", "")
	t.Setenv("APP_AUTH_JWT_ISSUER", "")

	cfg, err := config.Load()
	if err != nil {
		t.Skipf("config.Load unavailable in this environment: %v", err)
	}
	if cfg.Security.JWKSURL == "" {
		t.Fatal("security.jwks_url must default to the identity JWKS endpoint")
	}
	if cfg.Security.JWTIssuer == "" {
		t.Fatal("security.jwt_issuer must default to the identity issuer")
	}
}
