package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/sentiae/platform-kit/authjwt"
)

type contextKey string

const (
	UserIDContextKey   contextKey = "user_id"
	TenantIDContextKey contextKey = "tenant_id"
)

// GetUserIDFromContext extracts the authenticated user ID from the request context.
func GetUserIDFromContext(ctx context.Context) uuid.UUID {
	if v, ok := ctx.Value(UserIDContextKey).(uuid.UUID); ok {
		return v
	}
	return uuid.Nil
}

// GetTenantIDFromContext extracts the tenant (organization) ID from the request context.
func GetTenantIDFromContext(ctx context.Context) uuid.UUID {
	if v, ok := ctx.Value(TenantIDContextKey).(uuid.UUID); ok {
		return v
	}
	return uuid.Nil
}

// jwtValidator is lazily constructed from env on first request so
// tests that don't set JWT_JWKS_URL still exercise the dev path.
var (
	jwtValidatorOnce sync.Once
	jwtValidator     *authjwt.Validator
)

func getJWTValidator() *authjwt.Validator {
	jwtValidatorOnce.Do(func() {
		jwksURL := os.Getenv("JWT_JWKS_URL")
		if jwksURL == "" {
			return
		}
		audiences := splitCSV(os.Getenv("JWT_AUDIENCES"))
		v, err := authjwt.New(authjwt.Config{
			JWKSURL:   jwksURL,
			Issuer:    os.Getenv("JWT_ISSUER"),
			Audiences: audiences,
		})
		if err != nil {
			slog.Warn("JWT validator init failed, falling back to dev-mode headers", "err", err)
			return
		}
		jwtValidator = v
	})
	return jwtValidator
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// AuthMiddleware validates the Authorization bearer token. When a JWT
// validator is configured (JWT_JWKS_URL env), claims drive the
// (user_id, tenant_id) context. Otherwise we fall back to reading the
// X-User-ID/X-Organization-ID/X-Tenant-ID headers the earlier dev
// setup uses — sibling services rely on this path today.
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error":"unauthorized","message":"missing authorization header"}`, http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == authHeader {
			http.Error(w, `{"error":"unauthorized","message":"invalid authorization format"}`, http.StatusUnauthorized)
			return
		}

		ctx := r.Context()

		// Production path: JWT + JWKS. When validation succeeds, the
		// claims are the source of truth and header overrides are
		// ignored so a misbehaving caller can't spoof identity.
		if v := getJWTValidator(); v != nil {
			claims, err := v.Validate(ctx, token)
			if err != nil {
				http.Error(w, `{"error":"unauthorized","message":"invalid token"}`, http.StatusUnauthorized)
				return
			}
			if claims.UserID != uuid.Nil {
				ctx = context.WithValue(ctx, UserIDContextKey, claims.UserID)
			}
			if claims.OrganizationID != uuid.Nil {
				ctx = context.WithValue(ctx, TenantIDContextKey, claims.OrganizationID)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Dev path: trust the headers sibling services forward.
		userIDStr := r.Header.Get("X-User-ID")
		tenantIDStr := r.Header.Get("X-Tenant-ID")
		if tenantIDStr == "" {
			tenantIDStr = r.Header.Get("X-Organization-ID")
		}
		if userIDStr == "" {
			userIDStr = r.URL.Query().Get("user_id")
		}
		if tenantIDStr == "" {
			tenantIDStr = r.URL.Query().Get("organization_id")
		}
		if uid, err := uuid.Parse(userIDStr); err == nil {
			ctx = context.WithValue(ctx, UserIDContextKey, uid)
		}
		if tid, err := uuid.Parse(tenantIDStr); err == nil {
			ctx = context.WithValue(ctx, TenantIDContextKey, tid)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
