package middleware

import (
	"context"
	"net/http"
	"strings"

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

// NewAuthMiddleware builds the HTTP auth middleware. Identity comes from the
// RS256 claims of a JWT validated against identity-service's JWKS — and from
// nothing else.
//
// It deliberately has no header/query-parameter identity path. The previous
// implementation fell back to trusting X-User-ID / X-Tenant-ID /
// X-Organization-ID headers and ?user_id= / ?organization_id= query params
// whenever the validator was nil, which it always was in the fleet
// (JWT_JWKS_URL was a name nothing sets). Since vigil's tenant isolation is
// explicit WHERE tenant_id clauses fed from this context, that handed any
// caller who could reach port 8191 the ability to name the tenant it wanted to
// act as — over per-tenant findings AND the D-155 deploy gate. Claims are now
// the sole source: a spoofed header alongside a valid JWT is ignored, and a
// credential in a URL is never honored under any configuration (it would land
// in access logs and referrers regardless of validation).
//
// validator must be non-nil; the caller (app.NewServer) fails boot rather than
// construct this middleware without one, so there is no configuration in which
// vigil serves this surface unauthenticated.
func NewAuthMiddleware(validator *authjwt.Validator) func(http.Handler) http.Handler {
	if validator == nil {
		panic("middleware: NewAuthMiddleware requires a non-nil JWT validator")
	}
	return func(next http.Handler) http.Handler {
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
			claims, err := validator.Validate(ctx, token)
			if err != nil {
				http.Error(w, `{"error":"unauthorized","message":"invalid token"}`, http.StatusUnauthorized)
				return
			}

			// Every route behind this middleware scopes its reads/writes by the
			// context tenant. A token carrying no user/org would leave those
			// uuid.Nil and query an unscoped identity, so it is rejected here
			// rather than allowed to reach a handler.
			if claims.UserID == uuid.Nil || claims.OrganizationID == uuid.Nil {
				http.Error(w, `{"error":"unauthorized","message":"token missing user or organization claim"}`, http.StatusUnauthorized)
				return
			}

			ctx = context.WithValue(ctx, UserIDContextKey, claims.UserID)
			ctx = context.WithValue(ctx, TenantIDContextKey, claims.OrganizationID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
