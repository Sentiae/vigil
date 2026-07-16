package middleware_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/sentiae/platform-kit/authjwt"
	"github.com/sentiae/vigil/service/internal/middleware"
)

const testIssuer = "identity-service"

// newJWKSServer mirrors platform-kit/authjwt's own test harness: a real RSA key
// served over httptest so the middleware exercises real RS256 verification
// rather than a stub.
func newJWKSServer(t *testing.T, kid string) (*httptest.Server, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	nB := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
	eB := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []any{
				map[string]any{"kid": kid, "kty": "RSA", "alg": "RS256", "use": "sig", "n": nB, "e": eB},
			},
		})
	}))
	t.Cleanup(srv.Close)
	return srv, key
}

func mintToken(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// captured records the identity the middleware put on the context, so a test
// can assert what the downstream handler would scope its queries by.
type captured struct {
	called bool
	user   uuid.UUID
	tenant uuid.UUID
}

func newHarness(t *testing.T) (http.Handler, *captured, *rsa.PrivateKey) {
	t.Helper()
	srv, key := newJWKSServer(t, "k1")
	v, err := authjwt.New(authjwt.Config{JWKSURL: srv.URL, Issuer: testIssuer})
	if err != nil {
		t.Fatal(err)
	}
	got := &captured{}
	h := middleware.NewAuthMiddleware(v)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got.called = true
		got.user = middleware.GetUserIDFromContext(r.Context())
		got.tenant = middleware.GetTenantIDFromContext(r.Context())
	}))
	return h, got, key
}

func validClaims(uid, oid uuid.UUID) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":             testIssuer,
		"sub":             uid.String(),
		"organization_id": oid.String(),
		"exp":             time.Now().Add(time.Hour).Unix(),
	}
}

func TestAuthMiddleware_ValidJWT_IdentityFromClaims(t *testing.T) {
	h, got, key := newHarness(t)
	uid, oid := uuid.New(), uuid.New()
	tok := mintToken(t, key, "k1", validClaims(uid, oid))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/findings", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !got.called {
		t.Fatal("handler not reached")
	}
	if got.user != uid {
		t.Fatalf("user: got %s want %s", got.user, uid)
	}
	if got.tenant != oid {
		t.Fatalf("tenant: got %s want %s", got.tenant, oid)
	}
}

// The core of the fix: a valid token plus attacker-controlled identity inputs.
// The claims must win every time — the spoofed values must never reach the
// context the handlers scope their tenant queries by.
func TestAuthMiddleware_SpoofedIdentityInputsIgnored(t *testing.T) {
	attacker := uuid.New()

	tests := []struct {
		name  string
		apply func(*http.Request)
	}{
		{"X-Tenant-ID header", func(r *http.Request) { r.Header.Set("X-Tenant-ID", attacker.String()) }},
		{"X-Organization-ID header", func(r *http.Request) { r.Header.Set("X-Organization-ID", attacker.String()) }},
		{"X-User-ID header", func(r *http.Request) { r.Header.Set("X-User-ID", attacker.String()) }},
		{"organization_id query param", func(r *http.Request) {
			q := r.URL.Query()
			q.Set("organization_id", attacker.String())
			r.URL.RawQuery = q.Encode()
		}},
		{"user_id query param", func(r *http.Request) {
			q := r.URL.Query()
			q.Set("user_id", attacker.String())
			r.URL.RawQuery = q.Encode()
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, got, key := newHarness(t)
			uid, oid := uuid.New(), uuid.New()
			tok := mintToken(t, key, "k1", validClaims(uid, oid))

			req := httptest.NewRequest(http.MethodGet, "/api/v1/security/findings", nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			tt.apply(req)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status: got %d want %d", rec.Code, http.StatusOK)
			}
			if got.tenant == attacker || got.user == attacker {
				t.Fatalf("SPOOF HONORED: user=%s tenant=%s attacker=%s", got.user, got.tenant, attacker)
			}
			if got.user != uid || got.tenant != oid {
				t.Fatalf("claims not authoritative: user=%s tenant=%s want %s/%s", got.user, got.tenant, uid, oid)
			}
		})
	}
}

// The live hole verbatim: junk bearer + ?organization_id=<uuid>. This used to
// sail through the dev path and act as the named tenant.
func TestAuthMiddleware_RejectsUnvalidatedTokens(t *testing.T) {
	attacker := uuid.New()

	tests := []struct {
		name   string
		header string
		query  string
	}{
		{"garbage bearer with organization_id query", "Bearer not-a-jwt", "?organization_id=" + attacker.String()},
		{"garbage bearer", "Bearer not-a-jwt", ""},
		{"absent authorization header", "", ""},
		{"non-bearer scheme", "Basic abc123", ""},
		{"empty bearer token", "Bearer ", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, got, _ := newHarness(t)
			req := httptest.NewRequest(http.MethodGet, "/api/v1/security/findings"+tt.query, nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			req.Header.Set("X-Tenant-ID", attacker.String())
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status: got %d want %d", rec.Code, http.StatusUnauthorized)
			}
			if got.called {
				t.Fatal("handler reached without a validated token")
			}
		})
	}
}

// A token signed by a key the JWKS doesn't publish must not be trusted.
func TestAuthMiddleware_RejectsForeignSignature(t *testing.T) {
	h, got, _ := newHarness(t)
	foreign, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tok := mintToken(t, foreign, "k1", validClaims(uuid.New(), uuid.New()))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/findings", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d want %d", rec.Code, http.StatusUnauthorized)
	}
	if got.called {
		t.Fatal("handler reached with a foreign-signed token")
	}
}

func TestAuthMiddleware_RejectsExpiredAndWrongIssuer(t *testing.T) {
	tests := []struct {
		name   string
		claims func(uuid.UUID, uuid.UUID) jwt.MapClaims
	}{
		{"expired", func(u, o uuid.UUID) jwt.MapClaims {
			c := validClaims(u, o)
			c["exp"] = time.Now().Add(-time.Hour).Unix()
			return c
		}},
		{"wrong issuer", func(u, o uuid.UUID) jwt.MapClaims {
			c := validClaims(u, o)
			c["iss"] = "evil-issuer"
			return c
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, got, key := newHarness(t)
			tok := mintToken(t, key, "k1", tt.claims(uuid.New(), uuid.New()))
			req := httptest.NewRequest(http.MethodGet, "/api/v1/security/findings", nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status: got %d want %d", rec.Code, http.StatusUnauthorized)
			}
			if got.called {
				t.Fatalf("handler reached with %s token", tt.name)
			}
		})
	}
}

// A validated token still needs an org to scope by; uuid.Nil must never reach a
// handler that filters on tenant_id.
func TestAuthMiddleware_RejectsTokenMissingOrgClaim(t *testing.T) {
	h, got, key := newHarness(t)
	claims := jwt.MapClaims{
		"iss": testIssuer,
		"sub": uuid.New().String(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	tok := mintToken(t, key, "k1", claims)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/findings", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d want %d", rec.Code, http.StatusUnauthorized)
	}
	if got.called {
		t.Fatal("handler reached with an org-less token")
	}
}

// There is no configuration in which this middleware serves without a
// validator: constructing it without one is a programming error, and the boot
// path fails before reaching here.
func TestNewAuthMiddleware_NilValidatorPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic when constructed with a nil validator")
		}
	}()
	middleware.NewAuthMiddleware(nil)
}
