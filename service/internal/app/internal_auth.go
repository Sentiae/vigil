package app

import (
	"context"
	"crypto/subtle"
	"errors"
)

// serviceTokenValidator implements interceptor.APIKeyValidator: it accepts an
// inbound service-to-service x-api-key when it matches the configured token
// (constant-time compare). When no token is configured (dev), all calls pass.
// Mirrors catalog-service / codegen-service.
type serviceTokenValidator struct {
	expected string
}

func (v serviceTokenValidator) Validate(_ context.Context, key string) error {
	if v.expected == "" {
		return nil // not configured: trust in-cluster traffic (dev)
	}
	if subtle.ConstantTimeCompare([]byte(key), []byte(v.expected)) != 1 {
		return errors.New("invalid service token")
	}
	return nil
}
