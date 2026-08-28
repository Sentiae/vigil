package app

import (
	"context"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/workloadapi"

	pkconfig "github.com/sentiae/platform-kit/config"
	"github.com/sentiae/platform-kit/spiffe"
)

// meshSource acquires the workload SVID this service serves and dials with.
//
// D-189 / §34b: under any mesh mode a missing SVID is a BOOT REFUSAL, never a
// warning. On 2026-08-06 vigil booted 4.5 minutes ahead of the SPIRE agent,
// logged "SPIFFE source unavailable", and served :50054 with no TLS half for
// three weeks — a permissive listener that had degraded to plaintext-only
// silently. The degrade branch is gone: either this returns a source or the
// process refuses to start.
//
// Mode "off" is the one honest exemption — a service that declares itself
// outside the mesh does not dial the Workload API at all.
func meshSource(ctx context.Context) (*workloadapi.X509Source, error) {
	mode := pkconfig.MTLSMode()
	if mode == pkconfig.MTLSModeOff {
		return nil, nil
	}
	src, err := spiffe.NewSource(ctx)
	if err != nil {
		return nil, fmt.Errorf("mesh identity: APP_GRPC_MTLS_MODE=%s but no SVID from the workload API at %q: %w — refusing to boot",
			mode, pkconfig.SPIFFEEndpointSocket(), err)
	}
	return src, nil
}
