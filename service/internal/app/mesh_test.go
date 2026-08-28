package app

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadapi"

	pkconfig "github.com/sentiae/platform-kit/config"
)

// TestMeshSource pins the boot posture that was missing on 2026-08-06: under a
// mesh mode, an unreachable Workload API is an ERROR that refuses the boot —
// never a nil source that silently becomes a plaintext-only listener. Mode
// "off" is the one exemption and must not even dial.
func TestMeshSource(t *testing.T) {
	const missingSocket = "unix:///nonexistent/api.sock"

	tests := []struct {
		name        string
		mode        string
		deadline    time.Duration // 0 = no deadline on the context
		wantErr     bool
		wantWithin  time.Duration
		errContains []string
	}{
		{
			name:       "off does not dial the workload api",
			mode:       pkconfig.MTLSModeOff,
			wantErr:    false,
			wantWithin: 100 * time.Millisecond,
		},
		{
			name:        "strict with no workload api refuses to boot",
			mode:        pkconfig.MTLSModeStrict,
			deadline:    2 * time.Second,
			wantErr:     true,
			errContains: []string{"refusing to boot", "APP_GRPC_MTLS_MODE=strict"},
		},
		{
			name:        "permissive with no workload api refuses to boot",
			mode:        pkconfig.MTLSModePermissive,
			deadline:    2 * time.Second,
			wantErr:     true,
			errContains: []string{"refusing to boot", "APP_GRPC_MTLS_MODE=permissive"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("APP_GRPC_MTLS_MODE", tt.mode)
			t.Setenv("SPIFFE_ENDPOINT_SOCKET", missingSocket)

			ctx := context.Background()
			if tt.deadline > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tt.deadline)
				defer cancel()
			}

			start := time.Now()
			src, err := meshSource(ctx)
			elapsed := time.Since(start)

			if !tt.wantErr {
				if err != nil {
					t.Fatalf("meshSource(%s) = %v, want nil error", tt.mode, err)
				}
				if src != nil {
					t.Fatalf("meshSource(%s) returned a source; mode off must not dial the workload API", tt.mode)
				}
				if tt.wantWithin > 0 && elapsed > tt.wantWithin {
					t.Fatalf("meshSource(off) took %s; it must return without dialing (< %s)", elapsed, tt.wantWithin)
				}
				return
			}

			if err == nil {
				t.Fatalf("meshSource(%s) returned no error with %s unreachable; a mesh mode without an SVID must refuse the boot (src=%v)", tt.mode, missingSocket, src)
			}
			if src != nil {
				t.Fatalf("meshSource(%s) returned both a source and an error", tt.mode)
			}
			for _, want := range tt.errContains {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("meshSource(%s) error %q does not contain %q", tt.mode, err, want)
				}
			}
			if !strings.Contains(err.Error(), missingSocket) {
				t.Fatalf("meshSource(%s) error %q does not name the socket %q the operator must fix", tt.mode, err, missingSocket)
			}
		})
	}
}

// TestMeshSource_CancelledContextEndsWait pins the reason the signal context is
// installed before any boot work: the SVID wait is bounded at 60s, and a
// SIGTERM inside that window must end it. spiffe.NewSource derives its probe
// context from the caller's, so threading the signal ctx through NewServer is
// what makes a stop signal during boot a shutdown instead of a hang.
func TestMeshSource_CancelledContextEndsWait(t *testing.T) {
	t.Setenv("APP_GRPC_MTLS_MODE", pkconfig.MTLSModeStrict)
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", "unix:///nonexistent/api.sock")

	// No deadline on the context, so the 60s retry path is the one exercised;
	// only the cancellation can end it.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type result struct {
		src *workloadapi.X509Source
		err error
	}
	done := make(chan result, 1)

	start := time.Now()
	time.AfterFunc(200*time.Millisecond, cancel)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- result{err: fmt.Errorf("meshSource panicked: %v", r)}
			}
		}()
		src, err := meshSource(ctx)
		done <- result{src: src, err: err}
	}()

	select {
	case got := <-done:
		elapsed := time.Since(start)
		if got.src != nil {
			t.Fatalf("meshSource returned a source %v after cancellation", got.src)
		}
		if got.err == nil {
			t.Fatal("meshSource returned no error after its context was cancelled")
		}
		if !strings.Contains(got.err.Error(), "refusing to boot") {
			t.Fatalf("meshSource error %q does not contain %q", got.err, "refusing to boot")
		}
		if elapsed >= 2*time.Second {
			t.Fatalf("meshSource took %s to honour a cancellation at 200ms", elapsed)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("meshSource ignored ctx cancellation; SIGTERM during the SVID wait would hang the boot")
	}
}
