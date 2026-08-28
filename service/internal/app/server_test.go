package app

import (
	"strings"
	"testing"
)

// TestForwardPanic pins the shape a panicking accept loop must take: the panic
// becomes an error on serverErr, which main turns into an orderly Shutdown, a
// telemetry flush and exit 1. A bare crash loses the last log lines; a
// log-and-continue would leave a dead listener behind a healthy /health, which
// is the exact failure class this slice exists to close.
func TestForwardPanic(t *testing.T) {
	errs := make(chan error, 1)
	done := make(chan struct{})

	go func() {
		defer close(done)
		defer forwardPanic(errs, "gRPC server")
		panic("boom")
	}()
	<-done

	select {
	case err := <-errs:
		if err == nil {
			t.Fatal("forwardPanic sent a nil error")
		}
		if !strings.Contains(err.Error(), "gRPC server panicked: boom") {
			t.Fatalf("forwarded error = %q, want it to contain %q", err, "gRPC server panicked: boom")
		}
	default:
		t.Fatal("panic was not forwarded on serverErr")
	}
}
