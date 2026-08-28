package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "go.uber.org/automaxprocs"

	pkdebug "github.com/sentiae/platform-kit/debug"
	pkkafka "github.com/sentiae/platform-kit/kafka"
	otelkit "github.com/sentiae/platform-kit/otel"
	"github.com/sentiae/vigil/service/internal/app"
	"github.com/sentiae/vigil/service/pkg/config"
	"github.com/sentiae/vigil/service/pkg/logger"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
)

// maybeRegisterKafkaSchemas runs the G17 schema-registry bootstrap.
// Gated by APP_KAFKA_REGISTER_SCHEMAS_ON_BOOT=true.
func maybeRegisterKafkaSchemas() {
	if os.Getenv("APP_KAFKA_REGISTER_SCHEMAS_ON_BOOT") != "true" {
		return
	}
	url := os.Getenv("APP_KAFKA_SCHEMA_REGISTRY_URL")
	if url == "" {
		return
	}
	prefix := os.Getenv("APP_KAFKA_TOPIC_PREFIX")
	if prefix == "" {
		prefix = "sentiae"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	registry := pkkafka.NewSchemaRegistry(url)
	result := pkkafka.RegisterAllSchemas(ctx, registry, prefix)
	if len(result.Errors) > 0 {
		log.Printf("schema-registry bootstrap: registered=%d skipped=%d errors=%d (first: %s)",
			result.Registered, result.Skipped, len(result.Errors), result.Errors[0])
		return
	}
	log.Printf("schema-registry bootstrap: registered %d schemas", result.Registered)
}

func main() { os.Exit(run()) }

// run is the whole bootstrap, returning the process exit code rather than
// exiting from inside it: an exit call skips deferred work, and on every
// failure path — a refused SVID, a refused mTLS self-probe, a panicking accept
// loop — the deferred srv.Close → shutdownTelemetry → stopPprof → stop are
// exactly what must still run (§21 steps 7-8). The one process exit lives in
// main, after run has returned and every defer has completed.
func run() int {
	// The signal context is installed FIRST, before any boot work: NewServer can
	// wait up to 60s for an SVID and Start up to 15s for the self-probe, and a
	// SIGTERM inside that window must cancel the wait, not take Go's default
	// action of killing the process with no shutdown and no telemetry flush
	// (CLAUDE.md §12).
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go maybeRegisterKafkaSchemas()

	stopPprof := pkdebug.StartPprofServer(ctx, "VIGIL_DEBUG_PPROF")
	defer func() { _ = stopPprof() }()

	// 1. Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("Failed to load config: %v\n", err)
		return 1
	}

	// 2. Initialize Telemetry (traces, metrics & logs → OTLP collector). Runs
	// before the logger so SlogHandler binds to the global logger provider set
	// here, not the no-op default.
	shutdownTelemetry, err := otelkit.Init(ctx, otelkit.Config{
		ServiceName:    cfg.Telemetry.ServiceName,
		ServiceVersion: Version,
		Environment:    cfg.Server.Environment,
		Endpoint:       cfg.Telemetry.OTLPEndpoint,
		Insecure:       true,
	})
	if err != nil {
		logger.Error(ctx, "Failed to init telemetry", "error", err)
	}
	defer func() {
		if shutdownTelemetry != nil {
			_ = shutdownTelemetry(context.Background())
		}
	}()

	// 3. Initialize Logger (tees stdout JSON + trace-correlated OTLP logs).
	logger.Init(cfg.Server.LogLevel, otelkit.SlogHandler(cfg.Telemetry.ServiceName))
	logger.Info(ctx, "Starting vigil-service", "version", Version, "build_time", BuildTime)
	logger.Info(ctx, "Environment", "env", cfg.Server.Environment)

	// 4. Create and wire the server
	srv, err := app.NewServer(ctx, cfg, Version)
	if err != nil {
		if ctx.Err() != nil {
			// A stop signal during setup (e.g. mid SVID wait) is a shutdown, not a
			// failed boot: exit 0 so the supervisor does not restart a stopped unit.
			logger.Info(ctx, "Shutdown signal during server setup", "error", err)
			return 0
		}
		logger.Error(ctx, "Server setup failed", "error", err)
		fmt.Fprintf(os.Stderr, "FATAL: server setup failed: %v\n", err)
		return 1
	}
	defer srv.Close()

	// 5. Start servers
	serverErr := make(chan error, 2)
	srv.Start(ctx, serverErr)

	// 6. Wait for a stop signal or a server error
	exitCode := 0
	select {
	case <-ctx.Done():
		logger.Info(ctx, "Received shutdown signal")
	case err := <-serverErr:
		logger.Error(ctx, "Server startup failed, initiating shutdown", "error", err)
		exitCode = 1
	}

	// 7. Graceful shutdown; the deferred srv.Close → shutdownTelemetry →
	// stopPprof → stop run in that order on every return path (§21 steps 7-8).
	// A boot that could not serve returns NON-ZERO so the supervisor restarts it
	// instead of leaving a half-started process alive (D-189: a mesh listener
	// that cannot serve mTLS is a refusal, not a degrade).
	srv.Shutdown(ctx)
	return exitCode
}
