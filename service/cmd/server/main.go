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

	"github.com/sentiae/vigil/service/internal/app"
	"github.com/sentiae/vigil/service/pkg/config"
	"github.com/sentiae/vigil/service/pkg/logger"
	pkdebug "github.com/sentiae/platform-kit/debug"
	pkkafka "github.com/sentiae/platform-kit/kafka"
	otelkit "github.com/sentiae/platform-kit/otel"
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

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go maybeRegisterKafkaSchemas()

	stopPprof := pkdebug.StartPprofServer(ctx, "VIGIL_DEBUG_PPROF")
	defer func() { _ = stopPprof() }()

	// 1. Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("Failed to load config: %v\n", err)
		os.Exit(1)
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
		logger.Error(ctx, "Server setup failed", "error", err)
		fmt.Fprintf(os.Stderr, "FATAL: server setup failed: %v\n", err)
		os.Exit(1)
	}
	defer srv.Close()

	// 5. Start servers
	serverErr := make(chan error, 2)
	srv.Start(ctx, serverErr)

	// 6. Wait for interrupt signal or server error
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-quit:
		logger.Info(ctx, "Received shutdown signal")
	case err := <-serverErr:
		logger.Error(ctx, "Server startup failed, initiating shutdown", "error", err)
	}

	// 7. Graceful shutdown
	cancel()
	srv.Shutdown(ctx)
}
