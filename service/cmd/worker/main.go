package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/hibiken/asynq"

	scannerPkg "github.com/sentiae/vigil/service/internal/adapter/scanner"
	"github.com/sentiae/vigil/service/internal/adapter/scanner/cicd"
	"github.com/sentiae/vigil/service/internal/adapter/scanner/compliance"
	containerscanner "github.com/sentiae/vigil/service/internal/adapter/scanner/container"
	"github.com/sentiae/vigil/service/internal/adapter/scanner/cspm"
	dbscanner "github.com/sentiae/vigil/service/internal/adapter/scanner/database"
	"github.com/sentiae/vigil/service/internal/adapter/scanner/iac"
	"github.com/sentiae/vigil/service/internal/adapter/scanner/network"
	"github.com/sentiae/vigil/service/internal/adapter/scanner/sast"
	"github.com/sentiae/vigil/service/internal/adapter/scanner/sca"
	"github.com/sentiae/vigil/service/internal/adapter/scanner/secrets"
	apiscanner "github.com/sentiae/vigil/service/internal/adapter/scanner/api"
	"github.com/sentiae/vigil/service/internal/adapter/scanner/discovery"
	"github.com/sentiae/vigil/service/internal/adapter/scanner/headers"
	"github.com/sentiae/vigil/service/internal/adapter/scanner/web"
	"github.com/sentiae/vigil/service/internal/adapter/repository/postgres"
	"github.com/sentiae/vigil/service/internal/domain"
	"github.com/sentiae/vigil/service/internal/usecase"
	kafka "github.com/sentiae/platform-kit/kafka"

	"github.com/sentiae/vigil/service/pkg/config"
	"github.com/sentiae/vigil/service/pkg/database"
	"github.com/sentiae/vigil/service/pkg/events"
	"github.com/sentiae/vigil/service/pkg/logger"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// 2. Initialize Logger
	logger.Init(cfg.Server.LogLevel)
	logger.Info(ctx, "Starting vigil-worker", "version", Version, "build_time", BuildTime)

	// 3. Connect to PostgreSQL
	pool, err := database.NewPostgresPool(ctx, cfg.Database)
	if err != nil {
		logger.Error(ctx, "Database connection failed", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	// 4. Setup Kafka publisher
	var publisher events.Publisher
	if len(cfg.Kafka.Brokers) > 0 {
		pub, err := kafka.NewPublisher(kafka.PublisherConfig{
			Brokers:      cfg.Kafka.Brokers,
			Source:       "vigil-service",
			RequiredAcks: -1,
		})
		if err != nil {
			logger.Warn(ctx, "Failed to create Kafka publisher", "error", err)
		} else {
			publisher = pub
			defer pub.Close()
		}
	}

	// 5. Setup repositories, services, and use cases
	findingRepo := postgres.NewFindingRepository(pool)
	scanRepo := postgres.NewScanRepository(pool)
	assetRepo := postgres.NewAssetRepository(pool)

	scoringService := usecase.NewScoringService(findingRepo, assetRepo)
	policyService := usecase.NewPolicyService()

	// ClickHouse analytics is nil in worker (control plane handles it)
	findingUC := usecase.NewFindingService(findingRepo, nil, publisher, scoringService, policyService)

	// 6. Build scanner registry
	registry := scannerPkg.NewRegistry()

	// Register scanner modules
	registry.Register(domain.ScanTypeSecretDetection, secrets.New())
	registry.Register(domain.ScanTypeSAST, sast.New())
	registry.Register(domain.ScanTypeSCA, sca.New())
	registry.Register(domain.ScanTypeIaC, iac.New())
	registry.Register(domain.ScanTypeContainer, containerscanner.New())
	registry.Register(domain.ScanTypeCICD, cicd.New())
	registry.Register(domain.ScanTypeCloud, cspm.New())
	registry.Register(domain.ScanTypeNetwork, network.New())
	registry.Register(domain.ScanTypeDatabase, dbscanner.New())

	// DAST scanners (web vulnerability, headers, API, endpoint discovery)
	registry.Register(domain.ScanTypeDAST, web.New())
	registry.Register(domain.ScanTypeDAST, headers.New())
	registry.Register(domain.ScanTypeDAST, apiscanner.New())
	registry.Register(domain.ScanTypeEndpointDiscovery, discovery.New())
	registry.Register(domain.ScanTypeAPITest, apiscanner.New())
	registry.Register(domain.ScanTypeAPITest, headers.New())

	// "full" scan runs all repository-compatible scanners
	registry.Register(domain.ScanTypeFull, secrets.New())
	registry.Register(domain.ScanTypeFull, sast.New())
	registry.Register(domain.ScanTypeFull, sca.New())
	registry.Register(domain.ScanTypeFull, iac.New())
	registry.Register(domain.ScanTypeFull, containerscanner.New())
	registry.Register(domain.ScanTypeFull, cicd.New())
	registry.Register(domain.ScanTypeFull, compliance.New())
	registry.Register(domain.ScanTypeFull, web.New())
	registry.Register(domain.ScanTypeFull, headers.New())

	// 7. Create task handler
	taskHandler := scannerPkg.NewTaskHandler(registry, findingUC, scanRepo, publisher)

	// 8. Create asynq server
	redisOpt := asynq.RedisClientOpt{
		Addr:     cfg.Redis.Addr,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	}

	srv := asynq.NewServer(
		redisOpt,
		asynq.Config{
			Concurrency: 10,
			Queues: map[string]int{
				"critical": 6,
				"default":  3,
				"low":      1,
			},
		},
	)

	// 9. Register task handlers for each scan type
	mux := asynq.NewServeMux()
	mux.HandleFunc("scan:sast", taskHandler.HandleScanTask(domain.ScanTypeSAST))
	mux.HandleFunc("scan:sca", taskHandler.HandleScanTask(domain.ScanTypeSCA))
	mux.HandleFunc("scan:secret_detection", taskHandler.HandleScanTask(domain.ScanTypeSecretDetection))
	mux.HandleFunc("scan:iac", taskHandler.HandleScanTask(domain.ScanTypeIaC))
	mux.HandleFunc("scan:container", taskHandler.HandleScanTask(domain.ScanTypeContainer))
	mux.HandleFunc("scan:cloud", taskHandler.HandleScanTask(domain.ScanTypeCloud))
	mux.HandleFunc("scan:network", taskHandler.HandleScanTask(domain.ScanTypeNetwork))
	mux.HandleFunc("scan:cicd", taskHandler.HandleScanTask(domain.ScanTypeCICD))
	mux.HandleFunc("scan:database", taskHandler.HandleScanTask(domain.ScanTypeDatabase))
	mux.HandleFunc("scan:dast", taskHandler.HandleScanTask(domain.ScanTypeDAST))
	mux.HandleFunc("scan:endpoint_discovery", taskHandler.HandleScanTask(domain.ScanTypeEndpointDiscovery))
	mux.HandleFunc("scan:api_test", taskHandler.HandleScanTask(domain.ScanTypeAPITest))
	mux.HandleFunc("scan:full", taskHandler.HandleScanTask(domain.ScanTypeFull))

	// 10. Start worker
	go func() {
		if err := srv.Run(mux); err != nil {
			logger.Error(ctx, "Worker failed", "error", err)
			os.Exit(1)
		}
	}()

	logger.Info(ctx, "Worker started",
		"concurrency", 10,
		"scanners", []string{"secrets", "sast", "sca", "iac"},
	)

	// 11. Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info(ctx, "Received shutdown signal, stopping worker...")
	srv.Shutdown()
	logger.Info(ctx, "Worker stopped")
}
