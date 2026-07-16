package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/sentiae/platform-kit/authjwt"
	pkconfig "github.com/sentiae/platform-kit/config"
	"github.com/sentiae/platform-kit/grpcserver"
	pkinterceptor "github.com/sentiae/platform-kit/interceptor"
	"github.com/sentiae/platform-kit/spiffe"

	codeanalysisv1 "github.com/sentiae/vigil/service/gen/proto/code_analysis/v1"
	customHTTP "github.com/sentiae/vigil/service/internal/adapter/handler/http"
	"github.com/sentiae/vigil/service/internal/infrastructure/migrate"
	customMiddleware "github.com/sentiae/vigil/service/internal/middleware"
	"github.com/sentiae/vigil/service/pkg/config"
	"github.com/sentiae/vigil/service/pkg/database"
	"github.com/sentiae/vigil/service/pkg/logger"
)

// HealthStatus represents the health check response structure.
type HealthStatus struct {
	Status    string            `json:"status"`
	Timestamp time.Time         `json:"timestamp"`
	Services  map[string]string `json:"services"`
	Version   string            `json:"version"`
}

// Server holds all runtime dependencies for the vigil service.
type Server struct {
	db         *pgxpool.Pool
	container  *Container
	httpServer *http.Server
	grpcServer *grpcserver.Builder
	src        *workloadapi.X509Source
	grpcAddr   string
	version    string
	cancelBg   context.CancelFunc
}

// NewServer creates and wires a fully configured Server.
func NewServer(ctx context.Context, cfg *config.Config, version string) (*Server, error) {
	s := &Server{version: version}

	// 1. Connect to PostgreSQL (pgx/v5)
	pool, err := database.NewPostgresPool(ctx, cfg.Database)
	if err != nil {
		return nil, fmt.Errorf("database connection failed: %w", err)
	}
	s.db = pool
	logger.Info(ctx, "PostgreSQL connected successfully")

	// 1b. Apply embedded schema migrations before anything serves, so a fresh
	// deploy reproduces the Postgres schema with zero manual steps. Failure here
	// fails boot (main.go logs fatal).
	if err := migrate.Apply(ctx, pool); err != nil {
		return nil, fmt.Errorf("schema migration failed: %w", err)
	}

	// 2. Setup DI container
	containerCfg := ContainerConfig{
		DB:           pool,
		KafkaEnabled: len(cfg.Kafka.Brokers) > 0,
		KafkaBrokers: cfg.Kafka.Brokers,
		KafkaClientID: func() string {
			if cfg.Kafka.ClientID != "" {
				return cfg.Kafka.ClientID
			}
			return "vigil-service"
		}(),
		KafkaTopicPrefix: cfg.Kafka.TopicPrefix,
		RedisAddr:        cfg.Redis.Addr,
		RedisPassword:    cfg.Redis.Password,
		RedisDB:          cfg.Redis.DB,
		ClickHouseAddr:   cfg.ClickHouse.Addr,
		ClickHouseDB:     cfg.ClickHouse.Database,
		ClickHouseUser:   cfg.ClickHouse.User,
		ClickHousePass:   cfg.ClickHouse.Password,
		Neo4jURI:         cfg.Neo4j.URI,
		Neo4jUser:        cfg.Neo4j.User,
		Neo4jPass:        cfg.Neo4j.Password,
	}
	s.container = NewContainer(containerCfg)

	// 2b. Build the inbound user-JWT validator BEFORE the router.
	jwtValidator, err := newJWTValidator(cfg)
	if err != nil {
		return nil, err
	}

	// 3. Build HTTP router
	router := s.buildRouter(cfg, jwtValidator)

	s.httpServer = &http.Server{
		Addr:         ":" + cfg.Server.Port,
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// gRPC server for the P13 CodeAnalysisService seam, on the zero-trust mesh
	// via platform-kit's dual-mode builder (matching catalog-service). At
	// APP_GRPC_MTLS_MODE=permissive one listener serves BOTH transports through
	// cmux: bff-service reaches it over SPIFFE mTLS (the D-155 gate-policy
	// query), while delivery-service's plaintext + x-api-key client — the live
	// SEC-04 security gate — keeps working unchanged on the same port. A SPIRE
	// hiccup degrades to plaintext-only rather than wedge the service.
	// Runs alongside the Chi HTTP server, which is left fully intact.
	//
	// Caller auth (CLAUDE.md §23): the shared platform internal service-token
	// via x-api-key, constant-time compared against APP_INTERNAL_SERVICE_TOKEN
	// (empty → trust in-cluster; mirrors catalog-service). The standalone
	// UnaryAuth interceptor runs after the local recovery + logging, and the
	// builder prepends the SVID interceptors, so a peer SVID authenticates the
	// mTLS caller while x-api-key authenticates the plaintext one through this
	// same config. TokenValidator is nil (this M2M seam takes tenant_id in the
	// request, not a user JWT). AcceptAPIKey stays true and RequirePeerSVID
	// stays off: retiring the shared token is a later mesh-wide rollout step.
	var src *workloadapi.X509Source
	if pkconfig.MTLSMode() != pkconfig.MTLSModeOff {
		s, srcErr := spiffe.NewSource(ctx)
		if srcErr != nil {
			logger.Warn(ctx, "SPIFFE source unavailable, degrading to plaintext", "err", srcErr)
		} else {
			src = s
		}
	}
	s.src = src

	s.grpcServer = grpcserver.New(grpcserver.Config{
		Mode:        pkconfig.MTLSMode(),
		Source:      src,
		ServiceName: "vigil",
	},
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
		grpc.ChainUnaryInterceptor(
			recoveryUnaryInterceptor(),
			loggingUnaryInterceptor(),
			pkinterceptor.UnaryAuth(pkinterceptor.AuthConfig{
				APIKeyValidator: serviceTokenValidator{expected: cfg.Internal.ServiceToken},
				AcceptAPIKey:    true,
			}),
		),
	)
	// Registrar fans out to every underlying transport; the builder's Serve
	// registers reflection (grpcurl/ops) + health on each, so neither is
	// registered here.
	codeanalysisv1.RegisterCodeAnalysisServiceServer(s.grpcServer.Registrar(), s.container.CodeAnalysisHandler())
	s.grpcAddr = fmt.Sprintf(":%d", cfg.Server.GRPCPort)

	// 4. Start background services
	bgCtx, bgCancel := context.WithCancel(context.Background())
	s.cancelBg = bgCancel

	// SLA enforcement loop (checks every 5 minutes)
	go s.container.SLAService().Start(bgCtx, 5*time.Minute)

	// Kafka event consumer (auto-triggers scans from git/ops/canvas events)
	if consumer := s.container.EventConsumer(); consumer != nil {
		consumer.Start(bgCtx)
	}

	// Outbox relay (guaranteed event delivery)
	if relay := s.container.OutboxRelay(); relay != nil {
		go relay.Start(bgCtx)
	}

	// Agent offline detection loop (checks every 90 seconds)
	if agentH := s.container.AgentHandler(); agentH != nil {
		go func() {
			ticker := time.NewTicker(90 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					agentH.CheckOfflineAgents(bgCtx, 90*time.Second)
				case <-bgCtx.Done():
					return
				}
			}
		}()
	}

	// EPSS + CISA KEV sync on startup (with retry), then daily
	go func() {
		scoring := s.container.ScoringService()

		// Retry sync on startup with backoff (3 attempts)
		for attempt := 1; attempt <= 3; attempt++ {
			if err := scoring.SyncEPSS(bgCtx); err != nil {
				logger.Warn(bgCtx, "EPSS sync failed, retrying", "attempt", attempt, "error", err)
				select {
				case <-time.After(time.Duration(attempt*10) * time.Second):
				case <-bgCtx.Done():
					return
				}
				continue
			}
			break
		}
		for attempt := 1; attempt <= 3; attempt++ {
			if err := scoring.SyncCISAKEV(bgCtx); err != nil {
				logger.Warn(bgCtx, "CISA KEV sync failed, retrying", "attempt", attempt, "error", err)
				select {
				case <-time.After(time.Duration(attempt*10) * time.Second):
				case <-bgCtx.Done():
					return
				}
				continue
			}
			break
		}

		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := scoring.SyncEPSS(bgCtx); err != nil {
					logger.Error(bgCtx, "Daily EPSS sync failed", "error", err)
				}
				if err := scoring.SyncCISAKEV(bgCtx); err != nil {
					logger.Error(bgCtx, "Daily CISA KEV sync failed", "error", err)
				}
			case <-bgCtx.Done():
				return
			}
		}
	}()

	return s, nil
}

// Start launches the HTTP + gRPC servers in background goroutines.
func (s *Server) Start(ctx context.Context, serverErr chan<- error) {
	go func() {
		logger.Info(ctx, "HTTP server starting", "addr", s.httpServer.Addr)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- fmt.Errorf("HTTP server failed: %w", err)
		}
	}()

	go func() {
		logger.Info(ctx, "gRPC server starting", "addr", s.grpcAddr)
		lis, err := net.Listen("tcp", s.grpcAddr)
		if err != nil {
			serverErr <- fmt.Errorf("gRPC listen failed: %w", err)
			return
		}
		if err := s.grpcServer.Serve(lis); err != nil {
			serverErr <- fmt.Errorf("gRPC server failed: %w", err)
		}
	}()
}

// recoveryUnaryInterceptor converts a panicking handler into codes.Internal.
func recoveryUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		defer func() {
			if r := recover(); r != nil {
				logger.Error(ctx, "gRPC handler panic", "method", info.FullMethod, "recover", r)
				err = status.Error(codes.Internal, "internal error")
			}
		}()
		return handler(ctx, req)
	}
}

// loggingUnaryInterceptor logs each RPC's method, duration, and status code.
func loggingUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		logger.Info(ctx, "gRPC request",
			"method", info.FullMethod,
			"duration_ms", time.Since(start).Milliseconds(),
			"code", status.Code(err).String(),
		)
		return resp, err
	}
}

// Shutdown gracefully stops all servers with a 30-second timeout.
func (s *Server) Shutdown(ctx context.Context) {
	logger.Info(ctx, "Shutting down servers...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error(ctx, "HTTP server forced to shutdown", "error", err)
	}
	if s.grpcServer != nil {
		logger.Info(ctx, "Stopping gRPC server")
		s.grpcServer.GracefulStop()
	}
	if s.src != nil {
		_ = s.src.Close()
	}
	logger.Info(ctx, "Server exited")
}

// Close releases resources held by the server.
func (s *Server) Close() {
	if s.cancelBg != nil {
		s.cancelBg()
	}
	if s.db != nil {
		s.db.Close()
	}
	if s.container != nil {
		s.container.Close()
	}
}

// newJWTValidator builds the validator the HTTP surface authenticates with.
//
// vigil's HTTP routes scope every read/write by the context tenant, so a
// missing validator used to mean "trust X-Tenant-ID / ?organization_id=" — the
// caller picked its own tenant over per-tenant findings and the D-155 deploy
// gate. There is no degraded mode any more: an empty JWKS URL or a validator
// that won't build fails boot (D-073's fail-boot posture; foundry's rule that a
// broken validator must never fall open). A misconfigured deployment refuses to
// start rather than serve spoofable identity. There is deliberately no dev
// escape hatch — security.jwks_url defaults to the in-cluster identity endpoint,
// so dev is configured by default and tests inject their own validator.
func newJWTValidator(cfg *config.Config) (*authjwt.Validator, error) {
	if cfg.Security.JWKSURL == "" {
		return nil, fmt.Errorf("security.jwks_url is empty: refusing to boot without user-JWT validation (set APP_AUTH_JWKS_URL)")
	}
	v, err := authjwt.New(authjwt.Config{
		JWKSURL: cfg.Security.JWKSURL,
		Issuer:  cfg.Security.JWTIssuer,
	})
	if err != nil {
		return nil, fmt.Errorf("build JWKS validator: %w", err)
	}
	return v, nil
}

// buildRouter creates and configures the Chi HTTP router with all routes.
func (s *Server) buildRouter(cfg *config.Config, jwtValidator *authjwt.Validator) *chi.Mux {
	authMiddleware := customMiddleware.NewAuthMiddleware(jwtValidator)
	router := chi.NewRouter()

	// Global middleware
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	router.Use(otelhttp.NewMiddleware(cfg.Telemetry.ServiceName))

	// CORS
	router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000", "http://localhost:3001", "http://localhost:5173", "https://*.sentiae.com"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-Request-ID"},
		ExposedHeaders:   []string{"Link", "X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Metrics
	router.Method("GET", "/metrics", promhttp.Handler())

	// Health checks
	router.Get("/health", s.healthCheckHandler)
	router.Get("/health/ready", s.readinessHandler)
	router.Get("/health/live", livenessHandler)

	// REST API routes
	findingHandler := s.container.FindingHandler()
	scanHandler := s.container.ScanHandler()
	complianceHandler := s.container.ComplianceHandler()
	assetHandler := s.container.AssetHandler()
	attackChainHandler := s.container.AttackChainHandler()

	router.Route("/api/v1/security", func(r chi.Router) {
		r.Use(authMiddleware)

		// Findings
		r.Route("/findings", func(r chi.Router) {
			r.Get("/", findingHandler.ListFindings)
			r.Get("/{id}", findingHandler.GetFinding)
			r.Post("/{id}/resolve", findingHandler.ResolveFinding)
		})

		// Scans
		r.Route("/scans", func(r chi.Router) {
			r.Get("/", scanHandler.ListScans)
			r.Get("/{id}", scanHandler.GetScan)
			r.Post("/", scanHandler.TriggerScan)
		})

		// Compliance
		r.Get("/compliance/summary", complianceHandler.GetComplianceSummary)

		// Attack chains
		r.Get("/attack-chains", attackChainHandler.GetAttackChains)

		// Assets
		r.Route("/assets", func(r chi.Router) {
			r.Get("/{id}/posture", complianceHandler.GetAssetPosture)
			r.Get("/{id}/blast-radius", assetHandler.GetBlastRadius)
			r.Get("/{id}/attack-paths", assetHandler.GetAttackPaths)
		})

		// Phase 7 — risk zones.
		// POST because callers supply the raw signal maps. The service
		// does the blending; it doesn't reach across to git/ops itself.
		riskZoneHandler := customHTTP.NewRiskZoneHandler()
		r.Post("/risk-zones", riskZoneHandler.HandleCompute)

		// Phase 8 — test-coverage reporting. Singleton service so
		// uploads persist across requests within the process.
		coverageHandler := customHTTP.NewCoverageHandler(s.container.CoverageService())
		r.Post("/coverage-reports", coverageHandler.HandleIngest)
		r.Get("/coverage", coverageHandler.HandleGetLatest)
		r.Get("/coverage/by-file", coverageHandler.HandleByFile)

		// Phase 8 — SARIF report ingest (CI uploads scanner output).
		// Implicit Scan records link findings back to a CI run.
		sarifHandler := customHTTP.NewSARIFHandler(s.container.FindingRepo(), s.container.ScanRepo())
		r.Post("/sarif-reports", sarifHandler.HandleIngest)
	})

	// §11.2 — Code intelligence (embeddings search + entry points).
	if ci := s.container.CodeIntelligenceHandler(); ci != nil {
		router.Route("/api/v1/code", func(r chi.Router) {
			r.Use(authMiddleware)
			r.Get("/embeddings/search", ci.HandleEmbeddingSearch)
			r.Get("/entry-points", ci.HandleListEntryPoints)
			r.Post("/entry-points/detect", ci.HandleDetectEntryPoints)
			r.Post("/scip/index", ci.HandleSCIPIndex)
			r.Post("/embeddings/reindex", ci.HandleEmbeddingReindex)
		})
	}

	// B10 §11.2 — framework detection.
	// Exposed under /analyze/... (outside /api/v1/security) so agents
	// and workers can hit it without the tenant JWT context. Callers
	// either pass a project path in the body or wire a resolver via
	// NewFrameworkHandler. The default resolver is nil → body-driven.
	frameworkHandler := customHTTP.NewFrameworkHandler(nil)
	router.Route("/analyze", func(r chi.Router) {
		r.Post("/frameworks", frameworkHandler.HandleAnalyze)
		r.Get("/{projectID}/frameworks", frameworkHandler.HandleAnalyze)
	})

	return router
}


func (s *Server) healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	status := HealthStatus{
		Status:    "healthy",
		Timestamp: time.Now(),
		Services:  make(map[string]string),
		Version:   s.version,
	}

	if s.db != nil {
		if err := s.db.Ping(r.Context()); err != nil {
			status.Services["database"] = "unhealthy"
			status.Status = "degraded"
		} else {
			status.Services["database"] = "healthy"
		}
	} else {
		status.Services["database"] = "not configured"
		status.Status = "degraded"
	}

	w.Header().Set("Content-Type", "application/json")
	if status.Status == "healthy" {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(status)
}

func (s *Server) readinessHandler(w http.ResponseWriter, r *http.Request) {
	if s.db != nil {
		if err := s.db.Ping(r.Context()); err == nil {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ready"))
			return
		}
	}
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte("not ready"))
}

func livenessHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("alive"))
}
