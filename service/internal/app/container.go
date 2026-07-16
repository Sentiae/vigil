package app

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5/pgxpool"

	eventhandler "github.com/sentiae/vigil/service/internal/adapter/handler/event"
	grpchandler "github.com/sentiae/vigil/service/internal/adapter/handler/grpc"
	httphandler "github.com/sentiae/vigil/service/internal/adapter/handler/http"
	"github.com/sentiae/vigil/service/internal/infrastructure/scip"
	chrepo "github.com/sentiae/vigil/service/internal/adapter/repository/clickhouse"
	neo4jrepo "github.com/sentiae/vigil/service/internal/adapter/repository/neo4j"
	"github.com/sentiae/vigil/service/internal/adapter/repository/postgres"
	"github.com/sentiae/vigil/service/internal/port/repository"
	portuc "github.com/sentiae/vigil/service/internal/port/usecase"
	"github.com/sentiae/vigil/service/internal/usecase"
	neo4jdriver "github.com/neo4j/neo4j-go-driver/v5/neo4j"

	kafka "github.com/sentiae/platform-kit/kafka"

	"github.com/sentiae/vigil/service/pkg/config"
	"github.com/sentiae/vigil/service/pkg/database"
	"github.com/sentiae/vigil/service/pkg/events"
	"github.com/sentiae/vigil/service/pkg/logger"
)

// ContainerConfig holds all configuration needed by the DI container.
type ContainerConfig struct {
	DB *pgxpool.Pool

	// Kafka
	KafkaEnabled     bool
	KafkaBrokers     []string
	KafkaClientID    string
	KafkaTopicPrefix string

	// Redis
	RedisAddr     string
	RedisPassword string
	RedisDB       int

	// ClickHouse
	ClickHouseAddr string
	ClickHouseDB   string
	ClickHouseUser string
	ClickHousePass string

	// Neo4j
	Neo4jURI  string
	Neo4jUser string
	Neo4jPass string
}

// Container is the central DI registry for the vigil service.
type Container struct {
	cfg ContainerConfig

	// Repositories
	findingRepo    repository.FindingRepository
	scanRepo       repository.ScanRepository
	assetRepo      repository.AssetRepository
	outboxRepo     repository.OutboxRepository
	analyticsRepo  repository.AnalyticsRepository
	graphRepo      repository.GraphRepository
	gatePolicyRepo repository.GatePolicyRepository

	// Use cases
	findingUC    portuc.FindingUseCase
	scanUC       portuc.ScanUseCase
	complianceUC portuc.ComplianceUseCase
	gateUC       portuc.GatePolicyUseCase

	// Services
	scoringService *usecase.ScoringService
	policyService  *usecase.PolicyService
	slaService       *usecase.SLAService
	outboxRelay      *usecase.OutboxRelay
	attackChainSvc   *usecase.AttackChainService
	coverageService  *usecase.CoverageService

	// Handlers
	findingHandler          *httphandler.FindingHandler
	scanHandler             *httphandler.ScanHandler
	complianceHandler       *httphandler.ComplianceHandler
	assetHandler            *httphandler.AssetHandler
	attackChainHandler      *httphandler.AttackChainHandler
	codeIntelligenceHandler *httphandler.CodeIntelligenceHandler
	eventConsumer           *eventhandler.Consumer
	agentHandler            *grpchandler.AgentHandler
	codeAnalysisHandler     *grpchandler.CodeAnalysisHandler

	// §11.2 code intelligence
	embeddingIndexer *usecase.EmbeddingIndexer
	entryPointDetector *usecase.EntryPointDetector
	entryPointRepo *postgres.EntryPointRepository
	semanticAnalyzer *usecase.SemanticAnalyzer
	scipIndexRepo *postgres.SCIPIndexRepository
	graphRefresher *usecase.GraphRefresher

	// Infrastructure
	eventPublisher events.Publisher
	asynqClient    *asynq.Client
	clickhouseDB   *sql.DB
	neo4jDriver    neo4jdriver.DriverWithContext
}

// NewContainer creates a fully wired DI container.
func NewContainer(cfg ContainerConfig) *Container {
	c := &Container{cfg: cfg}

	c.setupInfrastructure()
	c.setupRepositories()
	c.setupServices()
	c.setupUseCases()
	c.setupHandlers()

	return c
}

func (c *Container) setupInfrastructure() {
	// Kafka publisher
	if c.cfg.KafkaEnabled && len(c.cfg.KafkaBrokers) > 0 {
		pub, err := kafka.NewPublisher(kafka.PublisherConfig{
			Brokers:      c.cfg.KafkaBrokers,
			TopicPrefix:  c.cfg.KafkaTopicPrefix,
			Source:       "vigil-service",
			RequiredAcks: -1,
		})
		if err != nil {
			logger.Warn(context.TODO(), "Failed to create Kafka publisher", "error", err)
		} else {
			c.eventPublisher = pub
			logger.Info(context.TODO(), "Kafka publisher initialized")
			ensureCtx, ensureCancel := context.WithTimeout(context.Background(), 15*time.Second)
			if err := pub.EnsureTopics(ensureCtx); err != nil {
				logger.Warn(ensureCtx, "Kafka EnsureTopics failed", "error", err)
			}
			ensureCancel()
		}
	}

	// ClickHouse analytics
	if c.cfg.ClickHouseAddr != "" {
		chDB, err := database.NewClickHouseDB(context.TODO(), config.ClickHouseConfig{
			Addr:     c.cfg.ClickHouseAddr,
			Database: c.cfg.ClickHouseDB,
			User:     c.cfg.ClickHouseUser,
			Password: c.cfg.ClickHousePass,
		})
		if err != nil {
			logger.Warn(context.TODO(), "ClickHouse not available (analytics disabled)", "error", err)
		} else {
			c.clickhouseDB = chDB
			logger.Info(context.TODO(), "ClickHouse connected")
		}
	}

	// Neo4j graph database
	if c.cfg.Neo4jURI != "" {
		driver, err := database.NewNeo4jDriver(context.TODO(), config.Neo4jConfig{
			URI:      c.cfg.Neo4jURI,
			User:     c.cfg.Neo4jUser,
			Password: c.cfg.Neo4jPass,
		})
		if err != nil {
			logger.Warn(context.TODO(), "Neo4j not available (graph features disabled)", "error", err)
		} else {
			c.neo4jDriver = driver
			logger.Info(context.TODO(), "Neo4j connected")
		}
	}

	// Asynq client for task queue
	if c.cfg.RedisAddr != "" {
		c.asynqClient = asynq.NewClient(asynq.RedisClientOpt{
			Addr:     c.cfg.RedisAddr,
			Password: c.cfg.RedisPassword,
			DB:       c.cfg.RedisDB,
		})
		logger.Info(context.TODO(), "Asynq client initialized")
	}
}

func (c *Container) setupRepositories() {
	c.findingRepo = postgres.NewFindingRepository(c.cfg.DB)
	c.scanRepo = postgres.NewScanRepository(c.cfg.DB)
	c.assetRepo = postgres.NewAssetRepository(c.cfg.DB)
	c.outboxRepo = postgres.NewOutboxRepository(c.cfg.DB)
	c.gatePolicyRepo = postgres.NewGatePolicyRepository(c.cfg.DB)
	if c.clickhouseDB != nil {
		c.analyticsRepo = chrepo.NewAnalyticsRepository(c.clickhouseDB)
	}
	if c.neo4jDriver != nil {
		c.graphRepo = neo4jrepo.NewAssetGraphRepository(c.neo4jDriver)
	}
	logger.Info(context.TODO(), "Repositories initialized")
}

func (c *Container) setupServices() {
	c.scoringService = usecase.NewScoringService(c.findingRepo, c.assetRepo)
	c.policyService = usecase.NewPolicyService()
	c.slaService = usecase.NewSLAService(c.findingRepo, c.eventPublisher)
	// Phase 8: prefer Postgres-backed coverage storage. Falls back to
	// the in-memory service if the DB pool isn't available (tests).
	if c.cfg.DB != nil {
		c.coverageService = usecase.NewCoverageServiceWithRepo(postgres.NewCoverageRepository(c.cfg.DB))
	} else {
		c.coverageService = usecase.NewCoverageService()
	}
	if c.eventPublisher != nil {
		c.outboxRelay = usecase.NewOutboxRelay(c.outboxRepo, c.eventPublisher, 10*time.Second)
	}
	c.attackChainSvc = usecase.NewAttackChainService(c.findingRepo, c.eventPublisher)
	logger.Info(context.TODO(), "Services initialized (scoring, policy, SLA, outbox, attack chains)")
}

func (c *Container) setupUseCases() {
	c.findingUC = usecase.NewFindingService(c.findingRepo, c.analyticsRepo, c.eventPublisher, c.scoringService, c.policyService)
	c.scanUC = usecase.NewScanService(c.scanRepo, c.eventPublisher, c.asynqClient)
	c.complianceUC = usecase.NewComplianceService(c.findingRepo, c.assetRepo, c.policyService)
	c.gateUC = usecase.NewGatePolicyService(c.gatePolicyRepo)
	logger.Info(context.TODO(), "Use cases initialized")
}

func (c *Container) setupHandlers() {
	c.findingHandler = httphandler.NewFindingHandler(c.findingUC)
	c.scanHandler = httphandler.NewScanHandler(c.scanUC)
	c.complianceHandler = httphandler.NewComplianceHandler(c.complianceUC)
	c.assetHandler = httphandler.NewAssetHandler(c.graphRepo)
	c.attackChainHandler = httphandler.NewAttackChainHandler(c.attackChainSvc)

	// P13 CodeAnalysisService gRPC seam — thin adapter over the same scan +
	// finding use cases the Chi HTTP handlers use, re-expressed over gRPC for
	// inter-service callers (ops/git/foundry/delivery).
	c.codeAnalysisHandler = grpchandler.NewCodeAnalysisHandler(c.scanUC, c.findingUC, c.gateUC)

	// §11.2 — code intelligence.
	// The DI wiring here is best-effort: when dependencies are
	// missing (e.g. no DB in tests) the handler surfaces a 501 for
	// the corresponding route instead of crashing at startup.
	if c.cfg.DB != nil {
		c.entryPointRepo = postgres.NewEntryPointRepository(c.cfg.DB)
		c.scipIndexRepo = postgres.NewSCIPIndexRepository(c.cfg.DB)

		// The embedding + semantics wiring depends on foundry-service;
		// without it the whole feature degrades to disabled but the
		// rest of the service keeps running.
		foundryURL := os.Getenv("FOUNDRY_SERVICE_URL")
		if foundryURL != "" {
			fc := newFoundryClient(foundryURL)
			c.embeddingIndexer = usecase.NewEmbeddingIndexer(
				&noopSymbolLister{}, // real lister is wired by the worker
				fc,
				postgres.NewEmbeddingRepository(c.cfg.DB),
			)
			c.semanticAnalyzer = usecase.NewSemanticAnalyzer(fc, postgres.NewSemanticsRepository(c.cfg.DB))
		}
	}
	c.entryPointDetector = usecase.NewEntryPointDetector(c.entryPointRepo)
	c.codeIntelligenceHandler = httphandler.NewCodeIntelligenceHandler(c.embeddingIndexer, c.entryPointDetector, c.entryPointRepo)
	// SCIP indexer shells out to the per-language CLIs. The production
	// container images (Dockerfile + Dockerfile.worker) bundle every
	// scip-* binary so Index is guaranteed to find its CLI on PATH; a
	// missing binary therefore surfaces as a 500 on /scip/index, not
	// a silent 501.
	c.codeIntelligenceHandler = c.codeIntelligenceHandler.WithSCIP(scip.NewCLIIndexer(), c.scipIndexRepo)

	// §11.3 — graph refresh on push.
	gitURL := os.Getenv("GIT_SERVICE_URL")
	gitClient := usecase.NewHTTPGitClient(gitURL)
	var graphPub usecase.GraphUpdatedPublisher
	if c.eventPublisher != nil {
		graphPub = usecase.NewKafkaGraphPublisher(c.eventPublisher)
	}
	c.graphRefresher = usecase.NewGraphRefresher(gitClient, gitClient, graphPub)

	// Event consumer (Kafka)
	if c.cfg.KafkaEnabled && len(c.cfg.KafkaBrokers) > 0 {
		c.eventConsumer = eventhandler.NewConsumer(c.scanUC, c.cfg.KafkaBrokers, "vigil-service-group").
			WithGraphRefresher(c.graphRefresher)
	}

	// Agent handler (gRPC)
	agentH, err := grpchandler.NewAgentHandler(c.eventPublisher)
	if err != nil {
		logger.Warn(context.TODO(), "Failed to create agent handler", "error", err)
	} else {
		c.agentHandler = agentH
	}

	logger.Info(context.TODO(), "Handlers initialized")
}

// noopSymbolLister is the DI-time placeholder for the symbol-source
// lister. The cmd/worker binary overrides this by re-wiring the
// indexer with a git-service-backed lister once it has repo access.
type noopSymbolLister struct{}

func (n *noopSymbolLister) ListSymbols(_ context.Context, _ uuid.UUID, _ string) ([]usecase.SymbolSource, error) {
	return nil, nil
}

// foundryClient is an in-container adapter that satisfies both
// usecase.Embedder and usecase.Completer. Kept tiny and dependency-
// free so the container doesn't reach across service boundaries for
// types. The real production client lives in foundry-service; this
// wrapper just speaks its HTTP contract.
type foundryClient struct {
	baseURL string
	http    *http.Client
}

func newFoundryClient(baseURL string) *foundryClient {
	return &foundryClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *foundryClient) Embed(ctx context.Context, texts []string) ([][]float32, error) {
	if len(texts) == 0 {
		return nil, nil
	}
	body, _ := json.Marshal(map[string]any{"texts": texts})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/foundry/embed", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("foundry embed %d: %s", resp.StatusCode, string(b))
	}
	var out struct {
		Embeddings [][]float32 `json:"embeddings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Embeddings, nil
}

func (c *foundryClient) Complete(ctx context.Context, system, prompt string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"system":      system,
		"prompt":      prompt,
		"json_mode":   true,
		"temperature": 0.0,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/foundry/complete", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("foundry complete %d: %s", resp.StatusCode, string(b))
	}
	var out struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.Text, nil
}

// Getters
func (c *Container) FindingHandler() *httphandler.FindingHandler       { return c.findingHandler }
func (c *Container) CodeIntelligenceHandler() *httphandler.CodeIntelligenceHandler {
	return c.codeIntelligenceHandler
}
func (c *Container) EmbeddingIndexer() *usecase.EmbeddingIndexer { return c.embeddingIndexer }
func (c *Container) EntryPointRepo() *postgres.EntryPointRepository { return c.entryPointRepo }
func (c *Container) SCIPIndexRepo() *postgres.SCIPIndexRepository { return c.scipIndexRepo }
func (c *Container) SemanticAnalyzer() *usecase.SemanticAnalyzer { return c.semanticAnalyzer }
func (c *Container) GraphRefresher() *usecase.GraphRefresher { return c.graphRefresher }
func (c *Container) ScanHandler() *httphandler.ScanHandler             { return c.scanHandler }
func (c *Container) ComplianceHandler() *httphandler.ComplianceHandler { return c.complianceHandler }
func (c *Container) ScoringService() *usecase.ScoringService           { return c.scoringService }
func (c *Container) SLAService() *usecase.SLAService                   { return c.slaService }
func (c *Container) GraphRepo() repository.GraphRepository              { return c.graphRepo }
func (c *Container) AssetHandler() *httphandler.AssetHandler             { return c.assetHandler }
func (c *Container) AgentHandler() *grpchandler.AgentHandler             { return c.agentHandler }
func (c *Container) CodeAnalysisHandler() *grpchandler.CodeAnalysisHandler {
	return c.codeAnalysisHandler
}
func (c *Container) EventConsumer() *eventhandler.Consumer               { return c.eventConsumer }
func (c *Container) AttackChainHandler() *httphandler.AttackChainHandler { return c.attackChainHandler }
func (c *Container) OutboxRelay() *usecase.OutboxRelay                   { return c.outboxRelay }
func (c *Container) CoverageService() *usecase.CoverageService           { return c.coverageService }
func (c *Container) FindingRepo() repository.FindingRepository           { return c.findingRepo }
func (c *Container) ScanRepo() repository.ScanRepository                  { return c.scanRepo }

// Close releases resources held by the container.
func (c *Container) Close() {
	if c.slaService != nil {
		c.slaService.Stop()
	}
	if c.eventConsumer != nil {
		c.eventConsumer.Stop()
	}
	if c.neo4jDriver != nil {
		_ = c.neo4jDriver.Close(context.TODO())
	}
	if c.clickhouseDB != nil {
		_ = c.clickhouseDB.Close()
	}
	if c.eventPublisher != nil {
		_ = c.eventPublisher.Close()
	}
	if c.asynqClient != nil {
		_ = c.asynqClient.Close()
	}
	logger.Info(context.TODO(), "Container resources released")
}
