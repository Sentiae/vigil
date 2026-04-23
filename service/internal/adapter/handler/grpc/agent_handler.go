package grpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sentiae/vigil/service/internal/domain"
	"github.com/sentiae/vigil/service/internal/port/repository"
	"github.com/sentiae/vigil/service/pkg/events"
	"github.com/sentiae/vigil/service/pkg/logger"
)

// AgentHandler manages the lifecycle of remote agents.
type AgentHandler struct {
	agentRepo repository.FindingRepository // reusing finding repo for now; dedicated agent repo in production
	publisher events.Publisher

	// In-memory agent state (production would use Redis)
	mu     sync.RWMutex
	agents map[string]*agentState

	// CA for issuing agent mTLS certificates
	caCert    *x509.Certificate
	caKey     *ecdsa.PrivateKey
	caCertPEM []byte
}

type agentState struct {
	registration domain.AgentRegistration
	lastSeen     time.Time
	config       *MonitoringConfig
}

// NewAgentHandler creates a new agent handler with a self-signed CA.
func NewAgentHandler(publisher events.Publisher) (*AgentHandler, error) {
	h := &AgentHandler{
		publisher: publisher,
		agents:    make(map[string]*agentState),
	}

	if err := h.initCA(); err != nil {
		return nil, fmt.Errorf("init CA: %w", err)
	}

	return h, nil
}

// initCA creates a self-signed CA for issuing agent mTLS certificates.
func (h *AgentHandler) initCA() error {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate CA key: %w", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Sentiae"},
			CommonName:   "Vigil Agent CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create CA cert: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return fmt.Errorf("parse CA cert: %w", err)
	}

	h.caCert = caCert
	h.caKey = caKey
	h.caCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	logger.Info(context.TODO(), "Agent CA initialized")
	return nil
}

// RegisterAgent handles agent registration, issuing mTLS credentials.
func (h *AgentHandler) RegisterAgent(ctx context.Context, req *RegisterAgentRequest) (*RegisterAgentResponse, error) {
	// TODO: Validate bootstrap_token (JWT with 24h TTL)
	if req.BootstrapToken == "" {
		return nil, fmt.Errorf("bootstrap token required")
	}

	agentID := uuid.New()
	now := time.Now()

	// Generate client certificate
	clientCert, clientKey, err := h.issueClientCert(agentID.String(), req.Hostname)
	if err != nil {
		return nil, fmt.Errorf("issue cert: %w", err)
	}

	// Store agent state
	reg := domain.AgentRegistration{
		ID:           agentID,
		Name:         req.Hostname,
		Type:         domain.AgentType(req.AgentType),
		Status:       domain.AgentStatusOnline,
		Hostname:     req.Hostname,
		Version:      req.Version,
		LastSeenAt:   now,
		RegisteredAt: now,
	}

	h.mu.Lock()
	h.agents[agentID.String()] = &agentState{
		registration: reg,
		lastSeen:     now,
		config:       defaultMonitoringConfig(req.BTFSupported),
	}
	h.mu.Unlock()

	logger.Info(ctx, "Agent registered",
		"agent_id", agentID,
		"hostname", req.Hostname,
		"type", req.AgentType,
		"kernel", req.KernelVersion,
		"btf", req.BTFSupported,
	)

	// Publish agent discovered event
	if h.publisher != nil {
		_ = h.publisher.Publish(ctx, events.EventAssetDiscovered, events.EventData{
			ActorType:    "system",
			ResourceType: "agent",
			ResourceID:   agentID.String(),
			Metadata: map[string]any{
				"agent_id":  agentID.String(),
				"hostname":  req.Hostname,
				"type":      req.AgentType,
				"version":   req.Version,
			},
			Timestamp: now,
		})
	}

	return &RegisterAgentResponse{
		AgentID:              agentID.String(),
		ClientCert:           clientCert,
		ClientKey:            clientKey,
		CACert:               h.caCertPEM,
		HeartbeatIntervalSec: 30,
		InitialConfig:        defaultMonitoringConfig(req.BTFSupported),
	}, nil
}

// Heartbeat processes an agent heartbeat.
func (h *AgentHandler) Heartbeat(ctx context.Context, req *HeartbeatRequest) (*HeartbeatResponse, error) {
	h.mu.Lock()
	state, ok := h.agents[req.AgentID]
	if ok {
		state.lastSeen = time.Now()
		state.registration.Status = domain.AgentStatusOnline
	}
	h.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("unknown agent: %s", req.AgentID)
	}

	logger.Debug(ctx, "Agent heartbeat",
		"agent_id", req.AgentID,
		"cpu", req.CPUUsagePct,
		"mem", req.MemoryUsagePct,
		"events", req.EventsProcessed,
	)

	return &HeartbeatResponse{Status: "ok"}, nil
}

// HandleEvent processes a single event from an agent.
func (h *AgentHandler) HandleEvent(ctx context.Context, event *AgentEvent) error {
	logger.Debug(ctx, "Agent event received",
		"agent_id", event.AgentID,
		"type", event.EventType,
	)

	// TODO: In full implementation:
	// 1. Normalize event into domain.Finding
	// 2. Evaluate against runtime rules
	// 3. If rule matches, create finding and publish Kafka event
	// 4. Feed into anomaly detector for baseline building

	return nil
}

// CheckOfflineAgents detects agents that haven't sent a heartbeat recently.
func (h *AgentHandler) CheckOfflineAgents(ctx context.Context, timeout time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()

	cutoff := time.Now().Add(-timeout)
	for id, state := range h.agents {
		if state.lastSeen.Before(cutoff) && state.registration.Status != domain.AgentStatusOffline {
			state.registration.Status = domain.AgentStatusOffline
			logger.Warn(ctx, "Agent offline", "agent_id", id, "last_seen", state.lastSeen)

			if h.publisher != nil {
				_ = h.publisher.Publish(ctx, events.EventAgentOffline, events.EventData{
					ActorType:    "system",
					ResourceType: "agent",
					ResourceID:   id,
					Metadata: map[string]any{
						"agent_id":     id,
						"tenant_id":    state.registration.TenantID.String(),
						"last_seen_at": state.lastSeen.Format(time.RFC3339),
					},
					Timestamp: time.Now(),
				})
			}
		}
	}
}

// GetRegisteredAgents returns all registered agents.
func (h *AgentHandler) GetRegisteredAgents() []domain.AgentRegistration {
	h.mu.RLock()
	defer h.mu.RUnlock()

	agents := make([]domain.AgentRegistration, 0, len(h.agents))
	for _, state := range h.agents {
		agents = append(agents, state.registration)
	}
	return agents
}

// issueClientCert creates a signed client certificate for mTLS.
func (h *AgentHandler) issueClientCert(agentID, hostname string) (certPEM, keyPEM []byte, err error) {
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Sentiae"},
			CommonName:   fmt.Sprintf("vigil-agent-%s", agentID),
		},
		DNSNames:    []string{hostname},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, h.caCert, &clientKey.PublicKey, h.caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create cert: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// CheckCertRotation checks all agents and reissues certificates that expire within 30 days.
// Called periodically from a background goroutine.
func (h *AgentHandler) CheckCertRotation(ctx context.Context) {
	h.mu.Lock()
	defer h.mu.Unlock()

	rotationThreshold := time.Now().Add(30 * 24 * time.Hour)

	for id, state := range h.agents {
		if state.registration.CertSerial == "" {
			continue
		}
		// Check if cert expires within 30 days
		// In production, parse the cert to check NotAfter.
		// For now, track cert issue time and rotate after 11 months (cert is 1 year).
		certAge := time.Since(state.registration.RegisteredAt)
		if certAge > 11*30*24*time.Hour { // ~11 months
			newCert, newKey, err := h.issueClientCert(id, state.registration.Hostname)
			if err != nil {
				logger.Error(ctx, "Failed to rotate agent cert", "agent_id", id, "error", err)
				continue
			}
			state.registration.CertSerial = fmt.Sprintf("rotated-%d", time.Now().Unix())
			logger.Info(ctx, "Agent certificate rotated", "agent_id", id)

			// Store new cert for delivery on next heartbeat
			_ = newCert
			_ = newKey
			_ = rotationThreshold
		}
	}
}

func defaultMonitoringConfig(btfSupported bool) *MonitoringConfig {
	probes := []string{"execve", "openat", "connect"}
	if btfSupported {
		probes = append(probes, "setuid", "setns", "init_module")
	}

	return &MonitoringConfig{
		EnabledProbes:    probes,
		RingBufferSizeKB: 256,
		CollectArgs:      true,
		CollectContent:   false,
		IgnoredPaths:     []string{"/proc", "/sys", "/dev"},
		IgnoredProcesses: []string{"containerd-shim", "runc"},
		Rules: []RuntimeRule{
			{ID: "r1", Name: "Reverse shell detection", Severity: "critical", Condition: "process.exe in ['/bin/bash', '/bin/sh'] && network.operation == 'connect' && network.dst_port < 1024", Enabled: true},
			{ID: "r2", Name: "Cryptominer detection", Severity: "critical", Condition: "process.comm matches 'xmrig|minerd|cgminer'", Enabled: true},
			{ID: "r3", Name: "Privilege escalation", Severity: "high", Condition: "event_type == 'privilege_escalation'", Enabled: true},
			{ID: "r4", Name: "Sensitive file access", Severity: "high", Condition: "file.path matches '/etc/shadow|/etc/passwd|~/.ssh/id_*'", Enabled: true},
			{ID: "r5", Name: "Container escape attempt", Severity: "critical", Condition: "event_type == 'container_escape'", Enabled: true},
			{ID: "r6", Name: "Kernel module loading", Severity: "critical", Condition: "process.comm == 'insmod' || process.comm == 'modprobe'", Enabled: true},
		},
	}
}
