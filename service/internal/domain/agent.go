package domain

import (
	"time"

	"github.com/google/uuid"
)

// AgentType represents the type of remote agent.
type AgentType string

const (
	AgentTypeCluster AgentType = "cluster"
	AgentTypeCICD    AgentType = "cicd"
	AgentTypeCloud   AgentType = "cloud"
	AgentTypeNetwork AgentType = "network"
)

// AgentStatus represents the current status of a remote agent.
type AgentStatus string

const (
	AgentStatusOnline  AgentStatus = "online"
	AgentStatusOffline AgentStatus = "offline"
	AgentStatusDegraded AgentStatus = "degraded"
)

// AgentRegistration represents a registered remote agent.
type AgentRegistration struct {
	ID          uuid.UUID   `json:"id"`
	TenantID    uuid.UUID   `json:"tenant_id"`
	Name        string      `json:"name"`
	Type        AgentType   `json:"agent_type"`
	Status      AgentStatus `json:"status"`
	Hostname    string      `json:"hostname"`
	Version     string      `json:"version"`
	CertSerial  string      `json:"cert_serial,omitempty"`
	LastSeenAt  time.Time   `json:"last_seen_at"`
	RegisteredAt time.Time  `json:"registered_at"`
}

// AgentHeartbeat represents a heartbeat from a remote agent.
type AgentHeartbeat struct {
	AgentID    uuid.UUID `json:"agent_id"`
	Timestamp  time.Time `json:"timestamp"`
	CPUUsage   float64   `json:"cpu_usage"`
	MemUsage   float64   `json:"mem_usage"`
	EventCount int64     `json:"event_count"`
}
