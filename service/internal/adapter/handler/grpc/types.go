package grpc

import (
	"time"
)

// These types mirror the protobuf definitions in proto/security/v1/agent.proto.
// They will be replaced by generated code when `buf generate` is run.
// For now they allow the handler to compile and express the full API contract.

type RegisterAgentRequest struct {
	BootstrapToken string `json:"bootstrap_token"`
	Hostname       string `json:"hostname"`
	AgentType      string `json:"agent_type"`
	Version        string `json:"version"`
	KernelVersion  string `json:"kernel_version"`
	BTFSupported   bool   `json:"btf_supported"`
}

type RegisterAgentResponse struct {
	AgentID              string           `json:"agent_id"`
	ClientCert           []byte           `json:"client_cert"`
	ClientKey            []byte           `json:"client_key"`
	CACert               []byte           `json:"ca_cert"`
	HeartbeatIntervalSec int32            `json:"heartbeat_interval_sec"`
	InitialConfig        *MonitoringConfig `json:"initial_config"`
}

type HeartbeatRequest struct {
	AgentID         string    `json:"agent_id"`
	CPUUsagePct     float64   `json:"cpu_usage_pct"`
	MemoryUsagePct  float64   `json:"memory_usage_pct"`
	EventsProcessed int64     `json:"events_processed"`
	EventsDropped   int64     `json:"events_dropped"`
	ActiveProbes    int32     `json:"active_probes"`
	Timestamp       time.Time `json:"timestamp"`
}

type HeartbeatResponse struct {
	Status string           `json:"status"` // ok, reconfigure, shutdown
	Config *MonitoringConfig `json:"config,omitempty"`
}

type AgentEvent struct {
	AgentID   string    `json:"agent_id"`
	EventType string    `json:"event_type"`
	Timestamp time.Time `json:"timestamp"`

	Process   *ProcessEvent    `json:"process,omitempty"`
	File      *FileEvent       `json:"file,omitempty"`
	Network   *NetworkEvent    `json:"network,omitempty"`
	Container *ContainerContext `json:"container,omitempty"`
}

type ProcessEvent struct {
	PID  uint32   `json:"pid"`
	PPID uint32   `json:"ppid"`
	UID  uint32   `json:"uid"`
	Comm string   `json:"comm"`
	Exe  string   `json:"exe"`
	Args []string `json:"args"`
	CWD  string   `json:"cwd"`
}

type FileEvent struct {
	PID       uint32 `json:"pid"`
	Path      string `json:"path"`
	Operation string `json:"operation"`
	Flags     uint32 `json:"flags"`
}

type NetworkEvent struct {
	PID       uint32 `json:"pid"`
	SrcAddr   string `json:"src_addr"`
	SrcPort   uint32 `json:"src_port"`
	DstAddr   string `json:"dst_addr"`
	DstPort   uint32 `json:"dst_port"`
	Protocol  string `json:"protocol"`
	Operation string `json:"operation"`
}

type ContainerContext struct {
	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name"`
	Image         string `json:"image"`
	Namespace     string `json:"namespace"`
	PodName       string `json:"pod_name"`
}

type MonitoringConfig struct {
	EnabledProbes    []string      `json:"enabled_probes"`
	Rules            []RuntimeRule `json:"rules"`
	RingBufferSizeKB int32         `json:"ring_buffer_size_kb"`
	CollectArgs      bool          `json:"collect_process_args"`
	CollectContent   bool          `json:"collect_file_content"`
	IgnoredPaths     []string      `json:"ignored_paths"`
	IgnoredProcesses []string      `json:"ignored_processes"`
}

type RuntimeRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Condition   string `json:"condition"`
	Enabled     bool   `json:"enabled"`
}
