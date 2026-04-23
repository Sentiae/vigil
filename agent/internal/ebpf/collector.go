package ebpf

import (
	"context"
	"time"
)

// Event represents a normalized eBPF event from kernel space.
type Event struct {
	Type      string    `json:"type"`       // process_exec, file_access, network_connect, privilege_escalation
	Timestamp time.Time `json:"timestamp"`
	PID       uint32    `json:"pid"`
	UID       uint32    `json:"uid"`
	Comm      string    `json:"comm"`

	// Process-specific
	PPID     uint32   `json:"ppid,omitempty"`
	Exe      string   `json:"exe,omitempty"`
	Args     []string `json:"args,omitempty"`
	Filename string   `json:"filename,omitempty"`

	// File-specific
	FilePath  string `json:"file_path,omitempty"`
	FileFlags uint32 `json:"file_flags,omitempty"`

	// Network-specific
	DstAddr string `json:"dst_addr,omitempty"`
	DstPort uint16 `json:"dst_port,omitempty"`
	SrcAddr string `json:"src_addr,omitempty"`
	SrcPort uint16 `json:"src_port,omitempty"`
	Proto   string `json:"proto,omitempty"`

	// Container context (enriched in userspace)
	ContainerID   string `json:"container_id,omitempty"`
	ContainerName string `json:"container_name,omitempty"`
	Image         string `json:"image,omitempty"`
	Namespace     string `json:"namespace,omitempty"`
	PodName       string `json:"pod_name,omitempty"`
}

// Collector reads events from eBPF ring buffers and normalizes them.
// On macOS/non-Linux, this is a no-op stub. The real implementation
// uses cilium/ebpf and is built with `//go:build linux` tag.
type Collector struct {
	events chan Event
	stopCh chan struct{}
}

// NewCollector creates a new eBPF event collector.
func NewCollector() *Collector {
	return &Collector{
		events: make(chan Event, 4096),
		stopCh: make(chan struct{}),
	}
}

// Start begins collecting eBPF events.
// On non-Linux platforms, this is a no-op.
func (c *Collector) Start(ctx context.Context) error {
	// The real implementation (collector_linux.go) will:
	// 1. Load compiled eBPF programs via bpf2go
	// 2. Attach to tracepoints (execve, openat, connect, setuid, setns, init_module)
	// 3. Create ring buffer readers (one goroutine per CPU)
	// 4. Read events, normalize, enrich with container context
	// 5. Send to events channel
	return nil
}

// Events returns the channel of normalized events.
func (c *Collector) Events() <-chan Event {
	return c.events
}

// Stop gracefully shuts down the collector.
func (c *Collector) Stop() {
	close(c.stopCh)
}
