package runtime

import (
	"sync"
	"time"

	"github.com/sentiae/vigil/agent/internal/ebpf"
)

// ProcessTree tracks the process hierarchy for a host or container.
// Used to detect anomalous process chains (e.g., web server spawning a shell).
type ProcessTree struct {
	mu        sync.RWMutex
	processes map[uint32]*ProcessNode // pid -> node
}

// ProcessNode represents a single process in the tree.
type ProcessNode struct {
	PID       uint32
	PPID      uint32
	UID       uint32
	Comm      string
	Exe       string
	Args      []string
	StartTime time.Time
	Container string // container ID
	Children  []*ProcessNode
}

func NewProcessTree() *ProcessTree {
	return &ProcessTree{
		processes: make(map[uint32]*ProcessNode),
	}
}

// RecordExec adds or updates a process from an execve event.
func (t *ProcessTree) RecordExec(event ebpf.Event) {
	t.mu.Lock()
	defer t.mu.Unlock()

	node := &ProcessNode{
		PID:       event.PID,
		PPID:      event.PPID,
		UID:       event.UID,
		Comm:      event.Comm,
		Exe:       event.Exe,
		Args:      event.Args,
		StartTime: event.Timestamp,
		Container: event.ContainerID,
	}

	t.processes[event.PID] = node

	// Link to parent
	if parent, ok := t.processes[event.PPID]; ok {
		parent.Children = append(parent.Children, node)
	}
}

// RecordExit removes a process from the tree.
func (t *ProcessTree) RecordExit(pid uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.processes, pid)
}

// GetAncestorChain returns the process chain from pid up to the root (or max depth).
func (t *ProcessTree) GetAncestorChain(pid uint32, maxDepth int) []*ProcessNode {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var chain []*ProcessNode
	current, ok := t.processes[pid]
	depth := 0

	for ok && depth < maxDepth {
		chain = append(chain, current)
		if current.PPID == 0 || current.PPID == current.PID {
			break
		}
		current, ok = t.processes[current.PPID]
		depth++
	}

	return chain
}

// IsSuspiciousChain checks if a process chain matches known attack patterns.
func (t *ProcessTree) IsSuspiciousChain(pid uint32) (bool, string) {
	chain := t.GetAncestorChain(pid, 10)
	if len(chain) < 2 {
		return false, ""
	}

	current := chain[0]
	parent := chain[1]

	// Web server spawning a shell
	webServers := map[string]bool{
		"nginx": true, "apache2": true, "httpd": true, "node": true,
		"java": true, "python": true, "python3": true, "ruby": true, "php": true,
	}
	shells := map[string]bool{
		"bash": true, "sh": true, "zsh": true, "dash": true, "csh": true, "ksh": true,
	}
	if webServers[parent.Comm] && shells[current.Comm] {
		return true, "web server spawned shell: " + parent.Comm + " -> " + current.Comm
	}

	// Database process spawning anything unexpected
	databases := map[string]bool{
		"postgres": true, "mysqld": true, "mongod": true, "redis-server": true,
	}
	if databases[parent.Comm] && !databases[current.Comm] {
		return true, "database spawned unexpected process: " + parent.Comm + " -> " + current.Comm
	}

	// Container init (PID 1) spawning recon tools
	reconTools := map[string]bool{
		"nmap": true, "masscan": true, "curl": true, "wget": true,
		"nc": true, "ncat": true, "netcat": true, "socat": true,
	}
	if parent.PID == 1 && reconTools[current.Comm] {
		return true, "container init spawned recon tool: " + current.Comm
	}

	return false, ""
}

// Size returns the number of tracked processes.
func (t *ProcessTree) Size() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.processes)
}
