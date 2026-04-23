# Code Analysis Agent (Vigil eBPF Agent)

This is the lightweight agent binary deployed as a Kubernetes DaemonSet on customer nodes. It captures real-time kernel telemetry via eBPF and streams events to the code-analysis-service control plane.

## Architecture

- **eBPF programs** (C, compiled via bpf2go): Hook syscalls (execve, openat, connect, setuid, setns, init_module)
- **Ring buffer reader**: Goroutine per CPU reads events from kernel ring buffer
- **Rule engine**: YAML-based rules evaluated against eBPF events
- **Anomaly detector**: gonum statistical baseline with z-score deviation alerting
- **gRPC client**: Bidirectional stream to control plane (mTLS)
- **WAL buffer**: Local write-ahead log for offline resilience

## Requirements

- Linux kernel 5.8+ with BTF/CO-RE support for full eBPF functionality
- For older kernels (5.4), falls back to Falco kernel module
- Requires `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_PTRACE` capabilities

## Key Libraries

- `github.com/cilium/ebpf` — Pure Go eBPF, no CGo
- `gonum.org/v1/gonum` — Statistics for anomaly detection
- `github.com/fsnotify/fsnotify` — File integrity monitoring
- `github.com/google/gopacket` — Network packet capture
- `google.golang.org/grpc` — gRPC for control plane communication
