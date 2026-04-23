package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/sentiae/vigil/agent/internal/ebpf"
	"github.com/sentiae/vigil/agent/internal/monitor"
	runtimepkg "github.com/sentiae/vigil/agent/internal/runtime"
	"github.com/sentiae/vigil/agent/internal/transport"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	slog.InfoContext(ctx, "Starting vigil-agent",
		"version", Version,
		"build_time", BuildTime,
		"os", runtime.GOOS,
		"arch", runtime.GOARCH,
	)

	// Configuration from environment
	controlPlaneURL := envOrDefault("VIGIL_CONTROL_PLANE_URL", "http://localhost:8091")
	bootstrapToken := envOrDefault("VIGIL_BOOTSTRAP_TOKEN", "dev-token")
	walDir := envOrDefault("VIGIL_WAL_DIR", "/var/lib/vigil/wal")
	auditAddr := envOrDefault("VIGIL_AUDIT_LISTEN_ADDR", ":9443")
	anomalyThreshold := 2.0 // z-score threshold

	// 1. Initialize WAL for offline resilience
	wal, err := transport.NewWAL(walDir)
	if err != nil {
		slog.Error("Failed to initialize WAL", "error", err)
		os.Exit(1)
	}
	defer wal.Close()

	// 2. Connect to control plane
	client := transport.NewControlPlaneClient(controlPlaneURL)

	hostname, _ := os.Hostname()
	agentID, err := client.Register(ctx, bootstrapToken, hostname, "cluster", Version, getKernelVersion(), hasBTFSupport())
	if err != nil {
		slog.Warn("Failed to register with control plane (will retry)", "error", err)
	} else {
		slog.Info("Registered with control plane", "agent_id", agentID)
	}

	// 3. Initialize eBPF collector
	collector := ebpf.NewCollector()
	if err := collector.Start(ctx); err != nil {
		slog.Error("Failed to start eBPF collector", "error", err)
		// Non-fatal on non-Linux — agent can still serve as a scan worker
	}
	defer collector.Stop()

	// 4. Initialize rule engine with default rules
	rules := []runtimepkg.Rule{
		{ID: "r1", Name: "Reverse shell detection", Severity: "critical", Condition: "process.exe in ['/bin/bash', '/bin/sh'] && network.operation == 'connect'", Enabled: true},
		{ID: "r2", Name: "Cryptominer detection", Severity: "critical", Condition: "matches 'xmrig|minerd|cgminer'", Enabled: true},
		{ID: "r3", Name: "Privilege escalation", Severity: "high", Condition: "privilege_escalation", Enabled: true},
		{ID: "r4", Name: "Sensitive file access", Severity: "high", Condition: "/etc/shadow", Enabled: true},
		{ID: "r5", Name: "Container escape attempt", Severity: "critical", Condition: "container_escape", Enabled: true},
		{ID: "r6", Name: "Kernel module loading", Severity: "critical", Condition: "insmod", Enabled: true},
	}
	ruleEngine := runtimepkg.NewRuleEngine(rules)

	// 4b. Initialize behavioral anomaly detector
	anomalyDetector := runtimepkg.NewAnomalyDetector(anomalyThreshold, 14*24*time.Hour) // 2 week training

	// 4c. Initialize process tree tracker
	processTree := runtimepkg.NewProcessTree()

	// 4d. Initialize DNS monitor
	dnsMonitor := monitor.NewDNSMonitor()

	// 4e. Initialize TLS monitor
	tlsMonitor := monitor.NewTLSMonitor()

	// 4f. Initialize Kubernetes audit log monitor
	auditMonitor := monitor.NewK8sAuditMonitor(auditAddr)
	go func() {
		if err := auditMonitor.Start(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("K8s audit monitor failed to start", "error", err)
		}
	}()

	// 5. Event processing pipeline
	go func() {
		var eventBatch []ebpf.Event
		batchTicker := time.NewTicker(5 * time.Second)
		defer batchTicker.Stop()

		for {
			select {
			case event := <-collector.Events():
				// Evaluate against rules
				ruleEngine.Evaluate(ctx, event)

				// Feed into anomaly detector
				anomalyDetector.ProcessEvent(ctx, event)

				// Track process tree
				if event.Type == "process_exec" {
					processTree.RecordExec(event)
					if suspicious, reason := processTree.IsSuspiciousChain(event.PID); suspicious {
						slog.Warn("Suspicious process chain", "reason", reason, "pid", event.PID, "comm", event.Comm)
					}
				}

				// Analyze DNS queries from network events
				if event.Type == "network_connect" && event.DstPort == 53 {
					dnsMonitor.AnalyzeQuery(event.SrcAddr, event.DstAddr, "A")
				}

				// Inspect TLS on new HTTPS connections (async, don't block pipeline)
				if event.Type == "network_connect" && event.DstPort == 443 {
					go tlsMonitor.InspectConnection(event.DstAddr, "443")
				}

				// Buffer for batch send
				eventBatch = append(eventBatch, event)

			case alert := <-ruleEngine.Alerts():
				slog.Warn("Security alert",
					"rule", alert.Rule.Name,
					"severity", alert.Rule.Severity,
					"pid", alert.Event.PID,
					"comm", alert.Event.Comm,
				)
				_ = wal.Write(alert.Event)

			case anomaly := <-anomalyDetector.Alerts():
				slog.Warn("Behavioral anomaly detected",
					"container", anomaly.ContainerKey,
					"metric", anomaly.MetricType,
					"z_score", anomaly.ZScore,
					"severity", anomaly.Severity,
				)

			case dnsAlert := <-dnsMonitor.Alerts():
				slog.Warn("DNS anomaly detected",
					"type", dnsAlert.AlertType,
					"domain", dnsAlert.Domain,
					"severity", dnsAlert.Severity,
				)

			case tlsAlert := <-tlsMonitor.Alerts():
				slog.Warn("TLS issue detected",
					"type", tlsAlert.AlertType,
					"host", tlsAlert.Host,
					"severity", tlsAlert.Severity,
				)

			case k8sAlert := <-auditMonitor.Alerts():
				slog.Warn("K8s audit alert",
					"type", k8sAlert.AlertType,
					"user", k8sAlert.User,
					"resource", k8sAlert.Resource,
					"severity", k8sAlert.Severity,
				)

			case <-batchTicker.C:
				if len(eventBatch) > 0 {
					if err := client.SendEvents(ctx, eventBatch); err != nil {
						// Connection failed — write to WAL
						for _, e := range eventBatch {
							_ = wal.Write(e)
						}
						slog.Warn("Failed to send events, buffered to WAL", "count", len(eventBatch), "error", err)
					}
					eventBatch = eventBatch[:0]
				}

			case <-ctx.Done():
				return
			}
		}
	}()

	// 6. Heartbeat loop
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := client.Heartbeat(ctx, 0, 0, wal.Count()); err != nil {
					slog.Warn("Heartbeat failed", "error", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// 7. Replay WAL on startup (send buffered events from previous offline period)
	go func() {
		replayCh := make(chan ebpf.Event, 1000)
		go func() {
			count, _ := wal.Replay(replayCh)
			close(replayCh)
			if count > 0 {
				slog.Info("WAL replay complete", "events", count)
			}
		}()

		var batch []ebpf.Event
		for event := range replayCh {
			batch = append(batch, event)
			if len(batch) >= 100 {
				_ = client.SendEvents(ctx, batch)
				batch = batch[:0]
			}
		}
		if len(batch) > 0 {
			_ = client.SendEvents(ctx, batch)
		}
	}()

	slog.InfoContext(ctx, "Agent running",
		"control_plane", controlPlaneURL,
		"hostname", hostname,
	)

	// 8. Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("Shutting down agent...")
	cancel()
	slog.Info("Agent stopped")
}

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func getKernelVersion() string {
	// On Linux, read /proc/version. On other platforms, return unknown.
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return "unknown"
	}
	return string(data[:min(len(data), 100)])
}

func hasBTFSupport() bool {
	// BTF support indicated by presence of /sys/kernel/btf/vmlinux
	_, err := os.Stat("/sys/kernel/btf/vmlinux")
	return err == nil
}
