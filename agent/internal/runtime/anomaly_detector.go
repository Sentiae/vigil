package runtime

import (
	"context"
	"math"
	"sync"
	"time"

	"gonum.org/v1/gonum/stat"

	"github.com/sentiae/vigil/agent/internal/ebpf"
)

// AnomalyDetector builds statistical baselines per container and detects deviations.
// During the training period (default 2 weeks), it collects metrics.
// After training, it alerts on z-score deviations > threshold (default 2.0).
type AnomalyDetector struct {
	mu        sync.RWMutex
	profiles  map[string]*ContainerProfile // keyed by container ID or image name
	threshold float64                      // z-score threshold for alerting
	training  time.Duration                // training period before alerting
	alerts    chan AnomalyAlert
}

// ContainerProfile holds the statistical baseline for a single container/image.
type ContainerProfile struct {
	Key       string    // container ID or image name
	CreatedAt time.Time // when profiling started
	Trained   bool      // whether training period is complete

	// Process execution rate (execve events per minute)
	ProcessRates []float64
	processMean  float64
	processStd   float64

	// Network connection rate (connect events per minute)
	NetworkRates []float64
	networkMean  float64
	networkStd   float64

	// File access rate (openat events per minute)
	FileRates []float64
	fileMean  float64
	fileStd   float64

	// Unique processes seen (for detecting new/unexpected processes)
	KnownProcesses map[string]int // comm -> count

	// Unique network destinations
	KnownDestinations map[string]int // ip:port -> count

	// Current window counters (reset every minute)
	currentWindow time.Time
	processCount  int
	networkCount  int
	fileCount     int
}

// AnomalyAlert represents a detected behavioral anomaly.
type AnomalyAlert struct {
	ContainerKey string    `json:"container_key"`
	MetricType   string    `json:"metric_type"` // process_rate, network_rate, file_rate, unknown_process, unknown_destination
	CurrentValue float64   `json:"current_value"`
	BaselineMean float64   `json:"baseline_mean"`
	BaselineStd  float64   `json:"baseline_std"`
	ZScore       float64   `json:"z_score"`
	Severity     string    `json:"severity"`
	Description  string    `json:"description"`
	Timestamp    time.Time `json:"timestamp"`
	Event        ebpf.Event `json:"event"`
}

// NewAnomalyDetector creates a detector with the given z-score threshold and training period.
func NewAnomalyDetector(threshold float64, trainingPeriod time.Duration) *AnomalyDetector {
	if threshold <= 0 {
		threshold = 2.0
	}
	if trainingPeriod <= 0 {
		trainingPeriod = 14 * 24 * time.Hour // 2 weeks default
	}

	return &AnomalyDetector{
		profiles:  make(map[string]*ContainerProfile),
		threshold: threshold,
		training:  trainingPeriod,
		alerts:    make(chan AnomalyAlert, 1024),
	}
}

// Alerts returns the channel of detected anomalies.
func (d *AnomalyDetector) Alerts() <-chan AnomalyAlert {
	return d.alerts
}

// ProcessEvent feeds an eBPF event into the anomaly detector.
func (d *AnomalyDetector) ProcessEvent(ctx context.Context, event ebpf.Event) {
	key := event.ContainerID
	if key == "" {
		key = event.Image
	}
	if key == "" {
		key = "__host__" // Host-level events (not in a container)
	}

	d.mu.Lock()
	profile, ok := d.profiles[key]
	if !ok {
		profile = &ContainerProfile{
			Key:               key,
			CreatedAt:         time.Now(),
			KnownProcesses:    make(map[string]int),
			KnownDestinations: make(map[string]int),
			currentWindow:     time.Now().Truncate(time.Minute),
		}
		d.profiles[key] = profile
	}
	d.mu.Unlock()

	d.updateProfile(profile, event)
}

func (d *AnomalyDetector) updateProfile(p *ContainerProfile, event ebpf.Event) {
	now := time.Now()
	windowStart := now.Truncate(time.Minute)

	// Check if we've moved to a new minute window
	if windowStart.After(p.currentWindow) {
		d.flushWindow(p)
		p.currentWindow = windowStart
		p.processCount = 0
		p.networkCount = 0
		p.fileCount = 0
	}

	switch event.Type {
	case "process_exec":
		p.processCount++

		// Track known processes
		if event.Comm != "" {
			prev := p.KnownProcesses[event.Comm]
			p.KnownProcesses[event.Comm] = prev + 1

			// If trained and this is a never-seen-before process, alert
			if p.Trained && prev == 0 {
				d.emitAlert(AnomalyAlert{
					ContainerKey: p.Key,
					MetricType:   "unknown_process",
					CurrentValue: 1,
					Severity:     "high",
					Description:  "Unknown process executed: " + event.Comm + " (exe: " + event.Exe + ")",
					Timestamp:    now,
					Event:        event,
				})
			}
		}

	case "file_access":
		p.fileCount++

	case "network_connect":
		p.networkCount++

		// Track known destinations
		if event.DstAddr != "" {
			dest := event.DstAddr + ":" + itoa(int(event.DstPort))
			prev := p.KnownDestinations[dest]
			p.KnownDestinations[dest] = prev + 1

			if p.Trained && prev == 0 {
				d.emitAlert(AnomalyAlert{
					ContainerKey: p.Key,
					MetricType:   "unknown_destination",
					CurrentValue: 1,
					Severity:     "medium",
					Description:  "Connection to unknown destination: " + dest,
					Timestamp:    now,
					Event:        event,
				})
			}
		}
	}
}

// flushWindow records the current minute's rates and checks for anomalies.
func (d *AnomalyDetector) flushWindow(p *ContainerProfile) {
	processRate := float64(p.processCount)
	networkRate := float64(p.networkCount)
	fileRate := float64(p.fileCount)

	p.ProcessRates = append(p.ProcessRates, processRate)
	p.NetworkRates = append(p.NetworkRates, networkRate)
	p.FileRates = append(p.FileRates, fileRate)

	// Cap stored data points (keep last 7 days at 1-minute resolution = ~10k points)
	const maxPoints = 10080
	if len(p.ProcessRates) > maxPoints {
		p.ProcessRates = p.ProcessRates[len(p.ProcessRates)-maxPoints:]
	}
	if len(p.NetworkRates) > maxPoints {
		p.NetworkRates = p.NetworkRates[len(p.NetworkRates)-maxPoints:]
	}
	if len(p.FileRates) > maxPoints {
		p.FileRates = p.FileRates[len(p.FileRates)-maxPoints:]
	}

	// Check if training period is complete
	if !p.Trained && time.Since(p.CreatedAt) >= d.training {
		d.trainProfile(p)
		p.Trained = true
	}

	// If trained, check for anomalies
	if p.Trained {
		d.checkRateAnomaly(p, "process_rate", processRate, p.processMean, p.processStd)
		d.checkRateAnomaly(p, "network_rate", networkRate, p.networkMean, p.networkStd)
		d.checkRateAnomaly(p, "file_rate", fileRate, p.fileMean, p.fileStd)
	}
}

// trainProfile computes mean and standard deviation from collected data.
func (d *AnomalyDetector) trainProfile(p *ContainerProfile) {
	if len(p.ProcessRates) > 1 {
		p.processMean, p.processStd = stat.MeanStdDev(p.ProcessRates, nil)
	}
	if len(p.NetworkRates) > 1 {
		p.networkMean, p.networkStd = stat.MeanStdDev(p.NetworkRates, nil)
	}
	if len(p.FileRates) > 1 {
		p.fileMean, p.fileStd = stat.MeanStdDev(p.FileRates, nil)
	}
}

func (d *AnomalyDetector) checkRateAnomaly(p *ContainerProfile, metricType string, current, mean, stddev float64) {
	if stddev == 0 {
		return // Can't compute z-score with zero variance
	}

	zScore := (current - mean) / stddev

	if math.Abs(zScore) > d.threshold {
		severity := "medium"
		if math.Abs(zScore) > d.threshold*2 {
			severity = "critical"
		} else if math.Abs(zScore) > d.threshold*1.5 {
			severity = "high"
		}

		direction := "spike"
		if zScore < 0 {
			direction = "drop"
		}

		d.emitAlert(AnomalyAlert{
			ContainerKey: p.Key,
			MetricType:   metricType,
			CurrentValue: current,
			BaselineMean: mean,
			BaselineStd:  stddev,
			ZScore:       zScore,
			Severity:     severity,
			Description:  metricType + " " + direction + " detected (z-score: " + ftoa(zScore) + ")",
			Timestamp:    time.Now(),
		})
	}
}

func (d *AnomalyDetector) emitAlert(alert AnomalyAlert) {
	select {
	case d.alerts <- alert:
	default:
		// Channel full, drop oldest
	}
}

// GetProfile returns the baseline profile for a container (for debugging/inspection).
func (d *AnomalyDetector) GetProfile(key string) *ContainerProfile {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.profiles[key]
}

// ProfileCount returns the number of profiled containers.
func (d *AnomalyDetector) ProfileCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.profiles)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := make([]byte, 0, 5)
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func ftoa(f float64) string {
	sign := ""
	if f < 0 {
		sign = "-"
		f = -f
	}
	whole := int(f)
	frac := int((f - float64(whole)) * 100)
	return sign + itoa(whole) + "." + itoa(frac)
}
