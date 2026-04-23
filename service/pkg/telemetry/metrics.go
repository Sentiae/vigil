package telemetry

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Vigil Prometheus metrics — registered globally via promauto.

var (
	// Scan metrics
	ScansTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vigil",
		Name:      "scans_total",
		Help:      "Total number of scans triggered",
	}, []string{"scan_type", "status"})

	ScanDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "vigil",
		Name:      "scan_duration_seconds",
		Help:      "Duration of scan execution in seconds",
		Buckets:   []float64{1, 5, 10, 30, 60, 120, 300, 600},
	}, []string{"scan_type"})

	// Finding metrics
	FindingsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vigil",
		Name:      "findings_total",
		Help:      "Total findings ingested",
	}, []string{"severity", "analysis_type", "scanner"})

	FindingsActive = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "vigil",
		Name:      "findings_active",
		Help:      "Currently active (unresolved) findings",
	}, []string{"severity"})

	FindingsResolved = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vigil",
		Name:      "findings_resolved_total",
		Help:      "Total findings resolved",
	}, []string{"resolution"})

	// SLA metrics
	SLABreachesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "vigil",
		Name:      "sla_breaches_total",
		Help:      "Total SLA deadline breaches detected",
	})

	// Scoring metrics
	EPSSCVECount = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "vigil",
		Name:      "epss_cve_count",
		Help:      "Number of CVEs in the EPSS cache",
	})

	KEVCVECount = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "vigil",
		Name:      "kev_cve_count",
		Help:      "Number of CVEs in the CISA KEV cache",
	})

	// Event metrics
	EventsPublished = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vigil",
		Name:      "events_published_total",
		Help:      "Total Kafka events published",
	}, []string{"event_type"})

	EventsPublishFailed = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "vigil",
		Name:      "events_publish_failed_total",
		Help:      "Total Kafka event publish failures",
	})

	// API metrics
	APIRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "vigil",
		Name:      "api_request_duration_seconds",
		Help:      "HTTP API request duration in seconds",
		Buckets:   prometheus.DefBuckets,
	}, []string{"method", "path", "status"})

	// Agent metrics
	AgentsRegistered = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "vigil",
		Name:      "agents_registered",
		Help:      "Number of registered agents",
	})

	AgentsOnline = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "vigil",
		Name:      "agents_online",
		Help:      "Number of online agents",
	})

	// Outbox metrics
	OutboxPending = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "vigil",
		Name:      "outbox_pending",
		Help:      "Number of pending outbox events",
	})

	OutboxDelivered = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "vigil",
		Name:      "outbox_delivered_total",
		Help:      "Total outbox events delivered",
	})
)
