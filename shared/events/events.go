package events

import (
	kafka "github.com/sentiae/platform-kit/kafka"
)

// Topic is the default Kafka topic for security events.
// With platform-kit the publisher derives topics dynamically from event types,
// but consumers may still reference this constant.
const Topic = "sentiae.security.events"

// Type aliases so that existing code importing this package keeps compiling.
type EventData = kafka.EventData
type Publisher = kafka.Publisher
type CloudEvent = kafka.CloudEvent

// Event type constants following the {domain}.{resource}.{action} pattern.
// The "sentiae." prefix is no longer part of the event type itself; the
// platform-kit publisher prepends the topic prefix automatically.
const (
	EventFindingCreated   = "security.finding.created"
	EventFindingUpdated   = "security.finding.updated"
	EventFindingResolved  = "security.finding.resolved"
	EventFindingSLABreach = "security.finding.sla_breach"
	EventScanStarted      = "security.scan.started"
	EventScanCompleted    = "security.scan.completed"
	EventScanFailed       = "security.scan.failed"
	EventAlertCritical    = "security.alert.critical"
	EventSecretDetected   = "security.secret.detected"
	EventAssetDiscovered  = "security.asset.discovered"
	EventComplianceReport = "security.compliance.report"
	EventAgentOffline     = "security.agent.offline"

	// DAST events
	EventDASTVulnFound    = "security.dast.vulnerability_found"
	EventDASTScanDone     = "security.dast.scan_completed"
	EventEndpointsFound   = "security.discovery.endpoints_found"
	EventAttackChainFound = "security.attack_chain.detected"
)
