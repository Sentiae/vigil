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
//
// These are aliases of the platform-kit taxonomy constants, not copies: the
// taxonomy is the allowlist every publish is validated against, so a local
// copy that drifts means every publish of that type is rejected at the
// publisher (#three-event-streams-are-rejected-at-the-publisher).
const (
	EventFindingCreated   = kafka.EventSecurityFindingCreated
	EventFindingUpdated   = kafka.EventSecurityFindingUpdated
	EventFindingResolved  = kafka.EventSecurityFindingResolved
	EventFindingSLABreach = kafka.EventSecurityFindingSLABreach
	EventScanStarted      = kafka.EventSecurityScanStarted
	EventScanCompleted    = kafka.EventSecurityScanCompleted
	EventScanFailed       = kafka.EventSecurityScanFailed
	EventAlertCritical    = kafka.EventSecurityAlertCritical
	EventSecretDetected   = kafka.EventSecuritySecretDetected
	EventAssetDiscovered  = kafka.EventSecurityAssetDiscovered
	EventAgentOffline     = kafka.EventSecurityAgentOffline
	EventAttackChainFound = kafka.EventSecurityAttackChainDetected
)
