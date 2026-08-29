package events

import (
	"testing"

	kafka "github.com/sentiae/platform-kit/kafka"
)

// TestEventTypes_MatchTaxonomy guards the aliases in events.go against drift.
// The taxonomy is the allowlist every publish is validated against, so an
// alias that silently becomes a local copy means every publish of that type
// is rejected at the publisher — a whole event stream dies with no build
// error and no test failure. This table is what makes that fail loudly.
func TestEventTypes_MatchTaxonomy(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"finding_created", EventFindingCreated, kafka.EventSecurityFindingCreated},
		{"finding_updated", EventFindingUpdated, kafka.EventSecurityFindingUpdated},
		{"finding_resolved", EventFindingResolved, kafka.EventSecurityFindingResolved},
		{"finding_sla_breach", EventFindingSLABreach, kafka.EventSecurityFindingSLABreach},
		{"scan_started", EventScanStarted, kafka.EventSecurityScanStarted},
		{"scan_completed", EventScanCompleted, kafka.EventSecurityScanCompleted},
		{"scan_failed", EventScanFailed, kafka.EventSecurityScanFailed},
		{"alert_critical", EventAlertCritical, kafka.EventSecurityAlertCritical},
		{"secret_detected", EventSecretDetected, kafka.EventSecuritySecretDetected},
		{"asset_discovered", EventAssetDiscovered, kafka.EventSecurityAssetDiscovered},
		{"agent_offline", EventAgentOffline, kafka.EventSecurityAgentOffline},
		{"attack_chain_detected", EventAttackChainFound, kafka.EventSecurityAttackChainDetected},
	}

	if len(tests) != 12 {
		t.Fatalf("table covers %d aliases, want 12", len(tests))
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("alias drifted from the taxonomy: got %q, want %q", tt.got, tt.want)
			}
			if err := kafka.ValidateEventType(tt.got); err != nil {
				t.Errorf("event type %q rejected by the taxonomy: %v", tt.got, err)
			}
			if _, ok := kafka.LookupEvent(tt.got); !ok {
				t.Errorf("event type %q is not registered in the taxonomy", tt.got)
			}
		})
	}
}
