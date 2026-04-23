package runtime

import (
	"context"
	"strings"

	"github.com/sentiae/vigil/agent/internal/ebpf"
)

// Rule defines a runtime security rule evaluated against eBPF events.
type Rule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Condition   string `json:"condition"`
	Enabled     bool   `json:"enabled"`
}

// Alert is produced when a rule matches an event.
type Alert struct {
	Rule  Rule       `json:"rule"`
	Event ebpf.Event `json:"event"`
}

// RuleEngine evaluates eBPF events against a set of security rules.
type RuleEngine struct {
	rules  []Rule
	alerts chan Alert
}

func NewRuleEngine(rules []Rule) *RuleEngine {
	return &RuleEngine{
		rules:  rules,
		alerts: make(chan Alert, 1024),
	}
}

// Evaluate checks an event against all enabled rules.
func (e *RuleEngine) Evaluate(ctx context.Context, event ebpf.Event) {
	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}
		if e.matchesRule(rule, event) {
			select {
			case e.alerts <- Alert{Rule: rule, Event: event}:
			default:
				// Alert channel full, drop
			}
		}
	}
}

// Alerts returns the channel of generated alerts.
func (e *RuleEngine) Alerts() <-chan Alert {
	return e.alerts
}

// UpdateRules replaces the rule set.
func (e *RuleEngine) UpdateRules(rules []Rule) {
	e.rules = rules
}

// matchesRule evaluates a simplified rule condition against an event.
func (e *RuleEngine) matchesRule(rule Rule, event ebpf.Event) bool {
	cond := rule.Condition

	// Reverse shell: bash/sh making outbound connections
	if strings.Contains(cond, "process.exe in") && strings.Contains(cond, "network.operation == 'connect'") {
		if event.Type == "process_exec" && (event.Comm == "bash" || event.Comm == "sh") {
			return true
		}
	}

	// Cryptominer detection
	if strings.Contains(cond, "matches 'xmrig|minerd|cgminer'") {
		miners := []string{"xmrig", "minerd", "cgminer", "cpuminer"}
		for _, m := range miners {
			if strings.Contains(strings.ToLower(event.Comm), m) {
				return true
			}
		}
	}

	// Privilege escalation
	if strings.Contains(cond, "privilege_escalation") && event.Type == "privilege_escalation" {
		return true
	}

	// Sensitive file access
	if strings.Contains(cond, "/etc/shadow") {
		sensitiveFiles := []string{"/etc/shadow", "/etc/passwd", "/.ssh/id_"}
		for _, sf := range sensitiveFiles {
			if strings.Contains(event.FilePath, sf) {
				return true
			}
		}
	}

	// Container escape
	if strings.Contains(cond, "container_escape") && event.Type == "container_escape" {
		return true
	}

	// Kernel module loading
	if strings.Contains(cond, "insmod") || strings.Contains(cond, "modprobe") {
		if event.Comm == "insmod" || event.Comm == "modprobe" {
			return true
		}
	}

	return false
}
