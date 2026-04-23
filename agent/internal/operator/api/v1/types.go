package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// =============================================================================
// SecurityAgent
// =============================================================================

// SecurityAgentSpec defines the desired state of a SecurityAgent.
type SecurityAgentSpec struct {
	AgentType        string   `json:"agentType,omitempty"`
	EnabledProbes    []string `json:"enabledProbes,omitempty"`
	RingBufferSizeKB int32    `json:"ringBufferSizeKB,omitempty"`
	CollectArgs      bool     `json:"collectProcessArgs,omitempty"`
	IgnoredPaths     []string `json:"ignoredPaths,omitempty"`
	IgnoredProcesses []string `json:"ignoredProcesses,omitempty"`
}

// SecurityAgentStatus defines the observed state of a SecurityAgent.
type SecurityAgentStatus struct {
	Phase           string       `json:"phase,omitempty"` // Pending, Running, Degraded, Offline
	LastHeartbeat   *metav1.Time `json:"lastHeartbeat,omitempty"`
	EventsProcessed int64        `json:"eventsProcessed,omitempty"`
	Version         string       `json:"version,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.agentType`
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Events",type=integer,JSONPath=`.status.eventsProcessed`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// SecurityAgent is the Schema for the securityagents API.
type SecurityAgent struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SecurityAgentSpec   `json:"spec,omitempty"`
	Status SecurityAgentStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SecurityAgentList contains a list of SecurityAgent.
type SecurityAgentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecurityAgent `json:"items"`
}

// =============================================================================
// SecurityPolicy
// =============================================================================

type SecurityPolicySpec struct {
	ScanOnPush      bool              `json:"scanOnPush,omitempty"`
	ScanOnPR        bool              `json:"scanOnPR,omitempty"`
	ScanTypes       []string          `json:"scanTypes,omitempty"`
	BlockOnCritical bool              `json:"blockOnCritical,omitempty"`
	SLAOverrides    *SLAOverrides     `json:"slaOverrides,omitempty"`
	ExcludedPaths   []string          `json:"excludedPaths,omitempty"`
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
}

type SLAOverrides struct {
	CriticalHours int `json:"critical,omitempty"`
	HighHours     int `json:"high,omitempty"`
}

// +kubebuilder:object:root=true

type SecurityPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec SecurityPolicySpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

type SecurityPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecurityPolicy `json:"items"`
}

// =============================================================================
// MonitoringConfig
// =============================================================================

type MonitoringConfigSpec struct {
	EnabledProbes    []string      `json:"enabledProbes,omitempty"`
	RingBufferSizeKB int32         `json:"ringBufferSizeKB,omitempty"`
	CollectArgs      bool          `json:"collectProcessArgs,omitempty"`
	CollectContent   bool          `json:"collectFileContent,omitempty"`
	IgnoredPaths     []string      `json:"ignoredPaths,omitempty"`
	IgnoredProcesses []string      `json:"ignoredProcesses,omitempty"`
	Rules            []RuntimeRule `json:"rules,omitempty"`
}

type RuntimeRule struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Severity  string `json:"severity"`
	Condition string `json:"condition"`
	Enabled   bool   `json:"enabled"`
}

// +kubebuilder:object:root=true

type MonitoringConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec MonitoringConfigSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

type MonitoringConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MonitoringConfig `json:"items"`
}
