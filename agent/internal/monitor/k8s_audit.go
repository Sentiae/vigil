package monitor

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// K8sAuditAlert represents a suspicious Kubernetes audit event.
type K8sAuditAlert struct {
	AlertType   string    `json:"alert_type"` // rbac_violation, secret_access, exec_into_pod, privileged_pod, host_namespace
	User        string    `json:"user"`
	Verb        string    `json:"verb"`
	Resource    string    `json:"resource"`
	Namespace   string    `json:"namespace"`
	Name        string    `json:"name"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
}

// K8sAuditEvent is a subset of the Kubernetes audit event schema.
type K8sAuditEvent struct {
	Level      string    `json:"level"`
	AuditID    string    `json:"auditID"`
	Stage      string    `json:"stage"`
	RequestURI string    `json:"requestURI"`
	Verb       string    `json:"verb"`
	User       AuditUser `json:"user"`
	ObjectRef  *AuditObjectRef `json:"objectRef,omitempty"`
	ResponseStatus *AuditStatus `json:"responseStatus,omitempty"`
	RequestObject  json.RawMessage `json:"requestObject,omitempty"`
	StageTimestamp time.Time `json:"stageTimestamp"`
}

type AuditUser struct {
	Username string   `json:"username"`
	Groups   []string `json:"groups"`
}

type AuditObjectRef struct {
	Resource  string `json:"resource"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	APIGroup  string `json:"apiGroup"`
}

type AuditStatus struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// K8sAuditMonitor consumes Kubernetes audit logs via webhook and detects suspicious activity.
type K8sAuditMonitor struct {
	alerts chan K8sAuditAlert
	server *http.Server
}

func NewK8sAuditMonitor(listenAddr string) *K8sAuditMonitor {
	m := &K8sAuditMonitor{
		alerts: make(chan K8sAuditAlert, 512),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/audit", m.handleAuditWebhook)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	m.server = &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
	}

	return m
}

func (m *K8sAuditMonitor) Alerts() <-chan K8sAuditAlert {
	return m.alerts
}

// Start begins the audit webhook HTTP server.
func (m *K8sAuditMonitor) Start(ctx context.Context) error {
	slog.Info("Starting K8s audit webhook", "addr", m.server.Addr)
	go func() {
		<-ctx.Done()
		m.server.Close()
	}()
	return m.server.ListenAndServe()
}

func (m *K8sAuditMonitor) handleAuditWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024)) // 10MB limit
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// K8s sends an EventList
	var eventList struct {
		Items []K8sAuditEvent `json:"items"`
	}
	if err := json.Unmarshal(body, &eventList); err != nil {
		// Try single event
		var event K8sAuditEvent
		if err := json.Unmarshal(body, &event); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		eventList.Items = []K8sAuditEvent{event}
	}

	for _, event := range eventList.Items {
		// Only process ResponseComplete stage
		if event.Stage != "ResponseComplete" {
			continue
		}
		m.analyzeEvent(event)
	}

	w.WriteHeader(http.StatusOK)
}

func (m *K8sAuditMonitor) analyzeEvent(event K8sAuditEvent) {
	if event.ObjectRef == nil {
		return
	}

	ref := event.ObjectRef
	now := event.StageTimestamp
	if now.IsZero() {
		now = time.Now()
	}

	// Check 1: Secret access (reading secrets is high-sensitivity)
	if ref.Resource == "secrets" && (event.Verb == "get" || event.Verb == "list" || event.Verb == "watch") {
		// Skip system accounts
		if !isSystemUser(event.User.Username) {
			m.emitAlert(K8sAuditAlert{
				AlertType:   "secret_access",
				User:        event.User.Username,
				Verb:        event.Verb,
				Resource:    ref.Resource,
				Namespace:   ref.Namespace,
				Name:        ref.Name,
				Severity:    "medium",
				Description: "Secret accessed by " + event.User.Username + " in " + ref.Namespace + "/" + ref.Name,
				Timestamp:   now,
			})
		}
	}

	// Check 2: Exec into pod (potential lateral movement)
	if ref.Resource == "pods" && strings.Contains(event.RequestURI, "/exec") {
		m.emitAlert(K8sAuditAlert{
			AlertType:   "exec_into_pod",
			User:        event.User.Username,
			Verb:        "exec",
			Resource:    ref.Resource,
			Namespace:   ref.Namespace,
			Name:        ref.Name,
			Severity:    "high",
			Description: event.User.Username + " exec'd into pod " + ref.Namespace + "/" + ref.Name,
			Timestamp:   now,
		})
	}

	// Check 3: RBAC violations (403 responses)
	if event.ResponseStatus != nil && event.ResponseStatus.Code == 403 {
		m.emitAlert(K8sAuditAlert{
			AlertType:   "rbac_violation",
			User:        event.User.Username,
			Verb:        event.Verb,
			Resource:    ref.Resource,
			Namespace:   ref.Namespace,
			Name:        ref.Name,
			Severity:    "medium",
			Description: "RBAC denied: " + event.User.Username + " tried to " + event.Verb + " " + ref.Resource,
			Timestamp:   now,
		})
	}

	// Check 4: Privileged pod creation
	if ref.Resource == "pods" && event.Verb == "create" && len(event.RequestObject) > 0 {
		if isPrivilegedPodSpec(event.RequestObject) {
			m.emitAlert(K8sAuditAlert{
				AlertType:   "privileged_pod",
				User:        event.User.Username,
				Verb:        event.Verb,
				Resource:    ref.Resource,
				Namespace:   ref.Namespace,
				Name:        ref.Name,
				Severity:    "critical",
				Description: "Privileged pod created by " + event.User.Username + " in " + ref.Namespace,
				Timestamp:   now,
			})
		}
	}

	// Check 5: ClusterRole/ClusterRoleBinding changes (privilege escalation)
	if (ref.Resource == "clusterroles" || ref.Resource == "clusterrolebindings") &&
		(event.Verb == "create" || event.Verb == "update" || event.Verb == "patch") {
		m.emitAlert(K8sAuditAlert{
			AlertType:   "rbac_modification",
			User:        event.User.Username,
			Verb:        event.Verb,
			Resource:    ref.Resource,
			Name:        ref.Name,
			Severity:    "high",
			Description: event.User.Username + " modified " + ref.Resource + ": " + ref.Name,
			Timestamp:   now,
		})
	}
}

func (m *K8sAuditMonitor) emitAlert(alert K8sAuditAlert) {
	select {
	case m.alerts <- alert:
	default:
	}
}

// isSystemUser checks if the user is a Kubernetes system account.
func isSystemUser(username string) bool {
	systemPrefixes := []string{
		"system:serviceaccount:kube-system:",
		"system:kube-",
		"system:apiserver",
		"system:node:",
	}
	for _, prefix := range systemPrefixes {
		if strings.HasPrefix(username, prefix) {
			return true
		}
	}
	return false
}

// isPrivilegedPodSpec checks if a pod request object contains privileged security context.
func isPrivilegedPodSpec(raw json.RawMessage) bool {
	// Quick string check before full parse
	s := string(raw)
	return strings.Contains(s, `"privileged":true`) ||
		strings.Contains(s, `"hostPID":true`) ||
		strings.Contains(s, `"hostNetwork":true`) ||
		strings.Contains(s, `"hostIPC":true`)
}
