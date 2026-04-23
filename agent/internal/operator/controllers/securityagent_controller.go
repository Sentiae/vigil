package controllers

import (
	"context"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	vigilv1 "github.com/sentiae/vigil/agent/internal/operator/api/v1"
)

// SecurityAgentReconciler reconciles a SecurityAgent object.
type SecurityAgentReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=vigil.sentiae.com,resources=securityagents,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=vigil.sentiae.com,resources=securityagents/status,verbs=get;update;patch

// Reconcile handles changes to SecurityAgent resources.
func (r *SecurityAgentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the SecurityAgent instance
	var agent vigilv1.SecurityAgent
	if err := r.Get(ctx, req.NamespacedName, &agent); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	logger.Info("Reconciling SecurityAgent",
		"name", agent.Name,
		"namespace", agent.Namespace,
		"type", agent.Spec.AgentType,
	)

	// Update status based on agent heartbeat
	if agent.Status.Phase == "" {
		agent.Status.Phase = "Pending"
		if err := r.Status().Update(ctx, &agent); err != nil {
			logger.Error(err, "Failed to update SecurityAgent status")
			return ctrl.Result{}, err
		}
	}

	// Check if agent has sent a heartbeat recently
	if agent.Status.LastHeartbeat != nil {
		lastSeen := agent.Status.LastHeartbeat.Time
		if time.Since(lastSeen) > 90*time.Second {
			if agent.Status.Phase != "Offline" {
				agent.Status.Phase = "Offline"
				if err := r.Status().Update(ctx, &agent); err != nil {
					return ctrl.Result{}, err
				}
				logger.Info("Agent marked offline", "name", agent.Name, "lastHeartbeat", lastSeen)
			}
		}
	}

	// Requeue to check heartbeat status periodically
	return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *SecurityAgentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&vigilv1.SecurityAgent{}).
		Complete(r)
}
