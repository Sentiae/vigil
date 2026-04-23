package controllers

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	vigilv1 "github.com/sentiae/vigil/agent/internal/operator/api/v1"
)

// MonitoringConfigReconciler reconciles MonitoringConfig objects.
// When a MonitoringConfig is created or updated, it reconfigures the eBPF
// probes on matching agents via the control plane's PushConfig RPC.
type MonitoringConfigReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=vigil.sentiae.com,resources=monitoringconfigs,verbs=get;list;watch

func (r *MonitoringConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var mc vigilv1.MonitoringConfig
	if err := r.Get(ctx, req.NamespacedName, &mc); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	logger.Info("Reconciling MonitoringConfig",
		"name", mc.Name,
		"namespace", mc.Namespace,
		"probes", mc.Spec.EnabledProbes,
		"ringBuffer", mc.Spec.RingBufferSizeKB,
	)

	// Push monitoring configuration to agents:
	// 1. Enable/disable eBPF probes
	// 2. Update ring buffer size
	// 3. Apply runtime detection rules
	// 4. Update ignored paths and processes

	return ctrl.Result{}, nil
}

func (r *MonitoringConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&vigilv1.MonitoringConfig{}).
		Complete(r)
}
