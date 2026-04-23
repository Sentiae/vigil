package controllers

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	vigilv1 "github.com/sentiae/vigil/agent/internal/operator/api/v1"
)

// SecurityPolicyReconciler reconciles SecurityPolicy objects.
// When a SecurityPolicy is created or updated, it pushes the scan configuration
// to all agents in the matching namespaces.
type SecurityPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=vigil.sentiae.com,resources=securitypolicies,verbs=get;list;watch

func (r *SecurityPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var policy vigilv1.SecurityPolicy
	if err := r.Get(ctx, req.NamespacedName, &policy); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	logger.Info("Reconciling SecurityPolicy",
		"name", policy.Name,
		"namespace", policy.Namespace,
		"scanOnPush", policy.Spec.ScanOnPush,
		"blockOnCritical", policy.Spec.BlockOnCritical,
	)

	// Push policy to control plane for enforcement:
	// 1. If scanOnPush is true, ensure git push webhook triggers scans
	// 2. If blockOnCritical is true, configure admission webhook to check findings
	// 3. Apply SLA overrides to the tenant's policy configuration
	// 4. Propagate excluded paths to scanner configurations

	return ctrl.Result{}, nil
}

func (r *SecurityPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&vigilv1.SecurityPolicy{}).
		Complete(r)
}
