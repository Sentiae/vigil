package main

import (
	"flag"
	"log/slog"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	vigilv1 "github.com/sentiae/vigil/agent/internal/operator/api/v1"
	"github.com/sentiae/vigil/agent/internal/operator/controllers"
)

var (
	scheme = runtime.NewScheme()

	Version   = "dev"
	BuildTime = "unknown"
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(vigilv1.AddToScheme(scheme))
}

func main() {
	var metricsAddr string
	var healthAddr string
	var enableLeaderElection bool

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&healthAddr, "health-probe-bind-address", ":8081", "The address the health probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false, "Enable leader election for controller manager.")
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))
	logger := ctrl.Log.WithName("vigil-operator")

	logger.Info("Starting Vigil operator",
		"version", Version,
		"buildTime", BuildTime,
	)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		HealthProbeBindAddress: healthAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "vigil-operator-leader.sentiae.com",
	})
	if err != nil {
		slog.Error("Unable to create manager", "error", err)
		os.Exit(1)
	}

	// Register reconcilers
	if err := (&controllers.SecurityAgentReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		slog.Error("Unable to create SecurityAgent controller", "error", err)
		os.Exit(1)
	}

	if err := (&controllers.SecurityPolicyReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		slog.Error("Unable to create SecurityPolicy controller", "error", err)
		os.Exit(1)
	}

	if err := (&controllers.MonitoringConfigReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		slog.Error("Unable to create MonitoringConfig controller", "error", err)
		os.Exit(1)
	}

	// Health checks
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		slog.Error("Unable to set up health check", "error", err)
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		slog.Error("Unable to set up ready check", "error", err)
		os.Exit(1)
	}

	logger.Info("Starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		slog.Error("Manager exited with error", "error", err)
		os.Exit(1)
	}
}
