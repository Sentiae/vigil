package grpc_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	pkconfig "github.com/sentiae/platform-kit/config"
	"github.com/sentiae/platform-kit/grpcclient"
	"github.com/sentiae/platform-kit/grpcserver"
	"github.com/sentiae/platform-kit/spiffe/spiffetest"

	codeanalysisv1 "github.com/sentiae/vigil/service/gen/proto/code_analysis/v1"
	grpchandler "github.com/sentiae/vigil/service/internal/adapter/handler/grpc"
	"github.com/sentiae/vigil/service/internal/app"
	"github.com/sentiae/vigil/service/internal/domain"
	"github.com/sentiae/vigil/service/internal/port/repository"
	portuc "github.com/sentiae/vigil/service/internal/port/usecase"
	"github.com/sentiae/vigil/service/pkg/config"
)

// TestCodeAnalysisService_StrictMTLS serves the REAL CodeAnalysisService handler
// through the REAL interceptor chain (app.GRPCServerOptions) on a strict
// grpcserver listener holding a real svc/vigil SVID, and drives it with real
// clients. It is the assertion the 2026-08-06 outage needed and did not have:
// configuration says "strict", only a live handshake proves it.
func TestCodeAnalysisService_StrictMTLS(t *testing.T) {
	ca := spiffetest.NewCA(t)
	serverSrc := ca.NewSource(t, "vigil")

	builder := grpcserver.New(grpcserver.Config{
		Mode:        pkconfig.MTLSModeStrict,
		Source:      serverSrc,
		ServiceName: "vigil",
	}, app.GRPCServerOptions(&config.Config{})...)

	codeanalysisv1.RegisterCodeAnalysisServiceServer(builder.Registrar(),
		grpchandler.NewCodeAnalysisHandler(unimplementedScanUseCase{}, unimplementedFindingUseCase{}, warnGateUseCase{}))

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	serveErr := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				serveErr <- fmt.Errorf("Serve panicked: %v", r)
			}
		}()
		serveErr <- builder.Serve(lis)
	}()
	t.Cleanup(func() {
		builder.Stop()
		select {
		case err := <-serveErr:
			if err != nil {
				t.Errorf("Serve returned %v after Stop; want nil", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return within 5s of Stop")
		}
	})

	if err := <-builder.Ready(); err != nil {
		t.Fatalf("strict listener refused to serve: %v", err)
	}
	addr := "passthrough:///" + lis.Addr().String()

	t.Run("delivery SVID with no x-api-key is admitted", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		conn, err := grpcclient.Dial(ctx, grpcclient.Config{
			Endpoint:      addr,
			Mode:          pkconfig.MTLSModeStrict,
			Source:        ca.NewSource(t, "delivery"),
			ServerService: "vigil",
		})
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer func() { _ = conn.Close() }()

		// No x-api-key metadata anywhere: the peer SVID is the only credential.
		resp, err := codeanalysisv1.NewCodeAnalysisServiceClient(conn).ResolveGatePolicy(ctx,
			&codeanalysisv1.ResolveGatePolicyRequest{TenantId: uuid.NewString()})
		if err != nil {
			t.Fatalf("ResolveGatePolicy over mTLS with no x-api-key: %v (code %s)", err, status.Code(err))
		}
		if !resp.GetSet() || resp.GetMode() != string(domain.GateModeWarn) {
			t.Fatalf("ResolveGatePolicy = %+v, want set=true mode=warn", resp)
		}
	})

	t.Run("plaintext caller is refused", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			t.Fatalf("plaintext dial: %v", err)
		}
		defer func() { _ = conn.Close() }()

		_, err = codeanalysisv1.NewCodeAnalysisServiceClient(conn).ResolveGatePolicy(ctx,
			&codeanalysisv1.ResolveGatePolicyRequest{TenantId: uuid.NewString()})
		if err == nil {
			t.Fatal("a plaintext caller reached the strict listener; the TLS half is not enforced")
		}
		if got := status.Code(err); got != codes.Unavailable {
			t.Fatalf("plaintext caller got code %s (%v), want Unavailable", got, err)
		}
	})

	t.Run("SVID from an untrusted CA is refused", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Same SPIFFE ID (svc/delivery), different root: only the trust bundle
		// distinguishes them, which is exactly what mTLS must check.
		rogue := spiffetest.NewCA(t)
		conn, err := grpcclient.Dial(ctx, grpcclient.Config{
			Endpoint:      addr,
			Mode:          pkconfig.MTLSModeStrict,
			Source:        rogue.NewSource(t, "delivery"),
			ServerService: "vigil",
		})
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer func() { _ = conn.Close() }()

		_, err = codeanalysisv1.NewCodeAnalysisServiceClient(conn).ResolveGatePolicy(ctx,
			&codeanalysisv1.ResolveGatePolicyRequest{TenantId: uuid.NewString()})
		if err == nil {
			t.Fatal("a caller holding an SVID from an untrusted CA was admitted")
		}
		if got := status.Code(err); got != codes.Unavailable {
			t.Fatalf("untrusted-CA caller got code %s (%v), want Unavailable", got, err)
		}
	})
}

// warnGateUseCase is the only fake that answers: ResolveGatePolicy is the RPC
// delivery's deploy gate actually calls over this seam.
type warnGateUseCase struct{}

func (warnGateUseCase) Resolve(context.Context, uuid.UUID, uuid.UUID) (domain.ResolvedGatePolicy, error) {
	return domain.ResolvedGatePolicy{
		Set:               true,
		Mode:              domain.GateModeWarn,
		SeverityThreshold: domain.SeverityHigh,
		Source:            domain.GateSourceOrg,
	}, nil
}

func (warnGateUseCase) GetPolicy(context.Context, uuid.UUID) (*domain.GatePolicy, error) {
	return nil, unimplemented("GetPolicy")
}

func (warnGateUseCase) SetPolicy(context.Context, portuc.SetGatePolicyInput) (*domain.GatePolicy, error) {
	return nil, unimplemented("SetPolicy")
}

func (warnGateUseCase) GetUserPref(context.Context, uuid.UUID, uuid.UUID) (*domain.GateUserPref, error) {
	return nil, unimplemented("GetUserPref")
}

func (warnGateUseCase) SetUserPref(context.Context, portuc.SetGateUserPrefInput) (*domain.GateUserPref, error) {
	return nil, unimplemented("SetUserPref")
}

type unimplementedScanUseCase struct{}

func (unimplementedScanUseCase) TriggerScan(context.Context, portuc.TriggerScanInput) (*domain.Scan, error) {
	return nil, unimplemented("TriggerScan")
}

func (unimplementedScanUseCase) GetScan(context.Context, uuid.UUID, uuid.UUID) (*domain.Scan, error) {
	return nil, unimplemented("GetScan")
}

func (unimplementedScanUseCase) ListScans(context.Context, repository.ScanFilter) ([]*domain.Scan, int, error) {
	return nil, 0, unimplemented("ListScans")
}

type unimplementedFindingUseCase struct{}

func (unimplementedFindingUseCase) GetFinding(context.Context, uuid.UUID, uuid.UUID) (*domain.Finding, error) {
	return nil, unimplemented("GetFinding")
}

func (unimplementedFindingUseCase) ListFindings(context.Context, repository.FindingFilter) ([]*domain.Finding, int, error) {
	return nil, 0, unimplemented("ListFindings")
}

func (unimplementedFindingUseCase) ResolveFinding(context.Context, uuid.UUID, portuc.ResolveFindingInput) (*domain.Finding, error) {
	return nil, unimplemented("ResolveFinding")
}

func (unimplementedFindingUseCase) IngestFindings(context.Context, uuid.UUID, []*domain.Finding) (int, int, error) {
	return 0, 0, unimplemented("IngestFindings")
}

func (unimplementedFindingUseCase) CountBySeverity(context.Context, uuid.UUID) (map[domain.Severity]int, error) {
	return nil, unimplemented("CountBySeverity")
}

func unimplemented(method string) error {
	return status.Errorf(codes.Unimplemented, "%s is not part of this transport regression", method)
}

var (
	_ portuc.ScanUseCase       = unimplementedScanUseCase{}
	_ portuc.FindingUseCase    = unimplementedFindingUseCase{}
	_ portuc.GatePolicyUseCase = warnGateUseCase{}
)
