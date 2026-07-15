package grpc

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	codeanalysisv1 "github.com/sentiae/vigil/service/gen/proto/code_analysis/v1"
	"github.com/sentiae/vigil/service/internal/domain"
	"github.com/sentiae/vigil/service/internal/port/repository"
	portuc "github.com/sentiae/vigil/service/internal/port/usecase"
)

// scanScanPageSize is the batch size used when paginating scans to locate the
// latest scan for a target. ScanFilter exposes no target predicate, so the
// selection is done in Go over created_at DESC-ordered pages.
const scanScanPageSize = 200

// maxScanPages bounds the Go-side scan pagination loop so a large tenant cannot
// wedge a single RPC unboundedly.
const maxScanPages = 50

// CodeAnalysisHandler serves the P13 CodeAnalysisService gRPC seam. It is a
// thin adapter over the existing scan/finding use cases — the same ones the
// Chi HTTP handlers call — re-expressed over gRPC for machine-to-machine
// callers (ops/git/foundry/delivery). tenant_id is carried in each request
// (the M2M contract), not derived from context.
type CodeAnalysisHandler struct {
	codeanalysisv1.UnimplementedCodeAnalysisServiceServer

	scanUC    portuc.ScanUseCase
	findingUC portuc.FindingUseCase
}

// NewCodeAnalysisHandler wires the handler over the scan + finding use cases.
func NewCodeAnalysisHandler(scanUC portuc.ScanUseCase, findingUC portuc.FindingUseCase) *CodeAnalysisHandler {
	return &CodeAnalysisHandler{scanUC: scanUC, findingUC: findingUC}
}

var _ codeanalysisv1.CodeAnalysisServiceServer = (*CodeAnalysisHandler)(nil)

// RequestScan triggers an asynchronous scan and returns a poll handle.
func (h *CodeAnalysisHandler) RequestScan(ctx context.Context, req *codeanalysisv1.RequestScanRequest) (*codeanalysisv1.ScanHandle, error) {
	tenantID, err := parseTenantID(req.GetTenantId())
	if err != nil {
		return nil, err
	}
	// NOTE: TriggerScanInput carries no CommitSHA field, so req.commit_sha
	// cannot propagate through the use case — mirror what the existing input
	// supports rather than extend it.
	scan, err := h.scanUC.TriggerScan(ctx, portuc.TriggerScanInput{
		TenantID:    tenantID,
		ScanType:    domain.ScanType(req.GetScanType()),
		Target:      req.GetTarget(),
		Branch:      req.GetBranch(),
		Priority:    req.GetPriority(),
		TriggeredBy: req.GetTriggeredBy(),
	})
	if err != nil {
		return nil, toGRPC(err)
	}
	return &codeanalysisv1.ScanHandle{
		ScanId:   scan.ID.String(),
		Status:   string(scan.Status),
		QueuedAt: timestamppb.New(scan.CreatedAt),
	}, nil
}

// GetScanStatus returns the lifecycle state + summary of a scan.
func (h *CodeAnalysisHandler) GetScanStatus(ctx context.Context, req *codeanalysisv1.GetScanStatusRequest) (*codeanalysisv1.SecurityScan, error) {
	tenantID, err := parseTenantID(req.GetTenantId())
	if err != nil {
		return nil, err
	}
	scanID, err := uuid.Parse(req.GetScanId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid scan_id")
	}
	scan, err := h.scanUC.GetScan(ctx, tenantID, scanID)
	if err != nil {
		return nil, toGRPC(err)
	}
	return scanToProto(scan), nil
}

// GetCurrentSecurityScan returns the most recent scan for a target regardless
// of completion state.
func (h *CodeAnalysisHandler) GetCurrentSecurityScan(ctx context.Context, req *codeanalysisv1.GetCurrentSecurityScanRequest) (*codeanalysisv1.SecurityScan, error) {
	tenantID, err := parseTenantID(req.GetTenantId())
	if err != nil {
		return nil, err
	}
	scan, err := h.latestScanForTarget(ctx, tenantID, req.GetTarget(), req.GetBranch(), nil)
	if err != nil {
		return nil, toGRPC(err)
	}
	if scan == nil {
		return nil, status.Errorf(codes.NotFound, "no scan for target %q", req.GetTarget())
	}
	return scanToProto(scan), nil
}

// GetSecurityBaseline returns the per-severity summary of the most recent
// completed scan for (tenant, target). Counts are scan-scoped: they are the
// per-severity counts stored on the scan row (what that scan's scanners
// produced), independent of the tenant-global dedup pool. When no completed
// scan exists for the target, an empty baseline (zero counts) is returned — not
// an error.
func (h *CodeAnalysisHandler) GetSecurityBaseline(ctx context.Context, req *codeanalysisv1.GetSecurityBaselineRequest) (*codeanalysisv1.SecurityBaseline, error) {
	tenantID, err := parseTenantID(req.GetTenantId())
	if err != nil {
		return nil, err
	}
	completed := domain.ScanStatusCompleted
	scan, err := h.latestScanForTarget(ctx, tenantID, req.GetTarget(), req.GetBranch(), &completed)
	if err != nil {
		return nil, toGRPC(err)
	}
	if scan == nil {
		// No completed baseline yet: empty, not an error.
		return &codeanalysisv1.SecurityBaseline{}, nil
	}

	critical := int32(scan.FindingsCritical)
	high := int32(scan.FindingsHigh)
	medium := int32(scan.FindingsMedium)
	low := int32(scan.FindingsLow)
	info := int32(scan.FindingsInfo)
	baseline := &codeanalysisv1.SecurityBaseline{
		ScanId:           scan.ID.String(),
		TenantId:         scan.TenantID.String(),
		Target:           scan.Target,
		Branch:           scan.Branch,
		CommitSha:        scan.CommitSHA,
		FindingsCritical: critical,
		FindingsHigh:     high,
		FindingsMedium:   medium,
		FindingsLow:      low,
		FindingsInfo:     info,
		FindingsTotal:    critical + high + medium + low + info,
	}
	if scan.CompletedAt != nil {
		baseline.CompletedAt = timestamppb.New(*scan.CompletedAt)
	}
	return baseline, nil
}

// ListFindings is a paginated findings feed for a tenant.
func (h *CodeAnalysisHandler) ListFindings(ctx context.Context, req *codeanalysisv1.ListFindingsRequest) (*codeanalysisv1.ListFindingsResponse, error) {
	tenantID, err := parseTenantID(req.GetTenantId())
	if err != nil {
		return nil, err
	}

	filter := repository.FindingFilter{
		TenantID: tenantID,
		Category: req.GetCategory(),
		Limit:    int(req.GetLimit()),
		Offset:   int(req.GetOffset()),
	}
	if sev := req.GetSeverity(); sev != "" {
		s := domain.Severity(sev)
		filter.Severity = &s
	}
	if st := req.GetStatus(); st != "" {
		s := domain.FindingStatus(st)
		filter.Status = &s
	}
	if at := req.GetAnalysisType(); at != "" {
		a := domain.AnalysisType(at)
		filter.AnalysisType = &a
	}

	findings, total, err := h.findingUC.ListFindings(ctx, filter)
	if err != nil {
		return nil, toGRPC(err)
	}

	out := &codeanalysisv1.ListFindingsResponse{
		Findings: make([]*codeanalysisv1.Finding, 0, len(findings)),
		Total:    int32(total),
	}
	for _, f := range findings {
		out.Findings = append(out.Findings, findingToProto(f))
	}
	return out, nil
}

// GetComplexityDelta is unimplemented: no existing use case computes the
// cyclomatic-complexity / per-commit findings delta between two SHAs, and this
// slice does not add one.
func (h *CodeAnalysisHandler) GetComplexityDelta(_ context.Context, _ *codeanalysisv1.GetComplexityDeltaRequest) (*codeanalysisv1.ComplexityDelta, error) {
	return nil, status.Error(codes.Unimplemented, "GetComplexityDelta is not implemented: no complexity/findings-delta use case exists in vigil")
}

// latestScanForTarget scans created_at DESC-ordered pages and returns the first
// scan matching target (and branch, when supplied). statusFilter, when set,
// restricts to that lifecycle status. Returns nil when no match is found.
func (h *CodeAnalysisHandler) latestScanForTarget(ctx context.Context, tenantID uuid.UUID, target, branch string, statusFilter *domain.ScanStatus) (*domain.Scan, error) {
	for page := 0; page < maxScanPages; page++ {
		scans, _, err := h.scanUC.ListScans(ctx, repository.ScanFilter{
			TenantID: tenantID,
			Status:   statusFilter,
			Limit:    scanScanPageSize,
			Offset:   page * scanScanPageSize,
		})
		if err != nil {
			return nil, err
		}
		for _, s := range scans {
			if s.Target != target {
				continue
			}
			if branch != "" && s.Branch != branch {
				continue
			}
			return s, nil
		}
		if len(scans) < scanScanPageSize {
			break
		}
	}
	return nil, nil
}

// parseTenantID validates the request-supplied tenant_id (M2M contract: the
// caller passes the tenant it acts for).
func parseTenantID(raw string) (uuid.UUID, error) {
	id, err := uuid.Parse(raw)
	if err != nil || id == uuid.Nil {
		return uuid.Nil, status.Error(codes.InvalidArgument, "invalid tenant_id")
	}
	return id, nil
}

// scanToProto maps a domain.Scan to the SecurityScan wire message.
func scanToProto(s *domain.Scan) *codeanalysisv1.SecurityScan {
	out := &codeanalysisv1.SecurityScan{
		Id:            s.ID.String(),
		TenantId:      s.TenantID.String(),
		ScanType:      string(s.Type),
		Target:        s.Target,
		Branch:        s.Branch,
		CommitSha:     s.CommitSHA,
		Status:        string(s.Status),
		Priority:      s.Priority,
		FindingsNew:   int32(s.FindingsNew),
		FindingsTotal: int32(s.FindingsTotal),
		DurationMs:    s.DurationMs,
		Error:         s.Error,
		TriggeredBy:   s.TriggeredBy,
		CreatedAt:     timestamppb.New(s.CreatedAt),
		UpdatedAt:     timestamppb.New(s.UpdatedAt),
	}
	if s.StartedAt != nil {
		out.StartedAt = timestamppb.New(*s.StartedAt)
	}
	if s.CompletedAt != nil {
		out.CompletedAt = timestamppb.New(*s.CompletedAt)
	}
	return out
}

// findingToProto maps a domain.Finding to the flattened Finding wire message.
func findingToProto(f *domain.Finding) *codeanalysisv1.Finding {
	out := &codeanalysisv1.Finding{
		Id:              f.ID.String(),
		TenantId:        f.TenantID.String(),
		Fingerprint:     f.Fingerprint,
		Title:           f.Title,
		Description:     f.Description,
		Severity:        string(f.Severity),
		Status:          string(f.Status),
		AnalysisType:    string(f.AnalysisType),
		Category:        f.Category,
		SourceScanner:   f.SourceScanner,
		SourceRuleId:    f.SourceRuleID,
		Cves:            f.CVEs,
		NormalizedScore: f.NormalizedScore,
		LocationSummary: locationSummary(f.Location),
		Remediation:     f.Remediation,
		FirstSeenAt:     timestamppb.New(f.FirstSeenAt),
		LastSeenAt:      timestamppb.New(f.LastSeenAt),
	}
	if f.ScanID != nil {
		out.ScanId = f.ScanID.String()
	}
	if f.CVSSScore != nil {
		out.CvssScore = *f.CVSSScore
	}
	if f.EPSSScore != nil {
		out.EpssScore = *f.EPSSScore
	}
	return out
}

// locationSummary renders the polymorphic finding location as a compact
// inter-service string (file:line or image[@digest], with sensible fallbacks).
func locationSummary(l domain.FindingLocation) string {
	switch {
	case l.FilePath != "":
		if l.LineStart != nil {
			return fmt.Sprintf("%s:%d", l.FilePath, *l.LineStart)
		}
		return l.FilePath
	case l.ContainerImage != "":
		if l.ImageDigest != "" {
			return l.ContainerImage + "@" + l.ImageDigest
		}
		return l.ContainerImage
	case l.PackageName != "":
		if l.PackageVersion != "" {
			return l.PackageName + "@" + l.PackageVersion
		}
		return l.PackageName
	case l.ResourceARN != "":
		return l.ResourceARN
	case l.Hostname != "":
		if l.Port != nil {
			return fmt.Sprintf("%s:%d", l.Hostname, *l.Port)
		}
		return l.Hostname
	default:
		return ""
	}
}

// toGRPC converts a domain/use-case error to a gRPC status at the handler
// boundary.
func toGRPC(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, domain.ErrScanNotFound),
		errors.Is(err, domain.ErrFindingNotFound),
		errors.Is(err, domain.ErrAssetNotFound),
		errors.Is(err, domain.ErrNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, domain.ErrInvalidScan),
		errors.Is(err, domain.ErrInvalidFinding),
		errors.Is(err, domain.ErrInvalidAsset),
		errors.Is(err, domain.ErrInvalidFingerprint):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, domain.ErrScanInProgress),
		errors.Is(err, domain.ErrDuplicateFinding):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, domain.ErrUnauthorized):
		return status.Error(codes.Unauthenticated, err.Error())
	case errors.Is(err, domain.ErrForbidden):
		return status.Error(codes.PermissionDenied, err.Error())
	default:
		return status.Error(codes.Internal, "internal error")
	}
}
