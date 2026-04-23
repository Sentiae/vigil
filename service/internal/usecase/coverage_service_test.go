package usecase

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/sentiae/vigil/service/internal/domain"
)

func TestCoverageService_IngestAndQuery(t *testing.T) {
	svc := NewCoverageService()
	orgID := uuid.New()

	report, err := svc.Ingest(context.Background(), CoverageIngestInput{
		OrgID:  orgID,
		RepoID: "acme/web",
		Format: domain.CoverageFormatLCOV,
		Body: strings.NewReader(`SF:src/app.ts
DA:1,1
DA:2,0
end_of_record
`),
	})
	if err != nil {
		t.Fatalf("ingest err: %v", err)
	}
	if len(report.Files) != 1 || report.Files[0].Path != "src/app.ts" {
		t.Fatalf("unexpected files: %+v", report.Files)
	}

	got, err := svc.CoverageByFile(context.Background(), orgID, "acme/web")
	if err != nil {
		t.Fatalf("query err: %v", err)
	}
	if got["src/app.ts"] != 0.5 {
		t.Fatalf("want 0.5, got %v", got)
	}
}

func TestCoverageService_LatestReplaces(t *testing.T) {
	svc := NewCoverageService()
	orgID := uuid.New()
	// First upload: 50% on one file.
	_, _ = svc.Ingest(context.Background(), CoverageIngestInput{
		OrgID: orgID, RepoID: "r", Format: domain.CoverageFormatLCOV,
		Body: strings.NewReader("SF:a\nDA:1,1\nDA:2,0\nend_of_record\n"),
	})
	// Second upload: 100%. Should supersede.
	_, _ = svc.Ingest(context.Background(), CoverageIngestInput{
		OrgID: orgID, RepoID: "r", Format: domain.CoverageFormatLCOV,
		Body: strings.NewReader("SF:a\nDA:1,1\nend_of_record\n"),
	})
	got, _ := svc.CoverageByFile(context.Background(), orgID, "r")
	if got["a"] != 1.0 {
		t.Fatalf("latest not honored: got %v", got)
	}
}

func TestCoverageService_UnknownFormat(t *testing.T) {
	svc := NewCoverageService()
	_, err := svc.Ingest(context.Background(), CoverageIngestInput{
		OrgID: uuid.New(), RepoID: "r", Format: "jacoco-raw",
		Body: strings.NewReader("<xml/>"),
	})
	if err == nil {
		t.Fatal("expected error on unknown format")
	}
}

func TestCoverageService_MissingRepoIDReturnsEmpty(t *testing.T) {
	svc := NewCoverageService()
	got, err := svc.CoverageByFile(context.Background(), uuid.New(), "nope")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %v", got)
	}
}
