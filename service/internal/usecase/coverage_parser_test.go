package usecase

import (
	"strings"
	"testing"
)

// TestParseLCOV_TwoFiles — the canonical happy path: two SF blocks
// with mixed-hit DA records and explicit end_of_record markers.
func TestParseLCOV_TwoFiles(t *testing.T) {
	in := `TN:
SF:src/a.ts
DA:1,1
DA:2,1
DA:3,0
LH:2
LF:3
end_of_record
SF:src/b.ts
DA:1,0
DA:2,0
LH:0
LF:2
end_of_record
`
	out, err := ParseLCOV(strings.NewReader(in))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	byPath := map[string]float64{}
	for _, f := range out {
		byPath[f.Path] = f.Fraction
	}
	if got := byPath["src/a.ts"]; got < 0.66 || got > 0.67 {
		t.Errorf("a.ts fraction = %f, want ~0.667", got)
	}
	if got := byPath["src/b.ts"]; got != 0 {
		t.Errorf("b.ts fraction = %f, want 0 (no lines hit)", got)
	}
}

// TestParseLCOV_ConcatDuplicates — concatenated tracefiles can
// repeat the same SF block; lines should aggregate, not double-count.
func TestParseLCOV_ConcatDuplicates(t *testing.T) {
	in := `SF:x.go
DA:1,1
end_of_record
SF:x.go
DA:1,1
DA:2,0
end_of_record
`
	out, _ := ParseLCOV(strings.NewReader(in))
	if len(out) != 1 {
		t.Fatalf("want 1 file, got %d", len(out))
	}
	if out[0].LinesTotal != 3 || out[0].LinesHit != 2 {
		t.Errorf("want hit=2 total=3, got hit=%d total=%d", out[0].LinesHit, out[0].LinesTotal)
	}
}

// TestParseGoCoverprofile — aggregates by file, skips the mode header,
// counts hit statements when count > 0.
func TestParseGoCoverprofile(t *testing.T) {
	in := `mode: set
pkg/billing/charge.go:10.2,12.3 2 1
pkg/billing/charge.go:15.2,16.3 1 0
pkg/billing/refund.go:5.2,8.3 3 1
`
	out, err := ParseGoCoverprofile(strings.NewReader(in))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	byPath := map[string]float64{}
	for _, f := range out {
		byPath[f.Path] = f.Fraction
	}
	if got := byPath["pkg/billing/charge.go"]; got < 0.66 || got > 0.67 {
		t.Errorf("charge.go fraction = %f, want ~0.667", got)
	}
	if got := byPath["pkg/billing/refund.go"]; got != 1.0 {
		t.Errorf("refund.go fraction = %f, want 1.0", got)
	}
}

// TestParseGoCoverprofile_NoMode — some tools emit profiles without
// the mode: header. Parser should still work.
func TestParseGoCoverprofile_NoMode(t *testing.T) {
	in := `a.go:1.1,2.1 1 1
a.go:3.1,4.1 1 0
`
	out, _ := ParseGoCoverprofile(strings.NewReader(in))
	if len(out) != 1 || out[0].Fraction != 0.5 {
		t.Fatalf("want fraction=0.5, got %+v", out)
	}
}

// TestParseLCOV_MalformedDALine — a garbage DA record should be
// skipped, not abort the whole parse.
func TestParseLCOV_MalformedDALine(t *testing.T) {
	in := `SF:a.go
DA:1,1
DA:garbage
DA:2,0
end_of_record
`
	out, err := ParseLCOV(strings.NewReader(in))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if out[0].LinesTotal != 2 || out[0].LinesHit != 1 {
		t.Errorf("garbage DA not skipped: %+v", out[0])
	}
}
