package usecase

import (
	"strings"
	"testing"
)

func TestParseCobertura(t *testing.T) {
	in := `<?xml version="1.0"?>
<coverage>
  <packages>
    <package>
      <classes>
        <class filename="src/a.py">
          <lines>
            <line hits="1"/>
            <line hits="0"/>
            <line hits="2"/>
          </lines>
        </class>
        <class filename="src/b.py">
          <lines>
            <line hits="0"/>
          </lines>
        </class>
      </classes>
    </package>
  </packages>
</coverage>`
	out, err := ParseCobertura(strings.NewReader(in))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	byPath := map[string]float64{}
	for _, f := range out {
		byPath[f.Path] = f.Fraction
	}
	if got := byPath["src/a.py"]; got < 0.66 || got > 0.67 {
		t.Errorf("a.py fraction = %f, want ~0.667", got)
	}
	if got := byPath["src/b.py"]; got != 0 {
		t.Errorf("b.py fraction = %f, want 0", got)
	}
}

func TestParseIstanbul_LinesShape(t *testing.T) {
	in := `{
	  "src/app.ts": {
	    "lines": {"total": 10, "covered": 7}
	  },
	  "total": {
	    "lines": {"total": 10, "covered": 7}
	  }
	}`
	out, err := ParseIstanbul(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 (total skipped), got %d", len(out))
	}
	if out[0].Path != "src/app.ts" || out[0].Fraction != 0.7 {
		t.Fatalf("unexpected: %+v", out[0])
	}
}

func TestParseIstanbul_StatementMapShape(t *testing.T) {
	in := `{
	  "src/app.ts": {
	    "s": {"0": 1, "1": 0, "2": 1, "3": 1}
	  }
	}`
	out, _ := ParseIstanbul(strings.NewReader(in))
	if len(out) != 1 {
		t.Fatalf("want 1, got %d", len(out))
	}
	if out[0].LinesTotal != 4 || out[0].LinesHit != 3 || out[0].Fraction != 0.75 {
		t.Fatalf("unexpected: %+v", out[0])
	}
}
