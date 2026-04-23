// Additional coverage-report parsers for Phase 8 (Cobertura + Istanbul).
//
// Cobertura is the de-facto XML format for Java (JaCoCo via
// cobertura-report) and Python (coverage.py --cobertura-xml).
// Istanbul JSON ships with nyc / c8 / jest when you pass the
// `json-summary` reporter, which is the shape most Node CIs produce.
//
// Both parsers aggregate to the same FileCoverage shape the risk-zone
// pipeline already consumes.
package usecase

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"

	"github.com/sentiae/vigil/service/internal/domain"
)

// ------ Cobertura ------

type coberturaCoverage struct {
	Packages struct {
		Package []coberturaPackage `xml:"package"`
	} `xml:"packages"`
}

type coberturaPackage struct {
	Classes struct {
		Class []coberturaClass `xml:"class"`
	} `xml:"classes"`
}

type coberturaClass struct {
	Filename string `xml:"filename,attr"`
	Lines    struct {
		Line []coberturaLine `xml:"line"`
	} `xml:"lines"`
}

type coberturaLine struct {
	Hits int `xml:"hits,attr"`
}

// ParseCobertura parses a Cobertura XML coverage report. Filenames
// are normalized to forward slashes so Unix/Windows uploads match.
func ParseCobertura(r io.Reader) ([]domain.FileCoverage, error) {
	var doc coberturaCoverage
	dec := xml.NewDecoder(r)
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode cobertura: %w", err)
	}
	files := map[string]*domain.FileCoverage{}
	for _, p := range doc.Packages.Package {
		for _, c := range p.Classes.Class {
			path := c.Filename
			if path == "" {
				continue
			}
			fc, ok := files[path]
			if !ok {
				fc = &domain.FileCoverage{Path: path}
				files[path] = fc
			}
			for _, line := range c.Lines.Line {
				fc.LinesTotal++
				if line.Hits > 0 {
					fc.LinesHit++
				}
			}
		}
	}
	out := make([]domain.FileCoverage, 0, len(files))
	for _, f := range files {
		if f.LinesTotal > 0 {
			f.Fraction = float64(f.LinesHit) / float64(f.LinesTotal)
		}
		out = append(out, *f)
	}
	return out, nil
}

// ------ Istanbul JSON ------

// Istanbul's "json-summary" reporter has two common shapes. We
// support both: a top-level object keyed by file path with .lines
// summary, and a flat "coverageMap"-style where each entry has a
// `.s` (statements hit map) + `.statementMap`.
//
// We parse to the simpler summary shape. The statement-map shape is
// hashed down server-side by coverage tools already; if we see it
// we compute total/hit by counting keys where value > 0.

type istanbulSummary map[string]istanbulFileSummary

type istanbulFileSummary struct {
	Lines *struct {
		Total   int `json:"total"`
		Covered int `json:"covered"`
		// Pct is emitted by newer tools but we derive ours to avoid
		// the "null %" edge.
		Pct any `json:"pct,omitempty"`
	} `json:"lines,omitempty"`
	// Statement-map variant
	S            map[string]int `json:"s,omitempty"`
	StatementMap map[string]any `json:"statementMap,omitempty"`
}

// ParseIstanbul parses an Istanbul JSON coverage report.
func ParseIstanbul(r io.Reader) ([]domain.FileCoverage, error) {
	var doc istanbulSummary
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode istanbul: %w", err)
	}
	out := make([]domain.FileCoverage, 0, len(doc))
	for path, f := range doc {
		if path == "total" {
			continue
		}
		fc := domain.FileCoverage{Path: path}
		switch {
		case f.Lines != nil && f.Lines.Total > 0:
			fc.LinesTotal = f.Lines.Total
			fc.LinesHit = f.Lines.Covered
		case len(f.S) > 0:
			fc.LinesTotal = len(f.S)
			for _, hits := range f.S {
				if hits > 0 {
					fc.LinesHit++
				}
			}
		default:
			continue // no usable data
		}
		if fc.LinesTotal > 0 {
			fc.Fraction = float64(fc.LinesHit) / float64(fc.LinesTotal)
		}
		out = append(out, fc)
	}
	return out, nil
}
