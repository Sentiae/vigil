// Coverage parsers.
//
// Two formats are supported today:
//
//  1. LCOV — the lingua franca of JS/TS (jest, c8, nyc), Python
//     (pytest-cov exports LCOV), and C/C++ (lcov/gcov). Line-based.
//     Spec: http://ltp.sourceforge.net/coverage/lcov/geninfo.1.php
//     Relevant records:
//       SF:<path>   start of a file block
//       DA:<line>,<count>   line execution count (<count>==0 → miss)
//       LH:<n>      lines hit (redundant but common)
//       LF:<n>      lines found (redundant but common)
//       end_of_record
//
//  2. Go coverprofile — `go test -coverprofile`. Block-based. Lines:
//       mode: set|count|atomic
//       path/file.go:lineStart.colStart,lineEnd.colEnd numStatements count
//     We aggregate per file: statements-hit / statements-total.
//
// Anything we can't parse produces an explicit error so callers don't
// silently ingest garbage.
package usecase

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/sentiae/vigil/service/internal/domain"
)

// ParseLCOV parses an LCOV tracefile from r into per-file coverage
// summaries. Malformed DA lines are skipped; missing end_of_record
// on the last file is tolerated so "cat *.info" style concatenations
// still parse.
func ParseLCOV(r io.Reader) ([]domain.FileCoverage, error) {
	files := map[string]*domain.FileCoverage{}
	var current *domain.FileCoverage
	scanner := bufio.NewScanner(r)
	// LCOV lines are short but some tools emit very long source paths;
	// bump the buffer to 1MiB so we don't truncate.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "SF:"):
			path := strings.TrimPrefix(line, "SF:")
			// De-dupe across multiple SF records for the same file
			// (LCOV concat outputs sometimes include repeats).
			if existing, ok := files[path]; ok {
				current = existing
			} else {
				current = &domain.FileCoverage{Path: path}
				files[path] = current
			}
		case strings.HasPrefix(line, "DA:"):
			if current == nil {
				continue
			}
			rest := strings.TrimPrefix(line, "DA:")
			comma := strings.IndexByte(rest, ',')
			if comma < 0 {
				continue
			}
			count, err := strconv.Atoi(strings.TrimSpace(rest[comma+1:]))
			if err != nil {
				continue
			}
			current.LinesTotal++
			if count > 0 {
				current.LinesHit++
			}
		case line == "end_of_record":
			current = nil
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan lcov: %w", err)
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

// ParseGoCoverprofile parses `go test -coverprofile` output. The
// format's first line is `mode: <mode>`; subsequent lines follow:
//
//	<file>:<startL>.<startC>,<endL>.<endC> <nStmts> <count>
//
// We aggregate per file: statements-total sums nStmts; statements-hit
// sums nStmts for blocks with count > 0. LinesHit / LinesTotal are
// re-purposed to carry statement counts — the unit is whatever the
// profile emits and consumers should treat the field as "executable
// units covered / total executable units".
func ParseGoCoverprofile(r io.Reader) ([]domain.FileCoverage, error) {
	files := map[string]*domain.FileCoverage{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	first := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if first {
			first = false
			if strings.HasPrefix(line, "mode:") {
				continue
			}
			// Some tools omit the mode header; fall through.
		}

		// Split on spaces — path may contain dots but not spaces in
		// Go package paths.
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		spec := fields[0] // file.go:line.col,line.col
		nStmts, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		count, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		colon := strings.IndexByte(spec, ':')
		if colon < 0 {
			continue
		}
		path := spec[:colon]
		fc, ok := files[path]
		if !ok {
			fc = &domain.FileCoverage{Path: path}
			files[path] = fc
		}
		fc.LinesTotal += nStmts
		if count > 0 {
			fc.LinesHit += nStmts
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan coverprofile: %w", err)
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
