// Package usecase — Entry-point detection (§11.2).
//
// Entry points are the places where control enters a program: `main`
// functions, HTTP route handlers, CLI command hooks, worker loops,
// event handlers. They anchor the dependency graph — every execution
// path in a repository starts at one of these — so the node canvas
// colors them distinctly and the call-graph traversal starts here.
//
// This detector is regex + heuristic-driven. Tree-sitter produces
// richer ASTs but entry points live at predictable lexical locations
// per language/framework so regex parsing is enough for the 95% case
// and keeps this detector zero-dependency (no CGO, no grammar lookups).
package usecase

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/google/uuid"
)

// EntryPoint represents a single execution origin.
type EntryPoint struct {
	ID         uuid.UUID      `json:"id"`
	Kind       string         `json:"kind"` // main, http_route, event_handler, cli_command, worker
	Name       string         `json:"name"`
	SymbolID   string         `json:"symbol_id,omitempty"`
	FilePath   string         `json:"file_path"`
	LineNumber int            `json:"line_number"`
	Language   string         `json:"language,omitempty"`
	Framework  string         `json:"framework,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

// EntryPointStore is the persistence port. In production it wraps
// Postgres; tests pass an in-memory fake. A minimal interface keeps
// the detector itself free of DB concerns.
type EntryPointStore interface {
	Save(ctx context.Context, tenantID, repoID uuid.UUID, eps []EntryPoint) error
}

// EntryPointDetector walks a repository tree and surfaces every
// entry point it can recognize.
type EntryPointDetector struct {
	store EntryPointStore
	// maxFileBytes prevents a giant generated file from stalling the
	// regex pass. 256 KB covers typical Go/Python/Java files easily.
	maxFileBytes int64
}

// NewEntryPointDetector constructs a detector. Pass nil for store when
// you only need in-memory results (e.g. canvas preview, tests).
func NewEntryPointDetector(store EntryPointStore) *EntryPointDetector {
	return &EntryPointDetector{
		store:        store,
		maxFileBytes: 256 * 1024,
	}
}

// DetectEntryPoints walks the repo at rootPath, collects entry points,
// optionally persists them via the configured store, and returns them.
func (d *EntryPointDetector) DetectEntryPoints(ctx context.Context, tenantID, repoID uuid.UUID, rootPath string) ([]EntryPoint, error) {
	if rootPath == "" {
		return nil, fmt.Errorf("entry-point detector: rootPath required")
	}
	info, err := os.Stat(rootPath)
	if err != nil {
		return nil, fmt.Errorf("entry-point detector: stat: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("entry-point detector: %s is not a directory", rootPath)
	}

	var out []EntryPoint

	// package.json — Node bin + main fields surface as entry points
	// regardless of how the code itself is laid out.
	if body, err := os.ReadFile(filepath.Join(rootPath, "package.json")); err == nil {
		out = append(out, detectNodeManifestEntries(rootPath, body)...)
	}

	// Walk source files once per pass, collect language-specific matches.
	err = filepath.WalkDir(rootPath, func(path string, de fs.DirEntry, werr error) error {
		if werr != nil {
			if de != nil && de.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if de.IsDir() {
			switch de.Name() {
			case "node_modules", "vendor", ".git", "dist", "build", "target",
				"__pycache__", ".venv", "venv":
				return fs.SkipDir
			}
			return nil
		}
		if select_ := ctx.Err(); select_ != nil {
			return select_
		}

		fi, err := de.Info()
		if err != nil {
			return nil
		}
		if fi.Size() > d.maxFileBytes {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(rootPath, path)
		if err != nil {
			rel = path
		}

		ext := strings.ToLower(filepath.Ext(path))
		// Extensionless scripts under bin/ (typical for Ruby CLIs) still
		// look like entry points when they start with a shebang. Treat
		// them as .rb so the Ruby detector can decide.
		if ext == "" && (strings.HasPrefix(rel, "bin/") || strings.HasPrefix(rel, "bin\\")) {
			if len(body) > 2 && body[0] == '#' && body[1] == '!' {
				ext = ".rb"
			}
		}
		switch ext {
		case ".go":
			out = append(out, detectGoEntries(rel, body)...)
		case ".py":
			out = append(out, detectPythonEntries(rel, body)...)
		case ".java", ".kt":
			out = append(out, detectJavaEntries(rel, body)...)
		case ".rs":
			out = append(out, detectRustEntries(rel, body)...)
		case ".rb":
			out = append(out, detectRubyEntries(rel, body)...)
		case ".php":
			out = append(out, detectPHPEntries(rel, body)...)
		case ".cs":
			out = append(out, detectCSharpEntries(rel, body)...)
		case ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs":
			out = append(out, detectNodeSourceEntries(rel, body)...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	out = dedupEntryPoints(out)
	// Deterministic ordering so DB upserts don't thrash indexes.
	sort.Slice(out, func(i, j int) bool {
		if out[i].FilePath != out[j].FilePath {
			return out[i].FilePath < out[j].FilePath
		}
		if out[i].LineNumber != out[j].LineNumber {
			return out[i].LineNumber < out[j].LineNumber
		}
		return out[i].Name < out[j].Name
	})

	for i := range out {
		if out[i].ID == uuid.Nil {
			out[i].ID = uuid.New()
		}
	}

	if d.store != nil && len(out) > 0 {
		if err := d.store.Save(ctx, tenantID, repoID, out); err != nil {
			return out, fmt.Errorf("entry-point detector: save: %w", err)
		}
	}
	return out, nil
}

// --------------------- per-language detectors ------------------------

var reGoMain = regexp.MustCompile(`(?m)^\s*func\s+main\s*\(\s*\)\s*{`)
var reGoCobraCmd = regexp.MustCompile(`(?m)&cobra\.Command\s*{`)

func detectGoEntries(file string, body []byte) []EntryPoint {
	var out []EntryPoint
	// Only treat func main as a real entry point when the file
	// declares `package main`. Running on every file would emit
	// false positives for test helpers.
	if !regexp.MustCompile(`(?m)^\s*package\s+main\b`).Match(body) {
		// Still check for cobra commands below — CLI apps keep them in sub-packages.
	} else {
		if m := reGoMain.FindIndex(body); m != nil {
			out = append(out, EntryPoint{
				Kind:       "main",
				Name:       "main",
				FilePath:   file,
				LineNumber: lineAt(body, m[0]),
				Language:   "Go",
			})
		}
	}
	for _, m := range reGoCobraCmd.FindAllIndex(body, -1) {
		out = append(out, EntryPoint{
			Kind:       "cli_command",
			Name:       "cobra.Command",
			FilePath:   file,
			LineNumber: lineAt(body, m[0]),
			Language:   "Go",
			Framework:  "cobra",
		})
	}
	return out
}

var rePythonMain = regexp.MustCompile(`(?m)^\s*if\s+__name__\s*==\s*["']__main__["']\s*:`)
var rePythonClick = regexp.MustCompile(`(?m)^\s*@click\.(?:command|group)\b`)
var rePythonArgparse = regexp.MustCompile(`argparse\.ArgumentParser\s*\(`)
var rePythonRoute = regexp.MustCompile(`(?m)^\s*@(?:app|router)\.(get|post|put|patch|delete|route)\s*\(\s*["']([^"']+)["']`)

func detectPythonEntries(file string, body []byte) []EntryPoint {
	var out []EntryPoint
	if m := rePythonMain.FindIndex(body); m != nil {
		out = append(out, EntryPoint{
			Kind:       "main",
			Name:       "__main__",
			FilePath:   file,
			LineNumber: lineAt(body, m[0]),
			Language:   "Python",
		})
	}
	for _, m := range rePythonClick.FindAllIndex(body, -1) {
		out = append(out, EntryPoint{
			Kind:       "cli_command",
			Name:       "click",
			FilePath:   file,
			LineNumber: lineAt(body, m[0]),
			Language:   "Python",
			Framework:  "click",
		})
	}
	if m := rePythonArgparse.FindIndex(body); m != nil {
		out = append(out, EntryPoint{
			Kind:       "cli_command",
			Name:       "argparse",
			FilePath:   file,
			LineNumber: lineAt(body, m[0]),
			Language:   "Python",
			Framework:  "argparse",
		})
	}
	for _, m := range rePythonRoute.FindAllSubmatchIndex(body, -1) {
		method := string(body[m[2]:m[3]])
		path := string(body[m[4]:m[5]])
		out = append(out, EntryPoint{
			Kind:       "http_route",
			Name:       strings.ToUpper(method) + " " + path,
			FilePath:   file,
			LineNumber: lineAt(body, m[0]),
			Language:   "Python",
			Metadata:   map[string]any{"method": strings.ToUpper(method), "path": path},
		})
	}
	return out
}

var reJavaMain = regexp.MustCompile(`(?m)public\s+static\s+void\s+main\s*\(\s*String\s*(?:\[\]\s*\w+|\.{3}\s*\w+)\s*\)\s*(?:throws\s+[^\{]*)?{`)
var reSpringMapping = regexp.MustCompile(`(?m)^\s*@(?:Get|Post|Put|Patch|Delete|Request)Mapping\s*\(\s*["']?([^"')]*)`)

func detectJavaEntries(file string, body []byte) []EntryPoint {
	var out []EntryPoint
	if m := reJavaMain.FindIndex(body); m != nil {
		out = append(out, EntryPoint{
			Kind:       "main",
			Name:       "main",
			FilePath:   file,
			LineNumber: lineAt(body, m[0]),
			Language:   "Java",
		})
	}
	for _, m := range reSpringMapping.FindAllSubmatchIndex(body, -1) {
		path := string(body[m[2]:m[3]])
		out = append(out, EntryPoint{
			Kind:       "http_route",
			Name:       path,
			FilePath:   file,
			LineNumber: lineAt(body, m[0]),
			Language:   "Java",
			Framework:  "spring",
			Metadata:   map[string]any{"path": path},
		})
	}
	return out
}

var reRustMain = regexp.MustCompile(`(?m)^\s*fn\s+main\s*\(\s*\)`)
var reRustClap = regexp.MustCompile(`clap::(?:Parser|Command|Args)\b`)

func detectRustEntries(file string, body []byte) []EntryPoint {
	var out []EntryPoint
	if m := reRustMain.FindIndex(body); m != nil {
		out = append(out, EntryPoint{
			Kind:       "main",
			Name:       "main",
			FilePath:   file,
			LineNumber: lineAt(body, m[0]),
			Language:   "Rust",
		})
	}
	if m := reRustClap.FindIndex(body); m != nil {
		out = append(out, EntryPoint{
			Kind:       "cli_command",
			Name:       "clap",
			FilePath:   file,
			LineNumber: lineAt(body, m[0]),
			Language:   "Rust",
			Framework:  "clap",
		})
	}
	return out
}

var reRubyRails = regexp.MustCompile(`(?m)Rails\.application\.routes\.draw`)
var reRubySinatra = regexp.MustCompile(`(?m)^\s*(get|post|put|patch|delete)\s+["']([^"']+)["']`)
var reRubyThor = regexp.MustCompile(`<\s*Thor\b`)

func detectRubyEntries(file string, body []byte) []EntryPoint {
	var out []EntryPoint
	if filepath.Base(file) == "config.ru" || strings.HasPrefix(file, "bin/") || strings.HasPrefix(file, "bin\\") {
		out = append(out, EntryPoint{
			Kind:       "main",
			Name:       filepath.Base(file),
			FilePath:   file,
			LineNumber: 1,
			Language:   "Ruby",
		})
	}
	if m := reRubyRails.FindIndex(body); m != nil {
		out = append(out, EntryPoint{
			Kind:       "http_route",
			Name:       "rails routes",
			FilePath:   file,
			LineNumber: lineAt(body, m[0]),
			Language:   "Ruby",
			Framework:  "rails",
		})
	}
	for _, m := range reRubySinatra.FindAllSubmatchIndex(body, -1) {
		method := string(body[m[2]:m[3]])
		path := string(body[m[4]:m[5]])
		out = append(out, EntryPoint{
			Kind:       "http_route",
			Name:       strings.ToUpper(method) + " " + path,
			FilePath:   file,
			LineNumber: lineAt(body, m[0]),
			Language:   "Ruby",
			Framework:  "sinatra",
			Metadata:   map[string]any{"method": strings.ToUpper(method), "path": path},
		})
	}
	if m := reRubyThor.FindIndex(body); m != nil {
		out = append(out, EntryPoint{
			Kind:       "cli_command",
			Name:       "Thor",
			FilePath:   file,
			LineNumber: lineAt(body, m[0]),
			Language:   "Ruby",
			Framework:  "thor",
		})
	}
	return out
}

var rePHPRoute = regexp.MustCompile(`(?m)Route::(get|post|put|patch|delete)\s*\(\s*["']([^"']+)["']`)

func detectPHPEntries(file string, body []byte) []EntryPoint {
	var out []EntryPoint
	base := filepath.Base(file)
	if base == "index.php" && (strings.HasPrefix(file, "public/") || strings.HasPrefix(file, "public\\")) {
		out = append(out, EntryPoint{
			Kind:       "main",
			Name:       "public/index.php",
			FilePath:   file,
			LineNumber: 1,
			Language:   "PHP",
		})
	}
	for _, m := range rePHPRoute.FindAllSubmatchIndex(body, -1) {
		method := string(body[m[2]:m[3]])
		path := string(body[m[4]:m[5]])
		out = append(out, EntryPoint{
			Kind:       "http_route",
			Name:       strings.ToUpper(method) + " " + path,
			FilePath:   file,
			LineNumber: lineAt(body, m[0]),
			Language:   "PHP",
			Framework:  "laravel",
			Metadata:   map[string]any{"method": strings.ToUpper(method), "path": path},
		})
	}
	return out
}

var reCSharpMain = regexp.MustCompile(`(?m)(?:static\s+(?:async\s+)?(?:Task\s+)?)?void\s+Main\s*\(\s*(?:string\s*\[\]\s*\w+)?\s*\)`)
var reCSharpTopLevel = regexp.MustCompile(`(?m)WebApplication\.CreateBuilder\s*\(`)
var reCSharpMapGet = regexp.MustCompile(`(?m)app\.Map(Get|Post|Put|Patch|Delete)\s*\(\s*"([^"]+)"`)

func detectCSharpEntries(file string, body []byte) []EntryPoint {
	var out []EntryPoint
	if m := reCSharpMain.FindIndex(body); m != nil {
		out = append(out, EntryPoint{
			Kind:       "main",
			Name:       "Main",
			FilePath:   file,
			LineNumber: lineAt(body, m[0]),
			Language:   "C#",
		})
	}
	if filepath.Base(file) == "Program.cs" {
		if m := reCSharpTopLevel.FindIndex(body); m != nil {
			out = append(out, EntryPoint{
				Kind:       "main",
				Name:       "Program.cs",
				FilePath:   file,
				LineNumber: lineAt(body, m[0]),
				Language:   "C#",
				Framework:  "aspnet-core",
			})
		}
	}
	for _, m := range reCSharpMapGet.FindAllSubmatchIndex(body, -1) {
		method := string(body[m[2]:m[3]])
		path := string(body[m[4]:m[5]])
		out = append(out, EntryPoint{
			Kind:       "http_route",
			Name:       strings.ToUpper(method) + " " + path,
			FilePath:   file,
			LineNumber: lineAt(body, m[0]),
			Language:   "C#",
			Framework:  "aspnet-core",
			Metadata:   map[string]any{"method": strings.ToUpper(method), "path": path},
		})
	}
	return out
}

var reExpressRoute = regexp.MustCompile(`(?m)\b(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*["']([^"']+)["']`)
var reNestDecorator = regexp.MustCompile(`(?m)@(Get|Post|Put|Patch|Delete)\s*\(\s*(?:["']([^"']*)["'])?\s*\)`)

func detectNodeSourceEntries(file string, body []byte) []EntryPoint {
	var out []EntryPoint
	for _, m := range reExpressRoute.FindAllSubmatchIndex(body, -1) {
		method := string(body[m[2]:m[3]])
		path := string(body[m[4]:m[5]])
		out = append(out, EntryPoint{
			Kind:       "http_route",
			Name:       strings.ToUpper(method) + " " + path,
			FilePath:   file,
			LineNumber: lineAt(body, m[0]),
			Language:   "TypeScript",
			Framework:  "express",
			Metadata:   map[string]any{"method": strings.ToUpper(method), "path": path},
		})
	}
	for _, m := range reNestDecorator.FindAllSubmatchIndex(body, -1) {
		method := string(body[m[2]:m[3]])
		path := ""
		if m[4] >= 0 {
			path = string(body[m[4]:m[5]])
		}
		out = append(out, EntryPoint{
			Kind:       "http_route",
			Name:       strings.ToUpper(method) + " " + path,
			FilePath:   file,
			LineNumber: lineAt(body, m[0]),
			Language:   "TypeScript",
			Framework:  "nestjs",
			Metadata:   map[string]any{"method": strings.ToUpper(method), "path": path},
		})
	}
	return out
}

// detectNodeManifestEntries maps `main` and `bin` fields in package.json
// onto `main` / `cli_command` entries so Node apps surface their
// canonical launch script regardless of source layout.
func detectNodeManifestEntries(root string, body []byte) []EntryPoint {
	var pkg struct {
		Name string          `json:"name"`
		Main string          `json:"main"`
		Bin  json.RawMessage `json:"bin"`
	}
	if err := json.Unmarshal(body, &pkg); err != nil {
		return nil
	}
	var out []EntryPoint
	if pkg.Main != "" {
		out = append(out, EntryPoint{
			Kind:       "main",
			Name:       pkg.Main,
			FilePath:   pkg.Main,
			LineNumber: 1,
			Language:   "TypeScript",
			Metadata:   map[string]any{"source": "package.json:main"},
		})
	}
	// bin can be a string ("./cli.js") or an object ({"name":"./cli.js"}).
	if len(pkg.Bin) > 0 {
		var single string
		if err := json.Unmarshal(pkg.Bin, &single); err == nil && single != "" {
			name := pkg.Name
			if name == "" {
				name = filepath.Base(single)
			}
			out = append(out, EntryPoint{
				Kind:       "cli_command",
				Name:       name,
				FilePath:   single,
				LineNumber: 1,
				Language:   "TypeScript",
				Metadata:   map[string]any{"source": "package.json:bin"},
			})
		} else {
			var bins map[string]string
			if err := json.Unmarshal(pkg.Bin, &bins); err == nil {
				for name, p := range bins {
					out = append(out, EntryPoint{
						Kind:       "cli_command",
						Name:       name,
						FilePath:   p,
						LineNumber: 1,
						Language:   "TypeScript",
						Metadata:   map[string]any{"source": "package.json:bin"},
					})
				}
			}
		}
	}
	_ = root
	return out
}

// --------------------------- helpers ---------------------------------

// lineAt converts a byte offset into a 1-indexed line number.
func lineAt(body []byte, off int) int {
	line := 1
	if off > len(body) {
		off = len(body)
	}
	for i := 0; i < off; i++ {
		if body[i] == '\n' {
			line++
		}
	}
	return line
}

// dedupEntryPoints collapses exact duplicates so upserts into the
// unique index (kind, file, line, name) don't raise conflicts.
func dedupEntryPoints(in []EntryPoint) []EntryPoint {
	seen := map[string]struct{}{}
	out := make([]EntryPoint, 0, len(in))
	for _, ep := range in {
		key := ep.Kind + "|" + ep.FilePath + "|" + fmt.Sprintf("%d", ep.LineNumber) + "|" + ep.Name
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, ep)
	}
	return out
}
