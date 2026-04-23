package usecase

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// =============================================================================
// B10 — Framework detection (§11.2)
// =============================================================================
//
// Framework detection is a best-effort, offline pass over a project tree.
// We inspect manifest files (package.json, requirements.txt, pyproject.toml,
// go.mod) *and* verify the framework is actually imported somewhere under
// the project root. That second step avoids tagging a project as "express"
// when a transitive dependency pulled it in but the code doesn't use it.
//
// The detector is intentionally rule-driven rather than AST-heavy: SCIP /
// tree-sitter passes already live elsewhere in the service, and this
// annotation pass runs during the cheap ingestion phase. We emit a
// confidence score in [0, 1] based on how many signals fired.
//
// Language ownership:
//   - JS/TS, Python, Go — full rules (Express, Next, React, Vue, Nest, Fastify,
//     Django, Flask, FastAPI, Gin, Chi, Echo, net/http).
//   - Rust — Actix-web, Axum, Rocket, Warp.
//   - Java/Kotlin — Spring, Micronaut, Quarkus.
//   - Ruby — Rails, Sinatra.
//   - PHP — Laravel, Symfony.
//   - C# — ASP.NET Core, .NET minimal APIs.

// DetectedFramework is the analysis-output shape. Confidence is a blend
// of dependency-manifest presence (0.5) and import/usage evidence (0.5).
// EvidenceFiles contains up to 8 project-relative paths that contributed.
type DetectedFramework struct {
	Name          string   `json:"name"`
	Language      string   `json:"language"`
	Version       string   `json:"version,omitempty"`
	Confidence    float64  `json:"confidence"`
	EvidenceFiles []string `json:"evidence_files,omitempty"`
}

// frameworkRule encodes the fingerprint for a single framework. The
// detector iterates all rules against every in-scope project root and
// collects the ones that fire.
type frameworkRule struct {
	Name     string
	Language string
	// ManifestDeps is the set of dependency names (as they appear in
	// package.json / requirements.txt / pyproject.toml / go.mod) that
	// indicate this framework is declared. Matching any one is enough.
	ManifestDeps []string
	// ImportPatterns is a compiled regex that, when matched against
	// source files of this language, indicates live usage. The first
	// submatch, if present, is treated as the version capture (rarely
	// useful for imports but kept for symmetry with manifest parsing).
	ImportPatterns []*regexp.Regexp
	// SourceExts constrains which files we scan for ImportPatterns —
	// scanning every file in a monorepo would blow past our time budget.
	SourceExts []string
}

func builtInFrameworkRules() []frameworkRule {
	return []frameworkRule{
		// --- JavaScript / TypeScript -----------------------------------
		{
			Name: "express", Language: "javascript",
			ManifestDeps:   []string{"express"},
			SourceExts:     []string{".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"},
			ImportPatterns: []*regexp.Regexp{regexp.MustCompile(`['"]express['"]`)},
		},
		{
			Name: "next", Language: "javascript",
			ManifestDeps:   []string{"next"},
			SourceExts:     []string{".js", ".mjs", ".ts", ".tsx", ".jsx"},
			ImportPatterns: []*regexp.Regexp{regexp.MustCompile(`['"]next(?:/[\w\-]+)?['"]`)},
		},
		{
			Name: "react", Language: "javascript",
			ManifestDeps:   []string{"react"},
			SourceExts:     []string{".js", ".jsx", ".ts", ".tsx"},
			ImportPatterns: []*regexp.Regexp{regexp.MustCompile(`['"]react(?:/[\w\-]+)?['"]`)},
		},
		{
			Name: "vue", Language: "javascript",
			ManifestDeps:   []string{"vue"},
			SourceExts:     []string{".js", ".ts", ".vue"},
			ImportPatterns: []*regexp.Regexp{regexp.MustCompile(`['"]vue['"]`)},
		},
		{
			Name: "nestjs", Language: "javascript",
			ManifestDeps:   []string{"@nestjs/core", "@nestjs/common"},
			SourceExts:     []string{".ts", ".js"},
			ImportPatterns: []*regexp.Regexp{regexp.MustCompile(`['"]@nestjs/(?:core|common)['"]`)},
		},
		{
			Name: "fastify", Language: "javascript",
			ManifestDeps:   []string{"fastify"},
			SourceExts:     []string{".js", ".mjs", ".ts"},
			ImportPatterns: []*regexp.Regexp{regexp.MustCompile(`['"]fastify['"]`)},
		},

		// --- Python ----------------------------------------------------
		{
			Name: "django", Language: "python",
			ManifestDeps:   []string{"django", "Django"},
			SourceExts:     []string{".py"},
			ImportPatterns: []*regexp.Regexp{regexp.MustCompile(`(?m)^\s*(?:from|import)\s+django\b`)},
		},
		{
			Name: "flask", Language: "python",
			ManifestDeps: []string{"flask", "Flask"},
			SourceExts:   []string{".py"},
			ImportPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?m)^\s*(?:from|import)\s+flask\b`),
				regexp.MustCompile(`(?m)^\s*@app\.route\b`),
			},
		},
		{
			Name: "fastapi", Language: "python",
			ManifestDeps: []string{"fastapi"},
			SourceExts:   []string{".py"},
			ImportPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?m)^\s*(?:from|import)\s+fastapi\b`),
				regexp.MustCompile(`(?m)^\s*@(?:app|router)\.(?:get|post|put|patch|delete)\b`),
			},
		},

		// --- Go --------------------------------------------------------
		{
			Name: "gin", Language: "go",
			ManifestDeps:   []string{"github.com/gin-gonic/gin"},
			SourceExts:     []string{".go"},
			ImportPatterns: []*regexp.Regexp{regexp.MustCompile(`"github\.com/gin-gonic/gin"`)},
		},
		{
			Name: "chi", Language: "go",
			ManifestDeps:   []string{"github.com/go-chi/chi"},
			SourceExts:     []string{".go"},
			ImportPatterns: []*regexp.Regexp{regexp.MustCompile(`"github\.com/go-chi/chi(?:/v\d+)?"`)},
		},
		{
			Name: "echo", Language: "go",
			ManifestDeps:   []string{"github.com/labstack/echo"},
			SourceExts:     []string{".go"},
			ImportPatterns: []*regexp.Regexp{regexp.MustCompile(`"github\.com/labstack/echo(?:/v\d+)?"`)},
		},
		{
			Name: "net/http", Language: "go",
			// net/http is stdlib: there's no go.mod line for it, so we
			// rely solely on import presence. Manifest deps left empty
			// and we weight the import evidence to full confidence.
			SourceExts:     []string{".go"},
			ImportPatterns: []*regexp.Regexp{regexp.MustCompile(`"net/http"`)},
		},

		// --- Rust ------------------------------------------------------
		{
			Name: "actix-web", Language: "rust",
			ManifestDeps:   []string{"actix-web"},
			SourceExts:     []string{".rs"},
			ImportPatterns: []*regexp.Regexp{regexp.MustCompile(`(?m)use\s+actix_web`)},
		},
		{
			Name: "axum", Language: "rust",
			ManifestDeps:   []string{"axum"},
			SourceExts:     []string{".rs"},
			ImportPatterns: []*regexp.Regexp{regexp.MustCompile(`(?m)use\s+axum`)},
		},
		{
			Name: "rocket", Language: "rust",
			ManifestDeps:   []string{"rocket"},
			SourceExts:     []string{".rs"},
			ImportPatterns: []*regexp.Regexp{regexp.MustCompile(`(?m)use\s+rocket`)},
		},
		{
			Name: "warp", Language: "rust",
			ManifestDeps:   []string{"warp"},
			SourceExts:     []string{".rs"},
			ImportPatterns: []*regexp.Regexp{regexp.MustCompile(`(?m)use\s+warp`)},
		},

		// --- Java / Kotlin ---------------------------------------------
		{
			Name: "spring-boot", Language: "java",
			ManifestDeps: []string{"spring-boot-starter", "org.springframework.boot:spring-boot-starter"},
			SourceExts:   []string{".java", ".kt"},
			ImportPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?m)^\s*import\s+org\.springframework\.boot`),
				regexp.MustCompile(`@SpringBootApplication\b`),
			},
		},
		{
			Name: "spring", Language: "java",
			ManifestDeps:   []string{"spring-core", "org.springframework:spring-core", "spring-web"},
			SourceExts:     []string{".java", ".kt"},
			ImportPatterns: []*regexp.Regexp{regexp.MustCompile(`(?m)^\s*import\s+org\.springframework\b`)},
		},
		{
			Name: "micronaut", Language: "java",
			ManifestDeps:   []string{"micronaut-core", "io.micronaut:micronaut-core"},
			SourceExts:     []string{".java", ".kt"},
			ImportPatterns: []*regexp.Regexp{regexp.MustCompile(`(?m)^\s*import\s+io\.micronaut`)},
		},
		{
			Name: "quarkus", Language: "java",
			ManifestDeps:   []string{"quarkus-core", "io.quarkus:quarkus-core"},
			SourceExts:     []string{".java", ".kt"},
			ImportPatterns: []*regexp.Regexp{regexp.MustCompile(`(?m)^\s*import\s+io\.quarkus`)},
		},

		// --- Ruby ------------------------------------------------------
		{
			Name: "rails", Language: "ruby",
			ManifestDeps:   []string{"rails"},
			SourceExts:     []string{".rb"},
			ImportPatterns: []*regexp.Regexp{regexp.MustCompile(`(?m)(?:^|\s)(?:require\s+['"]rails|Rails\.application)`)},
		},
		{
			Name: "sinatra", Language: "ruby",
			ManifestDeps:   []string{"sinatra"},
			SourceExts:     []string{".rb"},
			ImportPatterns: []*regexp.Regexp{regexp.MustCompile(`(?m)require\s+['"]sinatra['"]`)},
		},

		// --- PHP -------------------------------------------------------
		{
			Name: "laravel", Language: "php",
			ManifestDeps:   []string{"laravel/framework"},
			SourceExts:     []string{".php"},
			ImportPatterns: []*regexp.Regexp{regexp.MustCompile(`(?m)use\s+Illuminate\\`)},
		},
		{
			Name: "symfony", Language: "php",
			ManifestDeps:   []string{"symfony/framework-bundle", "symfony/http-foundation"},
			SourceExts:     []string{".php"},
			ImportPatterns: []*regexp.Regexp{regexp.MustCompile(`(?m)use\s+Symfony\\`)},
		},

		// --- C# / .NET -------------------------------------------------
		{
			Name: "aspnet-core", Language: "csharp",
			ManifestDeps: []string{"Microsoft.AspNetCore", "Microsoft.AspNetCore.App"},
			SourceExts:   []string{".cs"},
			ImportPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?m)using\s+Microsoft\.AspNetCore`),
				regexp.MustCompile(`WebApplication\.CreateBuilder\b`),
			},
		},
		{
			Name: "dotnet", Language: "csharp",
			ManifestDeps:   []string{"Microsoft.NET.Sdk"},
			SourceExts:     []string{".cs"},
			ImportPatterns: []*regexp.Regexp{regexp.MustCompile(`(?m)using\s+System\b`)},
		},
	}
}

// FrameworkDetector scans a project tree and emits the frameworks that
// fingerprint it. The zero value is ready to use; tests can inject
// custom rules via WithRules for coverage of extensible stubs.
type FrameworkDetector struct {
	rules []frameworkRule
	// maxFilesPerExt caps the number of source files we scan per
	// extension. 400 is enough to catch real imports without getting
	// trapped in vendored copies of libraries.
	maxFilesPerExt int
}

func NewFrameworkDetector() *FrameworkDetector {
	return &FrameworkDetector{
		rules:          builtInFrameworkRules(),
		maxFilesPerExt: 400,
	}
}

// WithRules replaces the rule set. Intended for tests and for plugging
// in Java / Ruby stubs from a config file later.
func (d *FrameworkDetector) WithRules(rules []frameworkRule) *FrameworkDetector {
	d.rules = rules
	return d
}

// Detect walks root once, collects manifest + source evidence, then
// scores each rule. It returns one DetectedFramework per rule that
// fired at least one signal, sorted by confidence desc / name asc.
func (d *FrameworkDetector) Detect(root string) ([]DetectedFramework, error) {
	if d == nil {
		d = NewFrameworkDetector()
	}
	if root == "" {
		return nil, fmt.Errorf("framework detector: root path required")
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("framework detector: stat %s: %w", root, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("framework detector: %s is not a directory", root)
	}

	// Pass 1 — walk the tree once, collecting manifest bodies and a
	// bucketed list of source files per extension.
	manifests := map[string][]byte{}
	sourcesByExt := map[string][]string{}
	if err := filepath.WalkDir(root, func(path string, de fs.DirEntry, werr error) error {
		if werr != nil {
			// Permission errors on a single sub-tree shouldn't kill
			// the whole scan; skip and continue.
			if de != nil && de.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if de.IsDir() {
			name := de.Name()
			// Skip obvious noise directories that inflate scan time
			// without adding signal.
			switch name {
			case "node_modules", "vendor", ".git", "dist", "build", "target", "__pycache__", ".venv", "venv":
				return fs.SkipDir
			}
			return nil
		}
		name := de.Name()
		ext := strings.ToLower(filepath.Ext(name))
		switch name {
		case "package.json", "requirements.txt", "pyproject.toml", "go.mod",
			"Cargo.toml", "Gemfile", "composer.json", "pom.xml", "build.gradle",
			"build.gradle.kts":
			b, rerr := os.ReadFile(path)
			if rerr == nil {
				manifests[name] = b
			}
		}
		// .csproj files are scanned generically to capture all project files.
		if ext == ".csproj" {
			b, rerr := os.ReadFile(path)
			if rerr == nil {
				// Concatenate all .csproj bodies so a single key holds them all.
				manifests["_csproj"] = append(manifests["_csproj"], b...)
				manifests["_csproj"] = append(manifests["_csproj"], '\n')
			}
		}
		if ext != "" {
			sourcesByExt[ext] = append(sourcesByExt[ext], path)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	// Pass 2 — parse manifests into name→version maps. Missing
	// manifests yield empty maps; downstream rules treat that as "no
	// manifest evidence" rather than an error.
	jsDeps := parsePackageJSONDeps(manifests["package.json"])
	pyDeps := mergeDepMaps(
		parseRequirementsTxt(manifests["requirements.txt"]),
		parsePyProjectTOML(manifests["pyproject.toml"]),
	)
	goDeps := parseGoMod(manifests["go.mod"])
	rustDeps := parseCargoToml(manifests["Cargo.toml"])
	javaDeps := mergeDepMaps(
		parsePomXML(manifests["pom.xml"]),
		mergeDepMaps(
			parseGradle(manifests["build.gradle"]),
			parseGradle(manifests["build.gradle.kts"]),
		),
	)
	rubyDeps := parseGemfile(manifests["Gemfile"])
	phpDeps := parseComposerJSON(manifests["composer.json"])
	csDeps := parseCsproj(manifests["_csproj"])

	// Pass 3 — evaluate rules. Each rule contributes manifest evidence
	// (0.5 if any declared dep matched) plus source evidence (up to 0.5
	// based on how many scanned files matched any import pattern).
	results := make([]DetectedFramework, 0, len(d.rules))
	for _, rule := range d.rules {
		var manifestHit bool
		var version string
		var evidence []string

		switch rule.Language {
		case "javascript":
			for _, dep := range rule.ManifestDeps {
				if v, ok := jsDeps[dep]; ok {
					manifestHit = true
					if version == "" {
						version = v
					}
				}
			}
			if manifestHit {
				evidence = append(evidence, "package.json")
			}
		case "python":
			for _, dep := range rule.ManifestDeps {
				if v, ok := pyDeps[strings.ToLower(dep)]; ok {
					manifestHit = true
					if version == "" {
						version = v
					}
				}
			}
			if manifestHit {
				if _, ok := manifests["pyproject.toml"]; ok {
					evidence = append(evidence, "pyproject.toml")
				} else {
					evidence = append(evidence, "requirements.txt")
				}
			}
		case "go":
			// Go modules frequently carry a /vN suffix (chi/v5, echo/v4).
			// Match by prefix so the rule doesn't have to enumerate
			// every major version.
			for _, dep := range rule.ManifestDeps {
				for mod, v := range goDeps {
					if mod == dep || strings.HasPrefix(mod, dep+"/v") {
						manifestHit = true
						if version == "" {
							version = v
						}
						break
					}
				}
			}
			if manifestHit {
				evidence = append(evidence, "go.mod")
			}
		case "rust":
			for _, dep := range rule.ManifestDeps {
				if v, ok := rustDeps[dep]; ok {
					manifestHit = true
					if version == "" {
						version = v
					}
				}
			}
			if manifestHit {
				evidence = append(evidence, "Cargo.toml")
			}
		case "java":
			for _, dep := range rule.ManifestDeps {
				if v, ok := javaDeps[dep]; ok {
					manifestHit = true
					if version == "" {
						version = v
					}
				}
				// Artifact-only lookup (the `artifactId` without group).
				if idx := strings.LastIndex(dep, ":"); idx >= 0 {
					if v, ok := javaDeps[dep[idx+1:]]; ok {
						manifestHit = true
						if version == "" {
							version = v
						}
					}
				}
			}
			if manifestHit {
				evidence = append(evidence, "pom.xml/build.gradle")
			}
		case "ruby":
			for _, dep := range rule.ManifestDeps {
				if v, ok := rubyDeps[dep]; ok {
					manifestHit = true
					if version == "" {
						version = v
					}
				}
			}
			if manifestHit {
				evidence = append(evidence, "Gemfile")
			}
		case "php":
			for _, dep := range rule.ManifestDeps {
				if v, ok := phpDeps[dep]; ok {
					manifestHit = true
					if version == "" {
						version = v
					}
				}
			}
			if manifestHit {
				evidence = append(evidence, "composer.json")
			}
		case "csharp":
			for _, dep := range rule.ManifestDeps {
				// csDeps keys are PackageReference Include="..." values.
				for k, v := range csDeps {
					if strings.EqualFold(k, dep) || strings.HasPrefix(k, dep) {
						manifestHit = true
						if version == "" {
							version = v
						}
						break
					}
				}
			}
			if manifestHit {
				evidence = append(evidence, "*.csproj")
			}
		}

		sourceHits, sourceEvidence := d.scanSources(root, rule, sourcesByExt)
		evidence = append(evidence, sourceEvidence...)

		// Deduplicate + cap evidence list so the API response stays
		// bounded regardless of monorepo size.
		evidence = dedupCapped(evidence, 8)

		confidence := 0.0
		if manifestHit {
			confidence += 0.5
		}
		if sourceHits > 0 {
			// Saturation curve: 1 hit → 0.25, 3 → 0.375, 10 → ~0.45.
			// Tuned so a single confirmed import + manifest lands at
			// 0.75 (our "confident" threshold in downstream consumers).
			confidence += 0.5 * saturate(float64(sourceHits), 1.0)
		}
		// Stdlib net/http has no manifest; promote pure-source evidence
		// so it still lands at reasonable confidence.
		if len(rule.ManifestDeps) == 0 && sourceHits > 0 {
			confidence = 0.5 + 0.5*saturate(float64(sourceHits), 1.0)
		}
		if confidence <= 0 {
			continue
		}

		results = append(results, DetectedFramework{
			Name:          rule.Name,
			Language:      rule.Language,
			Version:       version,
			Confidence:    roundTo(confidence, 2),
			EvidenceFiles: evidence,
		})
	}

	// Deterministic ordering helps consumers (tests, UI diff) stay stable.
	sort.Slice(results, func(i, j int) bool {
		if results[i].Confidence != results[j].Confidence {
			return results[i].Confidence > results[j].Confidence
		}
		return results[i].Name < results[j].Name
	})
	return results, nil
}

// scanSources reads up to maxFilesPerExt files per configured extension
// and counts matches of the rule's ImportPatterns. We stop reading the
// file at the first match to keep IO bounded.
func (d *FrameworkDetector) scanSources(root string, rule frameworkRule, sourcesByExt map[string][]string) (int, []string) {
	if len(rule.ImportPatterns) == 0 || len(rule.SourceExts) == 0 {
		return 0, nil
	}
	hits := 0
	var evidence []string
	for _, ext := range rule.SourceExts {
		files := sourcesByExt[ext]
		if len(files) == 0 {
			continue
		}
		limit := len(files)
		if limit > d.maxFilesPerExt {
			limit = d.maxFilesPerExt
		}
		for i := 0; i < limit; i++ {
			body, err := os.ReadFile(files[i])
			if err != nil {
				continue
			}
			for _, pat := range rule.ImportPatterns {
				if pat.Match(body) {
					hits++
					rel, rerr := filepath.Rel(root, files[i])
					if rerr != nil {
						rel = files[i]
					}
					evidence = append(evidence, rel)
					break
				}
			}
		}
	}
	return hits, evidence
}

// =============================================================================
// Manifest parsers — intentionally permissive: unknown shapes degrade to
// "no deps" instead of failing the whole scan.
// =============================================================================

// parsePackageJSONDeps flattens dependencies / devDependencies /
// peerDependencies into a single map so downstream rules don't care
// which bucket the dep lives in.
func parsePackageJSONDeps(body []byte) map[string]string {
	out := map[string]string{}
	if len(body) == 0 {
		return out
	}
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
		PeerDeps        map[string]string `json:"peerDependencies"`
	}
	if err := json.Unmarshal(body, &pkg); err != nil {
		return out
	}
	for k, v := range pkg.Dependencies {
		out[k] = v
	}
	for k, v := range pkg.DevDependencies {
		if _, ok := out[k]; !ok {
			out[k] = v
		}
	}
	for k, v := range pkg.PeerDeps {
		if _, ok := out[k]; !ok {
			out[k] = v
		}
	}
	return out
}

// parseRequirementsTxt handles the common shapes: `pkg==1.2.3`,
// `pkg>=1`, comments, and blank lines. Keys are lower-cased to match
// the pyDeps lookup convention.
func parseRequirementsTxt(body []byte) map[string]string {
	out := map[string]string{}
	if len(body) == 0 {
		return out
	}
	for _, raw := range strings.Split(string(body), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip inline comments.
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		// Ignore pip flags like -r requirements-dev.txt.
		if strings.HasPrefix(line, "-") {
			continue
		}
		name, version := splitPythonDep(line)
		if name == "" {
			continue
		}
		out[strings.ToLower(name)] = version
	}
	return out
}

// parsePyProjectTOML is a best-effort extractor that understands the
// two common shapes in the wild: PEP 621 [project] dependencies and
// Poetry [tool.poetry.dependencies]. We intentionally avoid pulling in
// a TOML dependency — a simple line scanner covers the 95% case.
func parsePyProjectTOML(body []byte) map[string]string {
	out := map[string]string{}
	if len(body) == 0 {
		return out
	}
	lines := strings.Split(string(body), "\n")
	section := ""
	inDepsArray := false
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			inDepsArray = false
			continue
		}

		// PEP 621: dependencies = ["django>=4", "flask"]
		if section == "project" && strings.HasPrefix(line, "dependencies") {
			inDepsArray = true
			// Handle same-line closure.
			if idx := strings.Index(line, "["); idx >= 0 {
				rest := line[idx+1:]
				if end := strings.Index(rest, "]"); end >= 0 {
					parsePyDepsArray(rest[:end], out)
					inDepsArray = false
					continue
				}
				parsePyDepsArray(rest, out)
			}
			continue
		}
		if inDepsArray {
			if idx := strings.Index(line, "]"); idx >= 0 {
				parsePyDepsArray(line[:idx], out)
				inDepsArray = false
				continue
			}
			parsePyDepsArray(line, out)
			continue
		}

		// Poetry: [tool.poetry.dependencies]\nfoo = "^1.2"
		if section == "tool.poetry.dependencies" {
			if eq := strings.Index(line, "="); eq > 0 {
				name := strings.TrimSpace(line[:eq])
				version := strings.Trim(strings.TrimSpace(line[eq+1:]), `"'`)
				if name != "" && name != "python" {
					out[strings.ToLower(name)] = version
				}
			}
		}
	}
	return out
}

func parsePyDepsArray(chunk string, out map[string]string) {
	for _, raw := range strings.Split(chunk, ",") {
		dep := strings.Trim(strings.TrimSpace(raw), `"'`)
		if dep == "" {
			continue
		}
		name, version := splitPythonDep(dep)
		if name == "" {
			continue
		}
		out[strings.ToLower(name)] = version
	}
}

// splitPythonDep handles `name==1.2`, `name>=1`, `name[extra]==1`, `name`.
func splitPythonDep(dep string) (string, string) {
	dep = strings.TrimSpace(dep)
	// Strip extras, e.g. uvicorn[standard].
	if b := strings.Index(dep, "["); b >= 0 {
		if e := strings.Index(dep, "]"); e > b {
			dep = dep[:b] + dep[e+1:]
		}
	}
	specifiers := []string{"==", ">=", "<=", "~=", "!=", ">", "<"}
	for _, s := range specifiers {
		if idx := strings.Index(dep, s); idx > 0 {
			return strings.TrimSpace(dep[:idx]), strings.TrimSpace(dep[idx+len(s):])
		}
	}
	return strings.TrimSpace(dep), ""
}

// parseGoMod extracts module paths from both `require (...)` blocks and
// single-line `require path version` forms. Versions are kept verbatim.
func parseGoMod(body []byte) map[string]string {
	out := map[string]string{}
	if len(body) == 0 {
		return out
	}
	text := string(body)
	// Block form.
	reBlock := regexp.MustCompile(`(?s)require\s*\((.*?)\)`)
	for _, m := range reBlock.FindAllStringSubmatch(text, -1) {
		for _, line := range strings.Split(m[1], "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "//") {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				out[parts[0]] = parts[1]
			}
		}
	}
	// Single-line form, e.g. `require github.com/foo/bar v1.2.3`.
	// We exclude the block-header case where the capture would be `(`.
	reLine := regexp.MustCompile(`(?m)^\s*require\s+([^\s(][^\s]*)\s+(\S+)`)
	for _, m := range reLine.FindAllStringSubmatch(text, -1) {
		out[m[1]] = m[2]
	}
	return out
}

// parseCargoToml extracts [dependencies] / [dev-dependencies] entries
// from a Cargo.toml body. Values can be either `name = "x.y.z"` or the
// inline-table form `name = { version = "x.y.z", ... }` — both yield
// the version string.
func parseCargoToml(body []byte) map[string]string {
	out := map[string]string{}
	if len(body) == 0 {
		return out
	}
	section := ""
	for _, raw := range strings.Split(string(body), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			continue
		}
		if section != "dependencies" && section != "dev-dependencies" &&
			section != "build-dependencies" {
			continue
		}
		eq := strings.Index(line, "=")
		if eq <= 0 {
			continue
		}
		name := strings.TrimSpace(line[:eq])
		rest := strings.TrimSpace(line[eq+1:])
		version := ""
		if strings.HasPrefix(rest, "{") {
			// Inline table: pull the version field if present.
			if v := extractTomlInlineValue(rest, "version"); v != "" {
				version = v
			}
		} else {
			version = strings.Trim(rest, `"'`)
		}
		if name != "" {
			out[name] = version
		}
	}
	return out
}

func extractTomlInlineValue(inline, key string) string {
	// Crude: find `key = "value"` within the inline table.
	idx := strings.Index(inline, key+" = ")
	if idx < 0 {
		idx = strings.Index(inline, key+"=")
		if idx < 0 {
			return ""
		}
	}
	rest := inline[idx+len(key):]
	// Skip `=`, whitespace.
	for i := 0; i < len(rest); i++ {
		if rest[i] == '=' || rest[i] == ' ' || rest[i] == '\t' {
			continue
		}
		rest = rest[i:]
		break
	}
	if len(rest) == 0 || (rest[0] != '"' && rest[0] != '\'') {
		return ""
	}
	quote := rest[0]
	rest = rest[1:]
	for i := 0; i < len(rest); i++ {
		if rest[i] == quote {
			return rest[:i]
		}
	}
	return ""
}

// parseGemfile pulls `gem "name", "version"` lines. Ignores comments,
// groups, source, ruby directives.
func parseGemfile(body []byte) map[string]string {
	out := map[string]string{}
	if len(body) == 0 {
		return out
	}
	re := regexp.MustCompile(`(?m)^\s*gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]*)['"])?`)
	for _, m := range re.FindAllStringSubmatch(string(body), -1) {
		name := m[1]
		version := ""
		if len(m) > 2 {
			version = m[2]
		}
		out[name] = version
	}
	return out
}

// parseComposerJSON mirrors parsePackageJSONDeps for Composer.
func parseComposerJSON(body []byte) map[string]string {
	out := map[string]string{}
	if len(body) == 0 {
		return out
	}
	var pkg struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	if err := json.Unmarshal(body, &pkg); err != nil {
		return out
	}
	for k, v := range pkg.Require {
		out[k] = v
	}
	for k, v := range pkg.RequireDev {
		if _, ok := out[k]; !ok {
			out[k] = v
		}
	}
	return out
}

// parsePomXML extracts <dependency><groupId>…</groupId><artifactId>…</artifactId><version>…</version></dependency>
// entries. Stores both under fully-qualified `group:artifact` and the
// bare artifact name so lookups can match either.
func parsePomXML(body []byte) map[string]string {
	out := map[string]string{}
	if len(body) == 0 {
		return out
	}
	// Simple regex scan — avoids XML lib for a 95% solution.
	re := regexp.MustCompile(`(?s)<dependency>(.*?)</dependency>`)
	gi := regexp.MustCompile(`<groupId>([^<]+)</groupId>`)
	ai := regexp.MustCompile(`<artifactId>([^<]+)</artifactId>`)
	vi := regexp.MustCompile(`<version>([^<]+)</version>`)
	for _, m := range re.FindAllStringSubmatch(string(body), -1) {
		chunk := m[1]
		g := ""
		a := ""
		v := ""
		if mg := gi.FindStringSubmatch(chunk); len(mg) > 1 {
			g = strings.TrimSpace(mg[1])
		}
		if ma := ai.FindStringSubmatch(chunk); len(ma) > 1 {
			a = strings.TrimSpace(ma[1])
		}
		if mv := vi.FindStringSubmatch(chunk); len(mv) > 1 {
			v = strings.TrimSpace(mv[1])
		}
		if a != "" {
			out[a] = v
			if g != "" {
				out[g+":"+a] = v
			}
		}
	}
	return out
}

// parseGradle extracts `implementation "group:artifact:version"` style
// dependency declarations. Supports Groovy + Kotlin DSL.
func parseGradle(body []byte) map[string]string {
	out := map[string]string{}
	if len(body) == 0 {
		return out
	}
	re := regexp.MustCompile(`(?m)(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*[(]?\s*["']([^"']+)["']`)
	for _, m := range re.FindAllStringSubmatch(string(body), -1) {
		ga := m[1]
		parts := strings.Split(ga, ":")
		if len(parts) >= 2 {
			artifact := parts[1]
			version := ""
			if len(parts) >= 3 {
				version = parts[2]
			}
			out[artifact] = version
			out[parts[0]+":"+parts[1]] = version
		}
	}
	return out
}

// parseCsproj scans <PackageReference Include="..." Version="..." /> entries.
func parseCsproj(body []byte) map[string]string {
	out := map[string]string{}
	if len(body) == 0 {
		return out
	}
	re := regexp.MustCompile(`<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"`)
	for _, m := range re.FindAllStringSubmatch(string(body), -1) {
		out[m[1]] = m[2]
	}
	// Sdk="Microsoft.NET.Sdk" → treat as a dep marker so framework rules fire.
	sdk := regexp.MustCompile(`<Project\s+Sdk="([^"]+)"`)
	for _, m := range sdk.FindAllStringSubmatch(string(body), -1) {
		out[m[1]] = ""
	}
	return out
}

// =============================================================================
// Helpers
// =============================================================================

func mergeDepMaps(a, b map[string]string) map[string]string {
	out := make(map[string]string, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		if _, ok := out[k]; !ok {
			out[k] = v
		}
	}
	return out
}

func dedupCapped(in []string, cap int) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
		if len(out) >= cap {
			break
		}
	}
	return out
}

// saturate returns hits/(hits+k), i.e. a smooth curve in [0,1) that
// approaches 1 as hits grows. k is the "hits at which we're 50% there".
func saturate(hits, k float64) float64 {
	if hits <= 0 {
		return 0
	}
	return hits / (hits + k)
}

func roundTo(v float64, decimals int) float64 {
	pow := 1.0
	for i := 0; i < decimals; i++ {
		pow *= 10
	}
	return float64(int64(v*pow+0.5)) / pow
}
