// Package scip provides a thin wrapper around the per-language SCIP
// CLIs (scip-typescript, scip-python, scip-go, scip-rust, scip-java)
// used to produce a SCIP protobuf index for a source tree.
//
// FEATURES.md §11.2 — the ingestion pipeline writes the raw proto bytes
// to disk / object-storage, then hands them to the git-service edge
// converter (ConvertReferencesToEdges) to produce symbol_references +
// edges for the node canvas and dependency graph.
//
// The production container images (Dockerfile + Dockerfile.worker) bake
// every scip-* binary into /usr/local/bin, so Index treats a missing
// binary as a hard error — there is no silent degrade path.
package scip

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Indexer generates SCIP protobuf bytes from a source tree.
type Indexer interface {
	// Index runs the appropriate per-language CLI inside repoPath and
	// returns the raw SCIP proto. language is the canonical name used
	// across the codebase (matches SymbolParser outputs): "TypeScript",
	// "Python", "Go", "Rust", "Java".
	Index(ctx context.Context, repoPath, language string) ([]byte, error)
}

// ErrIndexerNotAvailable is returned when the CLI isn't installed on
// PATH. Kept as a typed error for observability — callers MUST treat it
// as a hard failure in production; the container images ship every
// scip-* binary preinstalled (see Dockerfile + Dockerfile.worker).
var ErrIndexerNotAvailable = errors.New("scip indexer not available")

// ErrUnsupportedLanguage is returned for languages we don't have a CLI for.
var ErrUnsupportedLanguage = errors.New("scip: unsupported language")

// CLIIndexer shells out to the canonical scip-* binaries.
// Defaults + timeout tuned for interactive ingestion; callers can
// override via WithTimeout if bulk imports need longer runs.
type CLIIndexer struct {
	// timeout bounds each CLI call to prevent a stuck indexer from
	// blocking the worker forever. Defaults to 5 minutes.
	timeout time.Duration
}

// NewCLIIndexer builds an indexer with sensible defaults.
func NewCLIIndexer() *CLIIndexer {
	return &CLIIndexer{timeout: 5 * time.Minute}
}

// WithTimeout overrides the per-run timeout.
func (i *CLIIndexer) WithTimeout(d time.Duration) *CLIIndexer {
	i.timeout = d
	return i
}

// Index runs the right CLI for language against repoPath and returns
// the index.scip bytes. On missing CLI it returns ErrIndexerNotAvailable
// so callers can surface a structured degrade-mode warning.
func (i *CLIIndexer) Index(ctx context.Context, repoPath, language string) ([]byte, error) {
	cli, args, err := cliForLanguage(language)
	if err != nil {
		return nil, err
	}
	if _, err := exec.LookPath(cli); err != nil {
		return nil, fmt.Errorf("%w: %s on PATH", ErrIndexerNotAvailable, cli)
	}
	if fi, err := os.Stat(repoPath); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("scip: repoPath %q not a directory", repoPath)
	}

	runCtx, cancel := context.WithTimeout(ctx, i.timeoutOrDefault())
	defer cancel()

	cmd := exec.CommandContext(runCtx, cli, args...)
	cmd.Dir = repoPath
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("scip %s: %w (stderr=%s)", cli, err, strings.TrimSpace(stderr.String()))
	}

	// All CLIs write to `index.scip` in the current directory unless
	// overridden. Read it back and return the bytes so callers can
	// persist / forward / convert without depending on a specific path.
	out := filepath.Join(repoPath, "index.scip")
	body, err := os.ReadFile(out)
	if err != nil {
		return nil, fmt.Errorf("scip %s: read output: %w", cli, err)
	}
	return body, nil
}

func (i *CLIIndexer) timeoutOrDefault() time.Duration {
	if i.timeout > 0 {
		return i.timeout
	}
	return 5 * time.Minute
}

// cliForLanguage maps canonical language name → (cli, args).
// Language strings here are case-insensitive matches against the
// normalized names used throughout git-service and code-analysis.
func cliForLanguage(language string) (string, []string, error) {
	switch strings.ToLower(language) {
	case "typescript", "javascript", "ts", "js":
		return "scip-typescript", []string{"index"}, nil
	case "python", "py":
		return "scip-python", []string{"index", "."}, nil
	case "go":
		return "scip-go", []string{"."}, nil
	case "rust", "rs":
		return "scip-rust", []string{"index"}, nil
	case "java", "kotlin":
		return "scip-java", []string{"index", "."}, nil
	default:
		return "", nil, fmt.Errorf("%w: %s", ErrUnsupportedLanguage, language)
	}
}
