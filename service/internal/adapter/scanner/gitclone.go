package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sentiae/vigil/service/pkg/logger"
)

// CloneRepository clones a git repository to a temporary directory.
// Returns the local path to the cloned repo and a cleanup function.
// Supports both remote URLs (https://...) and local paths (/path/to/repo).
func CloneRepository(ctx context.Context, uri, branch string) (string, func(), error) {
	tmpDir, err := os.MkdirTemp("", "vigil-scan-*")
	if err != nil {
		return "", nil, fmt.Errorf("create temp dir: %w", err)
	}

	cleanup := func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			logger.Warn(ctx, "Failed to cleanup temp dir", "path", tmpDir, "error", err)
		}
	}

	clonePath := filepath.Join(tmpDir, "repo")

	args := []string{"clone"}

	// Local paths: use file:// protocol (--depth not supported for local clones)
	cloneURI := uri
	if isLocalPath(uri) {
		cloneURI = "file://" + uri
	} else {
		args = append(args, "--depth=1")
	}

	if branch != "" {
		args = append(args, "--branch", branch)
	}
	args = append(args, cloneURI, clonePath)

	result, err := RunSubprocess(ctx, "git", args...)
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("git clone failed: %w", err)
	}
	if result.ExitCode != 0 {
		cleanup()
		return "", nil, fmt.Errorf("git clone failed (exit %d): %s", result.ExitCode, string(result.Stderr))
	}

	logger.Info(ctx, "Repository cloned", "uri", uri, "branch", branch, "path", clonePath)
	return clonePath, cleanup, nil
}

// IsLocalPath returns true if the target is a local filesystem path rather than a URL.
func IsLocalPath(target string) bool {
	return isLocalPath(target)
}

func isLocalPath(uri string) bool {
	return strings.HasPrefix(uri, "/") || strings.HasPrefix(uri, "./") || strings.HasPrefix(uri, "../")
}
