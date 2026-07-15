package scanner

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/sentiae/vigil/service/pkg/logger"
)

// SubprocessResult holds the output of a subprocess execution.
type SubprocessResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Duration time.Duration
}

// RunSubprocess executes an external command with a timeout and returns the output.
func RunSubprocess(ctx context.Context, name string, args ...string) (*SubprocessResult, error) {
	return RunSubprocessEnv(ctx, nil, name, args...)
}

// RunSubprocessEnv is RunSubprocess with extra environment variables appended to
// the inherited environment. Used to pass registry credentials (e.g. a pull
// token) to a scanner via env — keeping the secret out of argv and out of logs.
func RunSubprocessEnv(ctx context.Context, extraEnv []string, name string, args ...string) (*SubprocessResult, error) {
	start := time.Now()

	cmd := exec.CommandContext(ctx, name, args...)
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	logger.Debug(ctx, "Running subprocess", "command", name, "args", args)

	err := cmd.Run()
	duration := time.Since(start)

	result := &SubprocessResult{
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
		Duration: duration,
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
			// Many scanners use non-zero exit codes to indicate findings were found
			// (e.g., gitleaks exit 1 = leaks found, semgrep exit 1 = findings)
			// So we don't treat all non-zero as errors
			logger.Debug(ctx, "Subprocess exited with non-zero code",
				"command", name, "exit_code", result.ExitCode, "duration", duration)
			return result, nil
		}
		return result, fmt.Errorf("subprocess %s failed: %w", name, err)
	}

	result.ExitCode = 0
	logger.Debug(ctx, "Subprocess completed", "command", name, "duration", duration)
	return result, nil
}

// CommandExists checks if a command is available on the PATH.
func CommandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
