package scip

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestCLIForLanguage(t *testing.T) {
	cases := []struct {
		language string
		wantCLI  string
		wantErr  bool
	}{
		{"TypeScript", "scip-typescript", false},
		{"typescript", "scip-typescript", false},
		{"Python", "scip-python", false},
		{"Go", "scip-go", false},
		{"Rust", "scip-rust", false},
		{"Java", "scip-java", false},
		{"Kotlin", "scip-java", false},
		{"Brainfuck", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.language, func(t *testing.T) {
			cli, _, err := cliForLanguage(tc.language)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error for %s", tc.language)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cli != tc.wantCLI {
				t.Errorf("cli = %q, want %q", cli, tc.wantCLI)
			}
		})
	}
}

func TestIndexMissingBinary(t *testing.T) {
	dir, err := os.MkdirTemp("", "scip-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	idx := NewCLIIndexer()
	// Force PATH to an empty dir so no scip-* binary is reachable.
	t.Setenv("PATH", dir)

	_, err = idx.Index(context.Background(), dir, "TypeScript")
	if err == nil {
		t.Fatal("expected error when binary is missing")
	}
	if !errors.Is(err, ErrIndexerNotAvailable) {
		t.Errorf("expected ErrIndexerNotAvailable, got %v", err)
	}
	if !strings.Contains(err.Error(), "scip-typescript") {
		t.Errorf("error should name the missing CLI, got %v", err)
	}
}

func TestIndexRejectsMissingRepo(t *testing.T) {
	idx := NewCLIIndexer()
	_, err := idx.Index(context.Background(), "/nonexistent/path/foo", "Python")
	if err == nil {
		t.Fatal("expected error on missing repoPath")
	}
}
