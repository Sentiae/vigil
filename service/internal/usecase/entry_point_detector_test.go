package usecase

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

func TestDetectEntryPoints(t *testing.T) {
	dir := t.TempDir()

	write := func(relPath, body string) {
		full := filepath.Join(dir, relPath)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Go main.
	write("cmd/server/main.go", "package main\n\nfunc main() {\n  _ = 1\n}\n")
	// Python __main__.
	write("tool.py", "def hello():\n    pass\n\nif __name__ == '__main__':\n    hello()\n")
	// Java main.
	write("Main.java", "public class Main {\n  public static void main(String[] args) {}\n}\n")
	// Rust main.
	write("src/main.rs", "fn main() { println!(\"hi\"); }\n")
	// Ruby bin/ and Rails routes.
	write("bin/worker", "#!/usr/bin/env ruby\nputs 'hi'\n")
	write("config/routes.rb", "Rails.application.routes.draw do\nend\n")
	// PHP Laravel index.
	write("public/index.php", "<?php\nrequire 'bootstrap.php';\n")
	write("routes/web.php", "<?php\nRoute::get('/foo', 'Ctrl@bar');\n")
	// C# Program.cs.
	write("Program.cs", "var builder = WebApplication.CreateBuilder(args);\napp.MapGet(\"/hello\", () => \"hi\");\n")
	// Node express route.
	write("server/app.ts", "app.get('/api/users', handler);\n")
	// package.json bin + main.
	write("package.json", `{"name":"mytool","main":"dist/index.js","bin":{"mytool":"./bin/mytool.js"}}`)

	d := NewEntryPointDetector(nil)
	eps, err := d.DetectEntryPoints(context.Background(), uuid.New(), uuid.New(), dir)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(eps) == 0 {
		t.Fatal("no entry points detected")
	}

	// Index matches by (kind, substring of name-or-file).
	got := map[string]bool{}
	for _, ep := range eps {
		got[ep.Kind+"::"+ep.FilePath] = true
	}

	mustHave := []string{
		"main::cmd/server/main.go",
		"main::tool.py",
		"main::Main.java",
		"main::src/main.rs",
		"main::bin/worker",
		"http_route::config/routes.rb",
		"main::public/index.php",
		"http_route::routes/web.php",
		"main::Program.cs",
		"http_route::Program.cs",
		"http_route::server/app.ts",
		"main::dist/index.js",
		"cli_command::./bin/mytool.js",
	}
	for _, want := range mustHave {
		if !got[want] {
			t.Errorf("missing entry point %q (got %v)", want, got)
		}
	}
}

func TestDetectEntryPointsRejectsBadPath(t *testing.T) {
	d := NewEntryPointDetector(nil)
	_, err := d.DetectEntryPoints(context.Background(), uuid.New(), uuid.New(), "")
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}
