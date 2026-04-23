package usecase

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// helper: fresh tmp dir + write files. Each test gets its own tree so
// rule interactions are isolated.
func makeProject(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", full, err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
	return root
}

// assert: a framework of the given name is present with confidence >= min.
func assertDetected(t *testing.T, got []DetectedFramework, name string, minConfidence float64) DetectedFramework {
	t.Helper()
	for _, f := range got {
		if f.Name == name {
			if f.Confidence < minConfidence {
				t.Fatalf("framework %q detected with confidence %.2f, want >= %.2f", name, f.Confidence, minConfidence)
			}
			return f
		}
	}
	t.Fatalf("framework %q not detected; got %+v", name, got)
	return DetectedFramework{}
}

// assert: framework with the given name was NOT detected. Used to
// verify we don't false-positive across neighboring rules.
func assertNotDetected(t *testing.T, got []DetectedFramework, name string) {
	t.Helper()
	for _, f := range got {
		if f.Name == name {
			t.Fatalf("framework %q unexpectedly detected: %+v", name, f)
		}
	}
}

// ---------------------------------------------------------------------------
// JavaScript / TypeScript fixtures
// ---------------------------------------------------------------------------

func TestDetect_Express(t *testing.T) {
	root := makeProject(t, map[string]string{
		"package.json": `{
			"name": "api",
			"dependencies": { "express": "^4.18.0" }
		}`,
		"src/server.js": `const express = require('express');
const app = express();
app.get('/', (req, res) => res.send('hi'));`,
	})
	got, err := NewFrameworkDetector().Detect(root)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	f := assertDetected(t, got, "express", 0.75)
	if f.Language != "javascript" {
		t.Fatalf("language = %q, want javascript", f.Language)
	}
	if f.Version != "^4.18.0" {
		t.Fatalf("version = %q, want ^4.18.0", f.Version)
	}
}

func TestDetect_NextReact(t *testing.T) {
	// A Next.js project always also uses React — both rules should fire.
	root := makeProject(t, map[string]string{
		"package.json": `{
			"dependencies": {
				"next": "14.1.0",
				"react": "18.2.0",
				"react-dom": "18.2.0"
			}
		}`,
		"app/page.tsx": `import Link from 'next/link';
import { useState } from 'react';
export default function Page() { return <Link href="/">home</Link>; }`,
	})
	got, err := NewFrameworkDetector().Detect(root)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	assertDetected(t, got, "next", 0.75)
	assertDetected(t, got, "react", 0.75)
}

func TestDetect_Vue(t *testing.T) {
	root := makeProject(t, map[string]string{
		"package.json": `{ "dependencies": { "vue": "3.4.0" } }`,
		"src/App.vue": `<script setup>
import { ref } from 'vue';
const count = ref(0);
</script>`,
	})
	got, err := NewFrameworkDetector().Detect(root)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	assertDetected(t, got, "vue", 0.75)
}

func TestDetect_NestJS(t *testing.T) {
	root := makeProject(t, map[string]string{
		"package.json": `{
			"dependencies": { "@nestjs/core": "10.0.0", "@nestjs/common": "10.0.0" }
		}`,
		"src/app.module.ts": `import { Module } from '@nestjs/common';
@Module({})
export class AppModule {}`,
	})
	got, err := NewFrameworkDetector().Detect(root)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	assertDetected(t, got, "nestjs", 0.75)
}

func TestDetect_Fastify(t *testing.T) {
	root := makeProject(t, map[string]string{
		"package.json": `{ "dependencies": { "fastify": "4.0.0" } }`,
		"server.js":    `const fastify = require('fastify')();`,
	})
	got, err := NewFrameworkDetector().Detect(root)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	assertDetected(t, got, "fastify", 0.75)
}

// A project with only a package.json dep but no import should still
// score manifest-only (0.5). This guards against accidental
// confidence inflation.
func TestDetect_ManifestOnly_NoImports(t *testing.T) {
	root := makeProject(t, map[string]string{
		"package.json": `{ "dependencies": { "express": "4.0.0" } }`,
		"src/noop.js":  `console.log('no express here');`,
	})
	got, err := NewFrameworkDetector().Detect(root)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	f := assertDetected(t, got, "express", 0.4)
	if f.Confidence > 0.6 {
		t.Fatalf("manifest-only should cap around 0.5, got %.2f", f.Confidence)
	}
}

// ---------------------------------------------------------------------------
// Python fixtures
// ---------------------------------------------------------------------------

func TestDetect_Django_Requirements(t *testing.T) {
	root := makeProject(t, map[string]string{
		"requirements.txt": `# web stack
Django>=4.2,<5
psycopg2-binary==2.9.9
`,
		"myapp/urls.py": `from django.urls import path
urlpatterns = []`,
	})
	got, err := NewFrameworkDetector().Detect(root)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	assertDetected(t, got, "django", 0.75)
}

func TestDetect_Flask_Decorators(t *testing.T) {
	root := makeProject(t, map[string]string{
		"requirements.txt": "Flask==3.0.0\n",
		"app.py": `from flask import Flask
app = Flask(__name__)

@app.route('/')
def index():
    return 'hi'
`,
	})
	got, err := NewFrameworkDetector().Detect(root)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	assertDetected(t, got, "flask", 0.75)
}

func TestDetect_FastAPI_PyProject(t *testing.T) {
	root := makeProject(t, map[string]string{
		"pyproject.toml": `[project]
name = "svc"
dependencies = ["fastapi>=0.110", "uvicorn[standard]>=0.27"]
`,
		"api/main.py": `from fastapi import FastAPI
app = FastAPI()

@app.get('/healthz')
def healthz():
    return {"ok": True}
`,
	})
	got, err := NewFrameworkDetector().Detect(root)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	f := assertDetected(t, got, "fastapi", 0.75)
	// pyproject.toml should have been recorded as evidence.
	foundManifest := false
	for _, e := range f.EvidenceFiles {
		if e == "pyproject.toml" {
			foundManifest = true
		}
	}
	if !foundManifest {
		t.Fatalf("fastapi evidence missing pyproject.toml; got %+v", f.EvidenceFiles)
	}
}

func TestDetect_Poetry(t *testing.T) {
	root := makeProject(t, map[string]string{
		"pyproject.toml": `[tool.poetry.dependencies]
python = "^3.11"
django = "^5.0"
`,
		"proj/settings.py": `from django.conf import settings`,
	})
	got, err := NewFrameworkDetector().Detect(root)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	assertDetected(t, got, "django", 0.75)
}

// ---------------------------------------------------------------------------
// Go fixtures
// ---------------------------------------------------------------------------

func TestDetect_Gin(t *testing.T) {
	root := makeProject(t, map[string]string{
		"go.mod": `module example.com/app
go 1.21
require (
	github.com/gin-gonic/gin v1.9.1
)
`,
		"main.go": `package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.Default()
	_ = r
}
`,
	})
	got, err := NewFrameworkDetector().Detect(root)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	assertDetected(t, got, "gin", 0.75)
	// net/http should NOT fire — no import present.
	assertNotDetected(t, got, "net/http")
}

func TestDetect_Chi_Versioned(t *testing.T) {
	root := makeProject(t, map[string]string{
		"go.mod": `module example.com/app
go 1.21
require github.com/go-chi/chi/v5 v5.0.10
`,
		"router.go": `package main
import (
	"net/http"
	"github.com/go-chi/chi/v5"
)

func router() http.Handler { return chi.NewRouter() }
`,
	})
	got, err := NewFrameworkDetector().Detect(root)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	assertDetected(t, got, "chi", 0.75)
	// net/http uses stdlib-only scoring (no manifest). Should still fire.
	assertDetected(t, got, "net/http", 0.5)
}

func TestDetect_Echo(t *testing.T) {
	root := makeProject(t, map[string]string{
		"go.mod": `module example.com/app
go 1.21
require github.com/labstack/echo/v4 v4.11.4
`,
		"cmd/main.go": `package main

import "github.com/labstack/echo/v4"

func main() { _ = echo.New() }
`,
	})
	got, err := NewFrameworkDetector().Detect(root)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	assertDetected(t, got, "echo", 0.75)
}

// ---------------------------------------------------------------------------
// Negative / edge cases
// ---------------------------------------------------------------------------

// An empty directory should yield no frameworks and no error.
func TestDetect_EmptyProject(t *testing.T) {
	root := t.TempDir()
	got, err := NewFrameworkDetector().Detect(root)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no frameworks in empty project, got %+v", got)
	}
}

// A non-existent path should error cleanly.
func TestDetect_MissingRoot(t *testing.T) {
	_, err := NewFrameworkDetector().Detect(filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("expected error for missing root")
	}
}

// A file (not dir) should error.
func TestDetect_FileRoot(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "a.go")
	if err := os.WriteFile(path, []byte("package main"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := NewFrameworkDetector().Detect(path)
	if err == nil {
		t.Fatal("expected error when root is a file")
	}
}

// node_modules and vendor are skipped so a nested react copy inside
// node_modules doesn't inflate confidence. We plant both a real
// top-level import AND a fake nested one to verify the skip.
func TestDetect_SkipsNoiseDirs(t *testing.T) {
	root := makeProject(t, map[string]string{
		"package.json":                `{ "dependencies": { "react": "18.0.0" } }`,
		"src/index.tsx":               `import React from 'react';`,
		"node_modules/foo/index.js":   `require('express'); require('fastify'); require('vue');`,
		"node_modules/bar/package.js": `import 'next'; import '@nestjs/core';`,
	})
	got, err := NewFrameworkDetector().Detect(root)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	// react is legitimately declared + imported.
	assertDetected(t, got, "react", 0.75)
	// The frameworks that only appear in node_modules must NOT fire.
	assertNotDetected(t, got, "express")
	assertNotDetected(t, got, "fastify")
	assertNotDetected(t, got, "vue")
	assertNotDetected(t, got, "next")
	assertNotDetected(t, got, "nestjs")
}

// ---------------------------------------------------------------------------
// Extensible stub smoke test — exercises WithRules + the rule struct
// export surface so future Java/Ruby rules can plug in without needing
// detector internals.
// ---------------------------------------------------------------------------

func TestDetect_ExtensibleStub_Java(t *testing.T) {
	root := makeProject(t, map[string]string{
		"pom.xml": `<project><dependencies>
<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency>
</dependencies></project>`,
		"src/main/java/App.java": `import org.springframework.boot.SpringApplication;`,
	})
	// Custom rule — stub shape for Spring, using an import-only check
	// since we don't parse pom.xml in built-in rules.
	rules := []frameworkRule{
		{
			Name:     "spring",
			Language: "java",
			// No manifest deps yet — proves the extensible stub path.
			SourceExts: []string{".java"},
			ImportPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?m)^\s*import\s+org\.springframework`),
			},
		},
	}
	det := NewFrameworkDetector().WithRules(rules)
	got, err := det.Detect(root)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	assertDetected(t, got, "spring", 0.5)
}
