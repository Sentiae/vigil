// Package usecase — LLM-driven module semantic analyzer (§11.2).
//
// For each module (package / directory / namespace) in the repo, we ask
// the foundry LLM to summarize:
//
//   - purpose:          one-sentence intent in natural language
//   - responsibilities: 3-5 bullet strings
//   - domain_concepts:  nouns from the ubiquitous language
//   - confidence:       self-scored 0-1
//
// This powers the "what does this folder do?" hover card and lets the
// dependency-graph consumer tag clusters semantically instead of just
// by file path.
//
// Persistence: one row per (repo, module_id). Idempotent — we record a
// module_hash and skip re-analysis when the content hasn't changed.
package usecase

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// ModuleInput carries everything the analyzer needs to produce a summary.
type ModuleInput struct {
	ModuleID       string   // stable identifier, e.g. "git-service/internal/parsing"
	Language       string   // canonical language name
	SourceSnippets []string // trimmed excerpts (public API first) — caller caps size
	NeighborNotes  []string // adjacent module purposes (for context)
	SymbolNames    []string // top-level symbol names from tree-sitter
}

// ModuleSemantics is the LLM's structured response.
type ModuleSemantics struct {
	ModuleID        string   `json:"module_id"`
	Purpose         string   `json:"purpose"`
	Responsibilities []string `json:"responsibilities"`
	DomainConcepts  []string `json:"domain_concepts"`
	Confidence      float64  `json:"confidence"`
	ModuleHash      string   `json:"module_hash,omitempty"`
	ModelName       string   `json:"model_name,omitempty"`
}

// Completer abstracts foundry's chat-completion endpoint. Returns the
// raw JSON text the LLM produced; the analyzer unmarshals it.
type Completer interface {
	Complete(ctx context.Context, system, prompt string) (string, error)
}

// SemanticsStore persists + retrieves summaries, and reports whether a
// given hash is already known so callers can short-circuit re-runs.
type SemanticsStore interface {
	ExistingHash(ctx context.Context, repoID uuid.UUID, moduleID string) (string, error)
	Save(ctx context.Context, tenantID, repoID uuid.UUID, sem ModuleSemantics) error
}

// SemanticAnalyzer wires the above together.
type SemanticAnalyzer struct {
	completer Completer
	store     SemanticsStore
	modelName string
}

// NewSemanticAnalyzer constructs the analyzer. store may be nil when
// only in-process evaluation is needed (tests, preview UIs).
func NewSemanticAnalyzer(completer Completer, store SemanticsStore) *SemanticAnalyzer {
	return &SemanticAnalyzer{
		completer: completer,
		store:     store,
		modelName: "foundry-default",
	}
}

// AnalyzeModule runs the LLM + persists the result. If the module hash
// matches a prior run, persistence is skipped and the stored summary
// isn't re-fetched (we only return the fresh LLM result when we ran it).
// The bool `changed` is true when the analyzer actually called the LLM.
func (a *SemanticAnalyzer) AnalyzeModule(ctx context.Context, tenantID, repoID uuid.UUID, mod ModuleInput) (ModuleSemantics, bool, error) {
	if a.completer == nil {
		return ModuleSemantics{}, false, errors.New("semantic analyzer: completer required")
	}
	if strings.TrimSpace(mod.ModuleID) == "" {
		return ModuleSemantics{}, false, errors.New("semantic analyzer: moduleID required")
	}

	hash := moduleContentHash(mod)
	if a.store != nil {
		if prior, err := a.store.ExistingHash(ctx, repoID, mod.ModuleID); err == nil && prior != "" && prior == hash {
			// Up-to-date — skip LLM call entirely.
			return ModuleSemantics{ModuleID: mod.ModuleID, ModuleHash: hash}, false, nil
		}
	}

	system := buildSemanticSystemPrompt()
	prompt := buildSemanticUserPrompt(mod)
	raw, err := a.completer.Complete(ctx, system, prompt)
	if err != nil {
		return ModuleSemantics{}, false, fmt.Errorf("completer: %w", err)
	}

	sem, err := parseModuleSemantics(raw)
	if err != nil {
		return ModuleSemantics{}, false, fmt.Errorf("parse response: %w", err)
	}
	sem.ModuleID = mod.ModuleID
	sem.ModuleHash = hash
	sem.ModelName = a.modelName

	if sem.Confidence < 0 {
		sem.Confidence = 0
	}
	if sem.Confidence > 1 {
		sem.Confidence = 1
	}

	if a.store != nil {
		if err := a.store.Save(ctx, tenantID, repoID, sem); err != nil {
			return sem, true, fmt.Errorf("save: %w", err)
		}
	}
	return sem, true, nil
}

// buildSemanticSystemPrompt returns the single-paragraph system prompt
// the LLM sees. Kept terse so extra tokens go to the input.
func buildSemanticSystemPrompt() string {
	return `You are a senior software architect summarizing a code module.
Respond with a single JSON object of shape:
{"purpose": string, "responsibilities": [string], "domain_concepts": [string], "confidence": number}.
Keep responsibilities to 3-5 items. Keep purpose under 180 characters.
Use only facts visible in the provided snippets — never speculate.`
}

// buildSemanticUserPrompt assembles the module payload.
func buildSemanticUserPrompt(mod ModuleInput) string {
	var b strings.Builder
	b.WriteString("Module ID: ")
	b.WriteString(mod.ModuleID)
	b.WriteString("\n")
	if mod.Language != "" {
		b.WriteString("Language: ")
		b.WriteString(mod.Language)
		b.WriteString("\n")
	}
	if len(mod.SymbolNames) > 0 {
		b.WriteString("Top-level symbols: ")
		b.WriteString(strings.Join(mod.SymbolNames, ", "))
		b.WriteString("\n")
	}
	if len(mod.NeighborNotes) > 0 {
		b.WriteString("Adjacent module notes:\n")
		for _, n := range mod.NeighborNotes {
			b.WriteString("- ")
			b.WriteString(n)
			b.WriteString("\n")
		}
	}
	b.WriteString("Source snippets:\n")
	for i, s := range mod.SourceSnippets {
		if i >= 4 {
			break // cap per-call payload
		}
		b.WriteString("---\n")
		b.WriteString(s)
		b.WriteString("\n")
	}
	return b.String()
}

// parseModuleSemantics handles LLMs that wrap JSON in ``` fences or
// prefix the reply with explanatory text.
func parseModuleSemantics(raw string) (ModuleSemantics, error) {
	trimmed := strings.TrimSpace(raw)
	// Strip ``` fences if present.
	if strings.HasPrefix(trimmed, "```") {
		if idx := strings.Index(trimmed, "\n"); idx >= 0 {
			trimmed = trimmed[idx+1:]
		}
		if strings.HasSuffix(trimmed, "```") {
			trimmed = strings.TrimSuffix(trimmed, "```")
		}
		trimmed = strings.TrimSpace(trimmed)
	}
	// If the LLM prefixes with prose, try to pull the first {...} block.
	if !strings.HasPrefix(trimmed, "{") {
		if start := strings.Index(trimmed, "{"); start >= 0 {
			trimmed = trimmed[start:]
		}
	}
	var sem ModuleSemantics
	if err := json.Unmarshal([]byte(trimmed), &sem); err != nil {
		return ModuleSemantics{}, err
	}
	return sem, nil
}

// moduleContentHash fingerprints the module inputs so re-analysis is
// skipped when nothing material changed. Deliberately excludes
// timestamp/UUID fields and transient ordering of neighbors.
func moduleContentHash(mod ModuleInput) string {
	h := sha256.New()
	h.Write([]byte(mod.ModuleID))
	h.Write([]byte{0})
	h.Write([]byte(mod.Language))
	h.Write([]byte{0})
	for _, s := range mod.SourceSnippets {
		h.Write([]byte(s))
		h.Write([]byte{1})
	}
	for _, s := range mod.SymbolNames {
		h.Write([]byte(s))
		h.Write([]byte{2})
	}
	return hex.EncodeToString(h.Sum(nil))
}
