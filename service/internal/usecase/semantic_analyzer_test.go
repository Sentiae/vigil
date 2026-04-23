package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

type fakeCompleter struct {
	raw   string
	err   error
	calls int
}

func (f *fakeCompleter) Complete(_ context.Context, _ string, _ string) (string, error) {
	f.calls++
	return f.raw, f.err
}

type fakeSemStore struct {
	priorHash string
	saved     *ModuleSemantics
}

func (f *fakeSemStore) ExistingHash(_ context.Context, _ uuid.UUID, _ string) (string, error) {
	return f.priorHash, nil
}

func (f *fakeSemStore) Save(_ context.Context, _ uuid.UUID, _ uuid.UUID, sem ModuleSemantics) error {
	cp := sem
	f.saved = &cp
	return nil
}

func TestAnalyzeModuleHappyPath(t *testing.T) {
	comp := &fakeCompleter{raw: `{"purpose":"Parses git commit metadata","responsibilities":["parse commits","emit events"],"domain_concepts":["commit","author"],"confidence":0.9}`}
	store := &fakeSemStore{}
	a := NewSemanticAnalyzer(comp, store)

	sem, changed, err := a.AnalyzeModule(context.Background(), uuid.New(), uuid.New(), ModuleInput{
		ModuleID:       "git-service/commit",
		Language:       "Go",
		SourceSnippets: []string{"func Parse() {}"},
	})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true on first run")
	}
	if sem.Purpose == "" || len(sem.Responsibilities) != 2 {
		t.Errorf("unexpected sem: %+v", sem)
	}
	if sem.Confidence != 0.9 {
		t.Errorf("confidence: got %v", sem.Confidence)
	}
	if store.saved == nil {
		t.Fatal("save never called")
	}
}

func TestAnalyzeModuleHashShortCircuit(t *testing.T) {
	in := ModuleInput{ModuleID: "m", Language: "Go", SourceSnippets: []string{"x"}, SymbolNames: []string{"A"}}
	hash := moduleContentHash(in)
	comp := &fakeCompleter{raw: `{"purpose":"x","confidence":0.5}`}
	store := &fakeSemStore{priorHash: hash}
	a := NewSemanticAnalyzer(comp, store)

	_, changed, err := a.AnalyzeModule(context.Background(), uuid.New(), uuid.New(), in)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("expected changed=false when hash matches")
	}
	if comp.calls != 0 {
		t.Errorf("expected 0 LLM calls, got %d", comp.calls)
	}
}

func TestAnalyzeModuleHandlesFences(t *testing.T) {
	comp := &fakeCompleter{raw: "```json\n{\"purpose\":\"y\",\"confidence\":0.4}\n```"}
	a := NewSemanticAnalyzer(comp, nil)

	sem, _, err := a.AnalyzeModule(context.Background(), uuid.New(), uuid.New(), ModuleInput{ModuleID: "m"})
	if err != nil {
		t.Fatal(err)
	}
	if sem.Purpose != "y" {
		t.Errorf("purpose: %q", sem.Purpose)
	}
}

func TestAnalyzeModuleRejectsBadInput(t *testing.T) {
	a := NewSemanticAnalyzer(&fakeCompleter{}, nil)
	if _, _, err := a.AnalyzeModule(context.Background(), uuid.New(), uuid.New(), ModuleInput{}); err == nil {
		t.Fatal("expected error on empty moduleID")
	}
	a2 := NewSemanticAnalyzer(nil, nil)
	if _, _, err := a2.AnalyzeModule(context.Background(), uuid.New(), uuid.New(), ModuleInput{ModuleID: "m"}); err == nil {
		t.Fatal("expected error on missing completer")
	}
}

func TestAnalyzeModuleSurfacesCompleterError(t *testing.T) {
	comp := &fakeCompleter{err: errors.New("boom")}
	a := NewSemanticAnalyzer(comp, nil)
	if _, _, err := a.AnalyzeModule(context.Background(), uuid.New(), uuid.New(), ModuleInput{ModuleID: "m"}); err == nil {
		t.Fatal("expected error")
	}
}
