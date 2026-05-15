package compiler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/loader"
)

func TestResolveRegoReference_ReadsRelativeRegoFile(t *testing.T) {
	repo := t.TempDir()
	sourceDir := filepath.Join(repo, "specs", "rulesets")
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	regoPath := filepath.Join(sourceDir, "policy.rego")
	if err := os.WriteFile(regoPath, []byte("package example\n\nallow := true\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	f := loader.LoadedFile{
		AbsPath: filepath.Join(sourceDir, "ruleset.yaml"),
		RelPath: "specs/rulesets/ruleset.yaml",
	}
	rego := ""
	regoRef := "policy.rego"

	if err := resolveRegoReference(repo, f, "ruleset.policy", &rego, &regoRef); err != nil {
		t.Fatalf("resolveRegoReference() error: %v", err)
	}
	if rego != "package example\n\nallow := true" {
		t.Fatalf("unexpected resolved Rego:\n%s", rego)
	}
	if regoRef != "" {
		t.Fatalf("expected rego_path to be cleared, got %q", regoRef)
	}
}

func TestResolveRegoReference_RejectsInlineAndPath(t *testing.T) {
	repo := t.TempDir()
	f := loader.LoadedFile{
		AbsPath: filepath.Join(repo, "specs", "ruleset.yaml"),
		RelPath: "specs/ruleset.yaml",
	}
	rego := "package example"
	regoRef := "policy.rego"

	err := resolveRegoReference(repo, f, "ruleset.policy", &rego, &regoRef)
	if err == nil || !strings.Contains(err.Error(), "cannot set both rego and rego_path") {
		t.Fatalf("expected inline/path rejection, got %v", err)
	}
}

func TestReadRegoFile_RejectsRepoEscape(t *testing.T) {
	repo := t.TempDir()
	sourceDir := filepath.Join(repo, "specs", "rulesets")
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		t.Fatal(err)
	}

	_, _, err := readRegoFile(repo, filepath.Join(sourceDir, "ruleset.yaml"), "../../../outside.rego")
	if err == nil || !strings.Contains(err.Error(), "path escapes repo root") {
		t.Fatalf("expected repo escape rejection, got %v", err)
	}
}
