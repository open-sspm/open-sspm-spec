package loader

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadSpecFiles_LoadsYAML(t *testing.T) {
	repo := t.TempDir()
	specsDir := filepath.Join(repo, "specs")
	if err := os.MkdirAll(filepath.Join(specsDir, "rulesets"), 0o755); err != nil {
		t.Fatal(err)
	}

	p1 := filepath.Join(specsDir, "rulesets", "a.yaml")
	p2 := filepath.Join(specsDir, "rulesets", "b.test.yaml")
	if err := os.WriteFile(p1, []byte("kind: opensspm.ruleset\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p2, []byte("kind: opensspm.test_case\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	files, err := LoadSpecFiles(context.Background(), Options{RepoRoot: repo, SpecsDir: "specs"})
	if err != nil {
		t.Fatalf("LoadSpecFiles() error: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("expected 2 files, got %d", len(files))
	}
	if files[0].RelPath >= files[1].RelPath {
		t.Fatalf("expected deterministic sort order, got %q then %q", files[0].RelPath, files[1].RelPath)
	}
}

func TestLoadSpecFiles_RejectsJSONAndYML(t *testing.T) {
	t.Run("json", func(t *testing.T) {
		repo := t.TempDir()
		specsDir := filepath.Join(repo, "specs")
		if err := os.MkdirAll(specsDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(specsDir, "bad.json"), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := LoadSpecFiles(context.Background(), Options{RepoRoot: repo, SpecsDir: "specs"})
		if err == nil || !strings.Contains(err.Error(), "json spec source not allowed") {
			t.Fatalf("expected json rejection error, got %v", err)
		}
	})

	t.Run("yml", func(t *testing.T) {
		repo := t.TempDir()
		specsDir := filepath.Join(repo, "specs")
		if err := os.MkdirAll(specsDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(specsDir, "bad.yml"), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := LoadSpecFiles(context.Background(), Options{RepoRoot: repo, SpecsDir: "specs"})
		if err == nil || !strings.Contains(err.Error(), ".yml is not allowed") {
			t.Fatalf("expected .yml rejection error, got %v", err)
		}
	})
}
