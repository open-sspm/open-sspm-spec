package compiler

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/loader"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
)

const maxRegoFileSize = loader.MaxSpecFileSize

func resolveRulesetRegoReferences(repoRootAbs string, f loader.LoadedFile, doc *types.RulesetDoc) error {
	if doc == nil {
		return nil
	}
	if doc.Ruleset.Policy != nil {
		if err := resolveRegoReference(repoRootAbs, f, "ruleset.policy", &doc.Ruleset.Policy.Rego, &doc.Ruleset.Policy.RegoPath); err != nil {
			return err
		}
	}
	for i := range doc.Ruleset.Rules {
		check := doc.Ruleset.Rules[i].Check
		if check == nil {
			continue
		}
		field := fmt.Sprintf("rule %q check", doc.Ruleset.Rules[i].Key)
		if err := resolveRegoReference(repoRootAbs, f, field, &check.Rego, &check.RegoPath); err != nil {
			return err
		}
	}
	return nil
}

func resolveEntityPolicyPackRegoReferences(repoRootAbs string, f loader.LoadedFile, doc *types.EntityPolicyPackDoc) error {
	if doc == nil {
		return nil
	}
	return resolveRegoReference(repoRootAbs, f, "entity_policy_pack.policy", &doc.EntityPolicyPack.Policy.Rego, &doc.EntityPolicyPack.Policy.RegoPath)
}

func resolveRegoReference(repoRootAbs string, f loader.LoadedFile, field string, rego, regoPath *string) error {
	if rego == nil || regoPath == nil {
		return nil
	}
	if *regoPath == "" {
		return nil
	}
	path := strings.TrimSpace(*regoPath)
	if path == "" {
		return fmt.Errorf("%s: %s.rego_path must not be blank", f.RelPath, field)
	}
	if strings.TrimSpace(*rego) != "" {
		return fmt.Errorf("%s: %s cannot set both rego and rego_path", f.RelPath, field)
	}

	b, rel, err := readRegoFile(repoRootAbs, f.AbsPath, path)
	if err != nil {
		return fmt.Errorf("%s: %s.rego_path: %w", f.RelPath, field, err)
	}
	module := strings.TrimSpace(string(b))
	if module == "" {
		return fmt.Errorf("%s: %s.rego_path %q resolved to empty Rego file %s", f.RelPath, field, path, rel)
	}

	*rego = module
	*regoPath = ""
	return nil
}

func readRegoFile(repoRootAbs, sourceAbs, ref string) ([]byte, string, error) {
	if filepath.IsAbs(ref) {
		return nil, "", fmt.Errorf("absolute paths are not allowed: %q", ref)
	}
	if strings.Contains(ref, "\\") {
		return nil, "", fmt.Errorf("paths must use forward slashes: %q", ref)
	}

	targetAbs := filepath.Clean(filepath.Join(filepath.Dir(sourceAbs), filepath.FromSlash(ref)))
	repoRootAbs = filepath.Clean(repoRootAbs)
	if !pathWithin(repoRootAbs, targetAbs) {
		return nil, "", fmt.Errorf("path escapes repo root: %q", ref)
	}
	resolvedRepoRootAbs, err := filepath.EvalSymlinks(repoRootAbs)
	if err != nil {
		return nil, "", fmt.Errorf("resolve repo root: %w", err)
	}
	if !strings.EqualFold(filepath.Ext(targetAbs), ".rego") {
		return nil, "", fmt.Errorf("referenced file must use .rego extension: %q", ref)
	}

	info, err := os.Lstat(targetAbs)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", repoRel(repoRootAbs, targetAbs), err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, "", fmt.Errorf("symlink not allowed: %s", repoRel(repoRootAbs, targetAbs))
	}
	if !info.Mode().IsRegular() {
		return nil, "", fmt.Errorf("not a regular file: %s", repoRel(repoRootAbs, targetAbs))
	}
	if info.Size() > maxRegoFileSize {
		return nil, "", fmt.Errorf("file too large (>2MiB): %s", repoRel(repoRootAbs, targetAbs))
	}

	resolvedAbs, err := filepath.EvalSymlinks(targetAbs)
	if err != nil {
		return nil, "", fmt.Errorf("resolve %s: %w", repoRel(repoRootAbs, targetAbs), err)
	}
	if !pathWithin(resolvedRepoRootAbs, resolvedAbs) {
		return nil, "", fmt.Errorf("path escapes repo root after resolving symlinks: %q", ref)
	}

	b, err := os.ReadFile(targetAbs)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", repoRel(repoRootAbs, targetAbs), err)
	}
	if !utf8.Valid(b) {
		return nil, "", fmt.Errorf("file must be UTF-8: %s", repoRel(repoRootAbs, targetAbs))
	}
	return b, repoRel(repoRootAbs, targetAbs), nil
}

func pathWithin(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel))
}

func repoRel(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}
