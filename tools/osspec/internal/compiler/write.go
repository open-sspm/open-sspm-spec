package compiler

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/hash"
)

func Build(ctx context.Context, opts Options) (*Result, error) {
	if opts.DistDir == "" {
		opts.DistDir = "dist"
	}
	res, err := Compile(ctx, opts)
	if err != nil {
		return nil, err
	}
	if err := writeDist(opts.RepoRoot, opts.DistDir, res); err != nil {
		return nil, err
	}
	return res, nil
}

func writeDist(repoRoot, distDir string, res *Result) error {
	repoRootAbs, err := filepath.Abs(repoRoot)
	if err != nil {
		return err
	}
	distAbs := filepath.Join(repoRootAbs, distDir)
	docsAbs := filepath.Join(repoRootAbs, "docs")

	_ = os.RemoveAll(filepath.Join(distAbs, "index"))
	if err := os.MkdirAll(filepath.Join(distAbs, "index"), 0o755); err != nil {
		return err
	}
	_ = os.RemoveAll(filepath.Join(distAbs, "compiled"))
	if err := os.MkdirAll(filepath.Join(distAbs, "compiled"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(distAbs, "compiled", "rulesets"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(distAbs, "compiled", "profiles"), 0o755); err != nil {
		return err
	}

	if err := writeCanonicalJSON(filepath.Join(distAbs, "descriptor.v1.json"), res.Descriptor); err != nil {
		return err
	}
	if err := os.MkdirAll(docsAbs, 0o755); err != nil {
		return err
	}
	if err := writeCanonicalJSON(filepath.Join(docsAbs, "descriptor.v1.json"), res.Descriptor); err != nil {
		return err
	}
	if err := copyMetaschemaToDocs(repoRootAbs, docsAbs); err != nil {
		return err
	}
	if err := writeCanonicalJSON(filepath.Join(distAbs, "index", "artifacts.json"), res.Artifacts); err != nil {
		return err
	}
	if err := writeCanonicalJSON(filepath.Join(distAbs, "index", "requirements.json"), res.Requirements); err != nil {
		return err
	}

	if err := writeCompiled(distAbs, res); err != nil {
		return err
	}
	return nil
}

func copyMetaschemaToDocs(repoRootAbs, docsAbs string) error {
	srcDir := filepath.Join(repoRootAbs, "metaschema")
	dstDir := filepath.Join(docsAbs, "metaschema")

	_ = os.RemoveAll(dstDir)
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return err
	}

	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		srcPath := filepath.Join(srcDir, name)
		dstPath := filepath.Join(dstDir, name)
		b, err := os.ReadFile(srcPath)
		if err != nil {
			return err
		}
		if err := os.WriteFile(dstPath, b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func writeCanonicalJSON(path string, v any) error {
	_, canonical, err := hash.HashObjectJCS(v)
	if err != nil {
		return err
	}
	canonical = append(canonical, '\n')
	return os.WriteFile(path, canonical, 0o644)
}

func writeCompiled(distAbs string, res *Result) error {
	// Rulesets
	for _, rs := range res.Descriptor.Rulesets {
		name := sanitizeFilename(rs.Object.Ruleset.Key) + ".json"
		if err := writeCanonicalJSON(filepath.Join(distAbs, "compiled", "rulesets", name), rs.Object); err != nil {
			return fmt.Errorf("write compiled ruleset %s: %w", rs.Object.Ruleset.Key, err)
		}
	}
	// Profiles
	for _, p := range res.Descriptor.Profiles {
		name := sanitizeFilename(p.Object.Profile.Key) + ".json"
		if err := writeCanonicalJSON(filepath.Join(distAbs, "compiled", "profiles", name), p.Object); err != nil {
			return fmt.Errorf("write compiled profile %s: %w", p.Object.Profile.Key, err)
		}
	}

	return nil
}

func sanitizeFilename(s string) string {
	if s == "" {
		return "unnamed"
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.' || r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}
