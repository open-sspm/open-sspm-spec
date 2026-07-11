package loader

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const MaxSpecFileSize = 2 * 1024 * 1024 // 2 MiB

type LoadedFile struct {
	AbsPath string
	RelPath string
	Bytes   []byte
}

func LoadSpecFiles(ctx context.Context, repoRoot string) ([]LoadedFile, error) {
	if repoRoot == "" {
		return nil, errors.New("loader: RepoRoot is required")
	}

	root := filepath.Clean(repoRoot)
	specsAbs := filepath.Join(root, "specs")

	var out []LoadedFile
	err := filepath.WalkDir(specsAbs, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Disallow symlinks anywhere in specs tree.
		if d.Type()&os.ModeSymlink != 0 {
			rel, _ := filepath.Rel(root, path)
			return fmt.Errorf("loader: symlink not allowed: %s", filepath.ToSlash(rel))
		}

		if d.IsDir() {
			return nil
		}

		nameLower := strings.ToLower(d.Name())
		ext := strings.ToLower(filepath.Ext(nameLower))

		switch ext {
		case ".yaml":
			// accepted
		case ".json":
			rel, _ := filepath.Rel(root, path)
			return fmt.Errorf("loader: json spec source not allowed (convert to .yaml): %s", filepath.ToSlash(rel))
		case ".yml":
			rel, _ := filepath.Rel(root, path)
			return fmt.Errorf("loader: .yml is not allowed (use .yaml): %s", filepath.ToSlash(rel))
		default:
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if info.Size() > MaxSpecFileSize {
			rel, _ := filepath.Rel(root, path)
			return fmt.Errorf("loader: file too large (>2MiB): %s", filepath.ToSlash(rel))
		}

		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, "../") {
			return fmt.Errorf("loader: path escapes repo root: %s", rel)
		}

		out = append(out, LoadedFile{
			AbsPath: path,
			RelPath: rel,
			Bytes:   b,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Ensure stable ordering for determinism (by rel path).
	sortLoaded(out)
	return out, nil
}

func sortLoaded(files []LoadedFile) {
	slices.SortFunc(files, func(a, b LoadedFile) int {
		return strings.Compare(a.RelPath, b.RelPath)
	})
}
