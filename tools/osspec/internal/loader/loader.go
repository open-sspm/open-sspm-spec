package loader

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const MaxSpecFileSize = 2 * 1024 * 1024 // 2 MiB

type LoadedFile struct {
	AbsPath string
	RelPath string
	Bytes   []byte
}

type Options struct {
	RepoRoot string
	SpecsDir string
}

func LoadSpecFiles(ctx context.Context, opts Options) ([]LoadedFile, error) {
	if opts.RepoRoot == "" {
		return nil, errors.New("loader: RepoRoot is required")
	}
	if opts.SpecsDir == "" {
		return nil, errors.New("loader: SpecsDir is required")
	}

	root := filepath.Clean(opts.RepoRoot)
	specsAbs := filepath.Join(root, opts.SpecsDir)

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

		if filepath.Ext(d.Name()) != ".json" {
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
	// small local insertion sort to avoid importing sort everywhere
	for i := 1; i < len(files); i++ {
		j := i
		for j > 0 && files[j-1].RelPath > files[j].RelPath {
			files[j-1], files[j] = files[j], files[j-1]
			j--
		}
	}
}

