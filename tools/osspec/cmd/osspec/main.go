package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/compiler"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/gengo"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/verify"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "validate":
		runValidate(os.Args[2:])
	case "verify":
		runVerify(os.Args[2:])
	case "build":
		runBuild(os.Args[2:])
	case "codegen":
		runCodegen(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "osspec: compile and validate Open SSPM compliance specs")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  osspec validate [--repo .]")
	fmt.Fprintln(os.Stderr, "  osspec verify   [--repo .]")
	fmt.Fprintln(os.Stderr, "  osspec build    [--repo .] [--out dist]")
	fmt.Fprintln(os.Stderr, "  osspec codegen  --lang go --out gen/go [--repo .]")
}

func runValidate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	repo := fs.String("repo", ".", "repo root")
	_ = fs.Parse(args)

	ctx := context.Background()
	_, err := compiler.Compile(ctx, *repo)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	fmt.Fprintln(os.Stdout, "ok")
}

func runVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	repo := fs.String("repo", ".", "repo root")
	_ = fs.Parse(args)

	repoAbs, err := filepath.Abs(*repo)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	ctx := context.Background()
	if err := verify.Run(ctx, repoAbs); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func runBuild(args []string) {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	repo := fs.String("repo", ".", "repo root")
	out := fs.String("out", "dist", "dist output dir (relative to repo root)")
	_ = fs.Parse(args)

	ctx := context.Background()
	if err := compiler.Build(ctx, *repo, *out); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	fmt.Fprintln(os.Stdout, "built")
}

func runCodegen(args []string) {
	fs := flag.NewFlagSet("codegen", flag.ExitOnError)
	repo := fs.String("repo", ".", "repo root")
	lang := fs.String("lang", "", "output language (currently go)")
	outDir := fs.String("out", "", "output directory")
	_ = fs.Parse(args)

	if *lang == "" || *outDir == "" {
		fmt.Fprintln(os.Stderr, "codegen requires --lang and --out")
		os.Exit(2)
	}
	if *lang != "go" {
		fmt.Fprintf(os.Stderr, "codegen: unsupported language %q\n", *lang)
		os.Exit(2)
	}

	repoAbs, err := filepath.Abs(*repo)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	ctx := context.Background()
	desc, err := compiler.Compile(ctx, repoAbs)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	files, err := gengo.Generate(*desc)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	if err := writeGeneratedFiles(repoAbs, *outDir, files); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "generated %d files\n", len(files))
}

func writeGeneratedFiles(repoRootAbs, outDir string, files []gengo.File) error {
	outAbs := outDir
	if !filepath.IsAbs(outAbs) {
		outAbs = filepath.Join(repoRootAbs, outDir)
	}
	if err := os.MkdirAll(outAbs, 0o755); err != nil {
		return err
	}
	for _, f := range files {
		rel := filepath.Clean(f.Path)
		if rel == "." || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
			return fmt.Errorf("codegen: invalid file path %q", f.Path)
		}
		p := filepath.Join(outAbs, rel)
		if !strings.HasPrefix(p, outAbs+string(os.PathSeparator)) && p != outAbs {
			return fmt.Errorf("codegen: path escapes output dir: %q", f.Path)
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		content := f.Content
		if !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			return err
		}
	}
	return nil
}
