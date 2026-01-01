package compiler

import (
	"context"
	"testing"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/testutil"
)

func TestCompile_RepoExamples(t *testing.T) {
	root := testutil.RepoRoot(t)
	if _, err := Compile(context.Background(), Options{RepoRoot: root}); err != nil {
		t.Fatalf("Compile() error: %v", err)
	}
}

