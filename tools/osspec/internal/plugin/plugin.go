package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
)

type Runner struct {
	RepoRoot string
}

func (r Runner) Run(ctx context.Context, language string, req types.CodegenRequest) (types.CodegenResponse, error) {
	pluginName := "osspec-gen-" + language

	cmd, err := r.commandForLanguage(ctx, pluginName, language)
	if err != nil {
		return types.CodegenResponse{}, err
	}

	in, err := json.Marshal(req)
	if err != nil {
		return types.CodegenResponse{}, fmt.Errorf("plugin: marshal request: %w", err)
	}

	cmd.Stdin = bytes.NewReader(in)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return types.CodegenResponse{}, fmt.Errorf("plugin: %s failed: %s", pluginName, msg)
	}

	var resp types.CodegenResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return types.CodegenResponse{}, fmt.Errorf("plugin: parse response: %w", err)
	}
	if resp.SchemaVersion != 1 || resp.Kind != "opensspm.codegen_response" {
		return types.CodegenResponse{}, fmt.Errorf("plugin: invalid response header: schema_version=%d kind=%q", resp.SchemaVersion, resp.Kind)
	}
	return resp, nil
}

func (r Runner) commandForLanguage(ctx context.Context, pluginName, language string) (*exec.Cmd, error) {
	if path, err := exec.LookPath(pluginName); err == nil {
		return exec.CommandContext(ctx, path), nil
	}

	// Dev/CI fallback: run from repo source if present.
	if r.RepoRoot == "" {
		return nil, fmt.Errorf("plugin: %s not found in PATH and RepoRoot not set for fallback", pluginName)
	}
	pkg := "./tools/osspec/cmd/" + pluginName
	cmd := exec.CommandContext(ctx, "go", "run", pkg)
	cmd.Dir = r.RepoRoot
	return cmd, nil
}

