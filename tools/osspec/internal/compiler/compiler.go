package compiler

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/hash"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/loader"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/normalize"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/schemasem"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/yamlstrict"
)

type Options struct {
	RepoRoot string

	SpecsDir      string
	MetaschemaDir string
	DistDir       string
}

type Result struct {
	Descriptor   types.Descriptor
	Artifacts    types.ArtifactsIndex
	Requirements types.RequirementsIndex
}

func Compile(ctx context.Context, opts Options) (*Result, error) {
	if opts.RepoRoot == "" {
		return nil, errors.New("compiler: RepoRoot is required")
	}
	if opts.SpecsDir == "" {
		opts.SpecsDir = "specs"
	}
	if opts.MetaschemaDir == "" {
		opts.MetaschemaDir = "metaschema"
	}

	repoRootAbs, err := filepath.Abs(opts.RepoRoot)
	if err != nil {
		return nil, err
	}

	reg, err := schemasem.LoadRegistry(filepath.Join(repoRootAbs, opts.MetaschemaDir))
	if err != nil {
		return nil, err
	}

	version, versionHash, err := loadVersion(repoRootAbs)
	if err != nil {
		return nil, err
	}

	specFiles, err := loader.LoadSpecFiles(ctx, loader.Options{RepoRoot: repoRootAbs, SpecsDir: opts.SpecsDir})
	if err != nil {
		return nil, err
	}

	var bundle schemasem.Bundle
	bundle.Version = version

	for _, f := range specFiles {
		var hdr types.Header
		if err := yamlstrict.DecodeSingleStrictYAML(f.Bytes, &hdr, false); err != nil {
			return nil, fmt.Errorf("%s: parse header: %w", f.RelPath, err)
		}
		if hdr.SchemaVersion != 2 {
			return nil, fmt.Errorf("%s: unsupported schema_version %d", f.RelPath, hdr.SchemaVersion)
		}
		jsonDoc, err := yamlstrict.DecodeSingleStrictYAMLToJSON(f.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: decode yaml to json: %w", f.RelPath, err)
		}
		if err := reg.ValidateKindJSON(hdr.Kind, jsonDoc); err != nil {
			return nil, fmt.Errorf("%s: %w", f.RelPath, err)
		}

		switch hdr.Kind {
		case "opensspm.ruleset":
			var doc types.RulesetDoc
			if err := yamlstrict.DecodeSingleStrictYAML(f.Bytes, &doc, true); err != nil {
				return nil, fmt.Errorf("%s: parse ruleset: %w", f.RelPath, err)
			}
			normalize.RulesetDoc(&doc)
			applyRulesetPolicyDefaults(&doc)
			bundle.Rulesets = append(bundle.Rulesets, struct {
				Path string
				Doc  types.RulesetDoc
			}{Path: f.RelPath, Doc: doc})
		case "opensspm.profile":
			var doc types.ProfileDoc
			if err := yamlstrict.DecodeSingleStrictYAML(f.Bytes, &doc, true); err != nil {
				return nil, fmt.Errorf("%s: parse profile: %w", f.RelPath, err)
			}
			normalize.ProfileDoc(&doc)
			bundle.Profiles = append(bundle.Profiles, struct {
				Path string
				Doc  types.ProfileDoc
			}{Path: f.RelPath, Doc: doc})
		case "opensspm.entity_policy_pack":
			var doc types.EntityPolicyPackDoc
			if err := yamlstrict.DecodeSingleStrictYAML(f.Bytes, &doc, true); err != nil {
				return nil, fmt.Errorf("%s: parse entity policy pack: %w", f.RelPath, err)
			}
			normalize.EntityPolicyPackDoc(&doc)
			bundle.EntityPolicyPacks = append(bundle.EntityPolicyPacks, struct {
				Path string
				Doc  types.EntityPolicyPackDoc
			}{Path: f.RelPath, Doc: doc})
		case "opensspm.test_case":
			// Test cases are validated by schema but not compiled into the descriptor.
			continue
		default:
			return nil, fmt.Errorf("%s: unsupported kind %q", f.RelPath, hdr.Kind)
		}
	}

	if semErrs := schemasem.ValidateSemantic(&bundle); len(semErrs) > 0 {
		return nil, joinErrors(semErrs)
	}

	reqIndex := buildRequirements(&bundle)
	artifactsIndex := types.ArtifactsIndex{
		SchemaVersion: 2,
		Kind:          "opensspm.artifacts_index",
		Artifacts: []types.Artifact{
			{Kind: "opensspm.version", Key: "version", SourcePath: "version.yaml", Hash: versionHash},
		},
	}

	desc := types.Descriptor{
		SchemaVersion: 2,
		Kind:          "opensspm.engine_descriptor",
		Version:       version,
		Index: types.DescriptorIndex{
			Requirements: reqIndex,
			Artifacts:    artifactsIndex,
		},
	}

	for _, rs := range bundle.Rulesets {
		h, _, err := hash.HashObjectCanonicalYAML(rs.Doc)
		if err != nil {
			return nil, fmt.Errorf("%s: hash: %w", rs.Path, err)
		}
		desc.Rulesets = append(desc.Rulesets, types.Compiled[types.RulesetDoc]{SourcePath: rs.Path, Hash: h, Object: rs.Doc})
		artifactsIndex.Artifacts = append(artifactsIndex.Artifacts, types.Artifact{Kind: rs.Doc.Kind, Key: rs.Doc.Ruleset.Key, SourcePath: rs.Path, Hash: h})
	}
	for _, pack := range bundle.EntityPolicyPacks {
		h, _, err := hash.HashObjectCanonicalYAML(pack.Doc)
		if err != nil {
			return nil, fmt.Errorf("%s: hash: %w", pack.Path, err)
		}
		desc.EntityPolicyPacks = append(desc.EntityPolicyPacks, types.Compiled[types.EntityPolicyPackDoc]{SourcePath: pack.Path, Hash: h, Object: pack.Doc})
		artifactsIndex.Artifacts = append(artifactsIndex.Artifacts, types.Artifact{Kind: pack.Doc.Kind, Key: pack.Doc.EntityPolicyPack.Metadata.ID, SourcePath: pack.Path, Hash: h})
	}
	for _, p := range bundle.Profiles {
		h, _, err := hash.HashObjectCanonicalYAML(p.Doc)
		if err != nil {
			return nil, fmt.Errorf("%s: hash: %w", p.Path, err)
		}
		desc.Profiles = append(desc.Profiles, types.Compiled[types.ProfileDoc]{SourcePath: p.Path, Hash: h, Object: p.Doc})
		artifactsIndex.Artifacts = append(artifactsIndex.Artifacts, types.Artifact{Kind: p.Doc.Kind, Key: p.Doc.Profile.Key, SourcePath: p.Path, Hash: h})
	}

	slices.SortFunc(artifactsIndex.Artifacts, func(a, b types.Artifact) int {
		if c := strings.Compare(a.Kind, b.Kind); c != 0 {
			return c
		}
		return strings.Compare(a.Key, b.Key)
	})
	desc.Index.Artifacts = artifactsIndex

	return &Result{
		Descriptor:   desc,
		Artifacts:    artifactsIndex,
		Requirements: reqIndex,
	}, nil
}

func applyRulesetPolicyDefaults(doc *types.RulesetDoc) {
	if doc == nil || doc.Ruleset.Policy == nil {
		return
	}
	policy := doc.Ruleset.Policy
	for i := range doc.Ruleset.Rules {
		check := doc.Ruleset.Rules[i].Check
		if check == nil {
			continue
		}
		if check.Engine == "" {
			check.Engine = policy.Engine
		}
		if check.Package == "" {
			check.Package = policy.Package
		}
		if check.Rego == "" {
			check.Rego = policy.Rego
		}
	}
}

func loadVersion(repoRootAbs string) (types.Version, string, error) {
	if _, err := os.Stat(filepath.Join(repoRootAbs, "version.json")); err == nil {
		return types.Version{}, "", fmt.Errorf("compiler: version.json is not allowed; use version.yaml")
	} else if !errors.Is(err, os.ErrNotExist) {
		return types.Version{}, "", fmt.Errorf("compiler: stat version.json: %w", err)
	}

	b, err := os.ReadFile(filepath.Join(repoRootAbs, "version.yaml"))
	if err != nil {
		return types.Version{}, "", fmt.Errorf("compiler: read version.yaml: %w", err)
	}

	var v types.Version
	if err := yamlstrict.DecodeSingleStrictYAML(b, &v, true); err != nil {
		return types.Version{}, "", fmt.Errorf("compiler: parse version.yaml: %w", err)
	}
	if v.Project == "" || v.Repo == "" || v.SpecVersion == "" || v.SchemaVersion != 2 {
		return types.Version{}, "", fmt.Errorf("compiler: invalid version.yaml (missing required fields)")
	}
	h, _, err := hash.HashObjectCanonicalYAML(v)
	if err != nil {
		return types.Version{}, "", err
	}
	return v, h, nil
}

func joinErrors(errs []error) error {
	var b strings.Builder
	b.WriteString("validation failed:\n")
	for _, e := range errs {
		b.WriteString(" - ")
		b.WriteString(e.Error())
		b.WriteString("\n")
	}
	return errors.New(strings.TrimSpace(b.String()))
}
