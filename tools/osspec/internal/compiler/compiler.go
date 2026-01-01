package compiler

import (
	"context"
	"encoding/json"
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
)

type Options struct {
	RepoRoot string

	SpecsDir     string
	MetaschemaDir string
	DistDir      string
}

type Result struct {
	Descriptor   types.DescriptorV1
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

	dictPath := filepath.Join(repoRootAbs, "dictionary.json")
	dictBytes, err := os.ReadFile(dictPath)
	if err != nil {
		return nil, fmt.Errorf("compiler: read dictionary.json: %w", err)
	}
	var dictDoc types.DictionaryDoc
	if err := json.Unmarshal(dictBytes, &dictDoc); err != nil {
		return nil, fmt.Errorf("compiler: parse dictionary.json: %w", err)
	}
	if err := reg.ValidateKindJSON(dictDoc.Kind, dictBytes); err != nil {
		return nil, fmt.Errorf("dictionary.json: %w", err)
	}
	normalize.DictionaryDoc(&dictDoc)
	dictHash, _, err := hash.HashObjectJCS(dictDoc)
	if err != nil {
		return nil, err
	}

	specFiles, err := loader.LoadSpecFiles(ctx, loader.Options{RepoRoot: repoRootAbs, SpecsDir: opts.SpecsDir})
	if err != nil {
		return nil, err
	}

	var bundle schemasem.Bundle
	bundle.Version = version
	bundle.Dictionary.Path = "dictionary.json"
	bundle.Dictionary.Doc = dictDoc

	for _, f := range specFiles {
		var hdr types.Header
		if err := json.Unmarshal(f.Bytes, &hdr); err != nil {
			return nil, fmt.Errorf("%s: parse header: %w", f.RelPath, err)
		}
		if hdr.SchemaVersion != 1 {
			return nil, fmt.Errorf("%s: unsupported schema_version %d", f.RelPath, hdr.SchemaVersion)
		}
		if err := reg.ValidateKindJSON(hdr.Kind, f.Bytes); err != nil {
			return nil, fmt.Errorf("%s: %w", f.RelPath, err)
		}

		switch hdr.Kind {
		case "opensspm.ruleset":
			var doc types.RulesetDoc
			if err := json.Unmarshal(f.Bytes, &doc); err != nil {
				return nil, fmt.Errorf("%s: parse ruleset: %w", f.RelPath, err)
			}
			normalize.RulesetDoc(&doc)
			bundle.Rulesets = append(bundle.Rulesets, struct {
				Path string
				Doc  types.RulesetDoc
			}{Path: f.RelPath, Doc: doc})
		case "opensspm.dataset_contract":
			var doc types.DatasetContractDoc
			if err := json.Unmarshal(f.Bytes, &doc); err != nil {
				return nil, fmt.Errorf("%s: parse dataset_contract: %w", f.RelPath, err)
			}
			bundle.DatasetContracts = append(bundle.DatasetContracts, struct {
				Path string
				Doc  types.DatasetContractDoc
			}{Path: f.RelPath, Doc: doc})
		case "opensspm.connector_manifest":
			var doc types.ConnectorManifestDoc
			if err := json.Unmarshal(f.Bytes, &doc); err != nil {
				return nil, fmt.Errorf("%s: parse connector_manifest: %w", f.RelPath, err)
			}
			normalize.ConnectorManifestDoc(&doc)
			bundle.Connectors = append(bundle.Connectors, struct {
				Path string
				Doc  types.ConnectorManifestDoc
			}{Path: f.RelPath, Doc: doc})
		case "opensspm.profile":
			var doc types.ProfileDoc
			if err := json.Unmarshal(f.Bytes, &doc); err != nil {
				return nil, fmt.Errorf("%s: parse profile: %w", f.RelPath, err)
			}
			normalize.ProfileDoc(&doc)
			bundle.Profiles = append(bundle.Profiles, struct {
				Path string
				Doc  types.ProfileDoc
			}{Path: f.RelPath, Doc: doc})
		default:
			return nil, fmt.Errorf("%s: unknown kind %q", f.RelPath, hdr.Kind)
		}
	}

	if semErrs := schemasem.ValidateSemantic(&bundle); len(semErrs) > 0 {
		return nil, joinErrors(semErrs)
	}

	reqIndex := buildRequirements(&bundle)
	artifactsIndex := types.ArtifactsIndex{
		SchemaVersion: 1,
		Kind:          "opensspm.artifacts_index",
		Artifacts: []types.Artifact{
			{Kind: "opensspm.version", Key: "version", SourcePath: "version.json", Hash: versionHash},
			{Kind: "opensspm.dictionary", Key: "dictionary", SourcePath: "dictionary.json", Hash: dictHash},
		},
	}

	desc := types.DescriptorV1{
		SchemaVersion: 1,
		Kind:          "opensspm.descriptor",
		Version:       version,
		Dictionary: types.Compiled[types.DictionaryDoc]{
			SourcePath: "dictionary.json",
			Hash:       dictHash,
			Object:     dictDoc,
		},
		Index: struct {
			Requirements types.RequirementsIndex `json:"requirements"`
			Artifacts    types.ArtifactsIndex    `json:"artifacts"`
		}{Requirements: reqIndex, Artifacts: artifactsIndex},
	}

	for _, rs := range bundle.Rulesets {
		h, _, err := hash.HashObjectJCS(rs.Doc)
		if err != nil {
			return nil, fmt.Errorf("%s: hash: %w", rs.Path, err)
		}
		desc.Rulesets = append(desc.Rulesets, types.Compiled[types.RulesetDoc]{SourcePath: rs.Path, Hash: h, Object: rs.Doc})
		artifactsIndex.Artifacts = append(artifactsIndex.Artifacts, types.Artifact{Kind: rs.Doc.Kind, Key: rs.Doc.Ruleset.Key, SourcePath: rs.Path, Hash: h})
	}
	for _, dc := range bundle.DatasetContracts {
		h, _, err := hash.HashObjectJCS(dc.Doc)
		if err != nil {
			return nil, fmt.Errorf("%s: hash: %w", dc.Path, err)
		}
		desc.DatasetContracts = append(desc.DatasetContracts, types.Compiled[types.DatasetContractDoc]{SourcePath: dc.Path, Hash: h, Object: dc.Doc})
		artifactsIndex.Artifacts = append(artifactsIndex.Artifacts, types.Artifact{Kind: dc.Doc.Kind, Key: fmt.Sprintf("%s@%d", dc.Doc.Dataset.Key, dc.Doc.Dataset.Version), SourcePath: dc.Path, Hash: h})
	}
	for _, c := range bundle.Connectors {
		h, _, err := hash.HashObjectJCS(c.Doc)
		if err != nil {
			return nil, fmt.Errorf("%s: hash: %w", c.Path, err)
		}
		desc.Connectors = append(desc.Connectors, types.Compiled[types.ConnectorManifestDoc]{SourcePath: c.Path, Hash: h, Object: c.Doc})
		artifactsIndex.Artifacts = append(artifactsIndex.Artifacts, types.Artifact{Kind: c.Doc.Kind, Key: c.Doc.Connector.Kind, SourcePath: c.Path, Hash: h})
	}
	for _, p := range bundle.Profiles {
		h, _, err := hash.HashObjectJCS(p.Doc)
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

func loadVersion(repoRootAbs string) (types.Version, string, error) {
	b, err := os.ReadFile(filepath.Join(repoRootAbs, "version.json"))
	if err != nil {
		return types.Version{}, "", fmt.Errorf("compiler: read version.json: %w", err)
	}
	var v types.Version
	if err := json.Unmarshal(b, &v); err != nil {
		return types.Version{}, "", fmt.Errorf("compiler: parse version.json: %w", err)
	}
	if v.Project == "" || v.Repo == "" || v.SpecVersion == "" || v.SchemaVersion != 1 {
		return types.Version{}, "", fmt.Errorf("compiler: invalid version.json (missing required fields)")
	}
	h, _, err := hash.HashObjectJCS(v)
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
