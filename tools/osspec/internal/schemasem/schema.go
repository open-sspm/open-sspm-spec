package schemasem

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

type Registry struct {
	schemas map[string]*jsonschema.Schema
}

type KindSchema struct {
	Kind     string
	Filename string
}

var KnownSchemas = []KindSchema{
	{Kind: "opensspm.ruleset", Filename: "opensspm.ruleset.schema.json"},
	{Kind: "opensspm.dataset_contract", Filename: "opensspm.dataset_contract.schema.json"},
	{Kind: "opensspm.connector_manifest", Filename: "opensspm.connector_manifest.schema.json"},
	{Kind: "opensspm.profile", Filename: "opensspm.profile.schema.json"},
	{Kind: "opensspm.dictionary", Filename: "opensspm.dictionary.schema.json"},
}

func LoadRegistry(metaschemaDir string) (*Registry, error) {
	if metaschemaDir == "" {
		return nil, errors.New("schemasem: metaschemaDir is required")
	}
	c := jsonschema.NewCompiler()

	schemas := make(map[string]*jsonschema.Schema, len(KnownSchemas))
	for _, ks := range KnownSchemas {
		path := filepath.Join(metaschemaDir, ks.Filename)
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("schemasem: read schema %s: %w", ks.Filename, err)
		}
		if err := c.AddResource(ks.Filename, bytes.NewReader(b)); err != nil {
			return nil, fmt.Errorf("schemasem: add schema %s: %w", ks.Filename, err)
		}
		s, err := c.Compile(ks.Filename)
		if err != nil {
			return nil, fmt.Errorf("schemasem: compile schema %s: %w", ks.Filename, err)
		}
		schemas[ks.Kind] = s
	}
	return &Registry{schemas: schemas}, nil
}

func (r *Registry) ValidateKindJSON(kind string, jsonBytes []byte) error {
	s, ok := r.schemas[kind]
	if !ok {
		return fmt.Errorf("schemasem: no schema registered for kind %q", kind)
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(jsonBytes))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return fmt.Errorf("schemasem: decode json: %w", err)
	}
	if err := s.Validate(v); err != nil {
		return fmt.Errorf("schemasem: schema validation failed: %w", err)
	}
	return nil
}

