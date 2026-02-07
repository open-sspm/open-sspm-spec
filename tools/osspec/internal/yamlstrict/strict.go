package yamlstrict

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

var jsonNumberPattern = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)

var allowedTags = map[string]struct{}{
	"!!map":   {},
	"!!seq":   {},
	"!!str":   {},
	"!!null":  {},
	"!!bool":  {},
	"!!int":   {},
	"!!float": {},
}

func DecodeSingleStrictYAML(data []byte, out any, knownFields bool) error {
	jsonBytes, err := DecodeSingleStrictYAMLToJSON(data)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}

	dec := json.NewDecoder(bytes.NewReader(jsonBytes))
	if knownFields {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("yamlstrict: decode: %w", err)
	}
	if tok, err := dec.Token(); err != io.EOF {
		if err != nil {
			return fmt.Errorf("yamlstrict: decode trailing: %w", err)
		}
		return fmt.Errorf("yamlstrict: decode trailing token %v", tok)
	}
	return nil
}

func DecodeSingleStrictYAMLToJSON(data []byte) ([]byte, error) {
	n, err := parseAndValidateSingle(data)
	if err != nil {
		return nil, err
	}
	v, err := nodeToJSONValue(n, "$")
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("yamlstrict: marshal json: %w", err)
	}
	return b, nil
}

func parseAndValidateSingle(data []byte) (*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))

	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("yamlstrict: empty document")
		}
		return nil, fmt.Errorf("yamlstrict: decode: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, fmt.Errorf("yamlstrict: expected a single YAML document")
	}

	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("yamlstrict: decode trailing document: %w", err)
		}
		return nil, fmt.Errorf("yamlstrict: multiple YAML documents are not allowed")
	}

	root := doc.Content[0]
	if err := validateNode(root, "$"); err != nil {
		return nil, err
	}
	return root, nil
}

func validateNode(n *yaml.Node, path string) error {
	if n == nil {
		return fmt.Errorf("yamlstrict: %s: nil node", path)
	}
	if n.Kind == yaml.AliasNode {
		return fmt.Errorf("yamlstrict: %s: aliases are not allowed", path)
	}
	if n.Anchor != "" {
		return fmt.Errorf("yamlstrict: %s: anchors are not allowed", path)
	}

	tag := n.ShortTag()
	if _, ok := allowedTags[tag]; !ok {
		if tag == "!!timestamp" {
			return fmt.Errorf("yamlstrict: %s: timestamp scalars are not allowed; quote date-like strings", path)
		}
		return fmt.Errorf("yamlstrict: %s: unsupported tag %q", path, tag)
	}

	switch n.Kind {
	case yaml.MappingNode:
		if len(n.Content)%2 != 0 {
			return fmt.Errorf("yamlstrict: %s: invalid mapping node", path)
		}
		seen := make(map[string]struct{}, len(n.Content)/2)
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			v := n.Content[i+1]

			if k.Kind == yaml.AliasNode || k.Anchor != "" {
				return fmt.Errorf("yamlstrict: %s: mapping key aliases/anchors are not allowed", path)
			}
			if k.Value == "<<" || k.ShortTag() == "!!merge" {
				return fmt.Errorf("yamlstrict: %s: merge keys are not allowed", path)
			}
			if k.Kind != yaml.ScalarNode || k.ShortTag() != "!!str" {
				return fmt.Errorf("yamlstrict: %s: mapping keys must be strings", path)
			}
			if _, exists := seen[k.Value]; exists {
				return fmt.Errorf("yamlstrict: %s: duplicate key %q", path, k.Value)
			}
			seen[k.Value] = struct{}{}

			if err := validateNode(v, path+"."+k.Value); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for i := range n.Content {
			if err := validateNode(n.Content[i], fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		switch tag {
		case "!!timestamp":
			return fmt.Errorf("yamlstrict: %s: timestamp scalars are not allowed; quote date-like strings", path)
		case "!!float":
			lv := strings.ToLower(strings.TrimSpace(n.Value))
			if lv == ".nan" || lv == ".inf" || lv == "-.inf" || lv == "+.inf" {
				return fmt.Errorf("yamlstrict: %s: non-finite floats are not JSON-compatible", path)
			}
			if !jsonNumberPattern.MatchString(n.Value) {
				return fmt.Errorf("yamlstrict: %s: float %q is not JSON-compatible", path, n.Value)
			}
		case "!!int":
			if !jsonNumberPattern.MatchString(n.Value) {
				return fmt.Errorf("yamlstrict: %s: integer %q is not JSON-compatible", path, n.Value)
			}
		case "!!bool", "!!null", "!!str":
			// Allowed.
		default:
			return fmt.Errorf("yamlstrict: %s: unsupported scalar tag %q", path, tag)
		}
	default:
		return fmt.Errorf("yamlstrict: %s: unsupported node kind %d", path, n.Kind)
	}

	return nil
}

func nodeToJSONValue(n *yaml.Node, path string) (any, error) {
	if n == nil {
		return nil, fmt.Errorf("yamlstrict: %s: nil node", path)
	}

	switch n.Kind {
	case yaml.MappingNode:
		out := make(map[string]any, len(n.Content)/2)
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			v := n.Content[i+1]
			vv, err := nodeToJSONValue(v, path+"."+k.Value)
			if err != nil {
				return nil, err
			}
			out[k.Value] = vv
		}
		return out, nil
	case yaml.SequenceNode:
		out := make([]any, 0, len(n.Content))
		for i := range n.Content {
			vv, err := nodeToJSONValue(n.Content[i], fmt.Sprintf("%s[%d]", path, i))
			if err != nil {
				return nil, err
			}
			out = append(out, vv)
		}
		return out, nil
	case yaml.ScalarNode:
		switch n.ShortTag() {
		case "!!str":
			return n.Value, nil
		case "!!null":
			return nil, nil
		case "!!bool":
			return parseBool(n.Value)
		case "!!int", "!!float":
			if !jsonNumberPattern.MatchString(n.Value) {
				return nil, fmt.Errorf("yamlstrict: %s: number %q is not JSON-compatible", path, n.Value)
			}
			return json.Number(n.Value), nil
		default:
			return nil, fmt.Errorf("yamlstrict: %s: unsupported scalar tag %q", path, n.ShortTag())
		}
	default:
		return nil, fmt.Errorf("yamlstrict: %s: unsupported node kind %d", path, n.Kind)
	}
}

func parseBool(v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "yes", "on":
		return true, nil
	case "false", "no", "off":
		return false, nil
	default:
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return false, fmt.Errorf("yamlstrict: invalid boolean %q", v)
		}
		return b, nil
	}
}
