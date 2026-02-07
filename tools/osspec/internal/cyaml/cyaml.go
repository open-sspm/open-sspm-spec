package cyaml

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

func MarshalCanonical(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("cyaml: marshal json: %w", err)
	}
	canonicalJSON, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("cyaml: canonicalize json: %w", err)
	}

	dec := json.NewDecoder(bytes.NewReader(canonicalJSON))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("cyaml: decode canonical json: %w", err)
	}

	var b strings.Builder
	if err := writeValue(&b, doc, 0); err != nil {
		return nil, err
	}
	b.WriteByte('\n')
	return []byte(b.String()), nil
}

func writeValue(b *strings.Builder, v any, indent int) error {
	switch x := v.(type) {
	case map[string]any:
		return writeMap(b, x, indent)
	case []any:
		return writeSeq(b, x, indent)
	default:
		s, err := scalarString(x)
		if err != nil {
			return err
		}
		b.WriteString(s)
		return nil
	}
}

func writeMap(b *strings.Builder, m map[string]any, indent int) error {
	if len(m) == 0 {
		b.WriteString("{}")
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for i, k := range keys {
		if i > 0 {
			b.WriteByte('\n')
		}
		writeIndent(b, indent)
		b.WriteString(quoteString(k))
		b.WriteString(":")

		vv := m[k]
		if isInline(vv) {
			b.WriteByte(' ')
			if err := writeInlineValue(b, vv); err != nil {
				return err
			}
			continue
		}

		b.WriteByte('\n')
		if err := writeValue(b, vv, indent+2); err != nil {
			return err
		}
	}
	return nil
}

func writeSeq(b *strings.Builder, s []any, indent int) error {
	if len(s) == 0 {
		b.WriteString("[]")
		return nil
	}

	for i := range s {
		if i > 0 {
			b.WriteByte('\n')
		}
		writeIndent(b, indent)
		b.WriteString("-")
		vv := s[i]
		if isInline(vv) {
			b.WriteByte(' ')
			if err := writeInlineValue(b, vv); err != nil {
				return err
			}
			continue
		}
		b.WriteByte('\n')
		if err := writeValue(b, vv, indent+2); err != nil {
			return err
		}
	}
	return nil
}

func writeInlineValue(b *strings.Builder, v any) error {
	switch x := v.(type) {
	case map[string]any:
		if len(x) == 0 {
			b.WriteString("{}")
			return nil
		}
		return fmt.Errorf("cyaml: non-empty map must not be inline")
	case []any:
		if len(x) == 0 {
			b.WriteString("[]")
			return nil
		}
		return fmt.Errorf("cyaml: non-empty sequence must not be inline")
	default:
		s, err := scalarString(x)
		if err != nil {
			return err
		}
		b.WriteString(s)
		return nil
	}
}

func isInline(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		return len(x) == 0
	case []any:
		return len(x) == 0
	case nil, bool, string, json.Number, float64, float32, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return true
	default:
		return true
	}
}

func scalarString(v any) (string, error) {
	switch x := v.(type) {
	case nil:
		return "null", nil
	case bool:
		if x {
			return "true", nil
		}
		return "false", nil
	case string:
		return quoteString(x), nil
	case json.Number:
		s := x.String()
		if _, err := strconv.ParseFloat(s, 64); err != nil {
			if _, errInt := strconv.ParseInt(s, 10, 64); errInt != nil {
				if _, errUint := strconv.ParseUint(s, 10, 64); errUint != nil {
					return "", fmt.Errorf("cyaml: invalid json number %q", s)
				}
			}
		}
		return s, nil
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64), nil
	case float32:
		return strconv.FormatFloat(float64(x), 'g', -1, 32), nil
	case int:
		return strconv.FormatInt(int64(x), 10), nil
	case int8:
		return strconv.FormatInt(int64(x), 10), nil
	case int16:
		return strconv.FormatInt(int64(x), 10), nil
	case int32:
		return strconv.FormatInt(int64(x), 10), nil
	case int64:
		return strconv.FormatInt(x, 10), nil
	case uint:
		return strconv.FormatUint(uint64(x), 10), nil
	case uint8:
		return strconv.FormatUint(uint64(x), 10), nil
	case uint16:
		return strconv.FormatUint(uint64(x), 10), nil
	case uint32:
		return strconv.FormatUint(uint64(x), 10), nil
	case uint64:
		return strconv.FormatUint(x, 10), nil
	default:
		return "", fmt.Errorf("cyaml: unsupported scalar type %T", v)
	}
}

func quoteString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func writeIndent(b *strings.Builder, n int) {
	for i := 0; i < n; i++ {
		b.WriteByte(' ')
	}
}
