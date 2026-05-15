package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"go/format"
	"io"
	"os"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/hash"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
)

//go:embed templates/descriptor_snapshot.go.tmpl
var descriptorSnapshotTemplate string

//go:embed templates/spec_types.go.tmpl
var specTypesTemplate string

//go:embed templates/runtime_types.go.tmpl
var runtimeTypesTemplate string

func main() {
	in, err := io.ReadAll(os.Stdin)
	if err != nil {
		fail(err)
	}
	var req types.CodegenRequest
	if err := json.Unmarshal(in, &req); err != nil {
		fail(fmt.Errorf("parse request: %w", err))
	}
	if req.SchemaVersion != 2 || req.Kind != "opensspm.codegen_request" {
		fail(fmt.Errorf("invalid request header: schema_version=%d kind=%q", req.SchemaVersion, req.Kind))
	}
	if req.Language != "go" {
		fail(fmt.Errorf("unsupported language %q", req.Language))
	}

	enumValues := types.EnumValues()

	specCode, err := generateSpecTypes(enumValues)
	if err != nil {
		fail(err)
	}
	runtimeCode, err := generateRuntimeTypes(enumValues)
	if err != nil {
		fail(err)
	}
	snapshotCode, err := generateDescriptorSnapshot(req.Descriptor)
	if err != nil {
		fail(err)
	}

	resp := types.CodegenResponse{
		SchemaVersion: 2,
		Kind:          "opensspm.codegen_response",
		Files: []types.CodegenFile{
			{Path: "opensspm/spec/v2/types.gen.go", Content: specCode},
			{Path: "opensspm/spec/v2/descriptor_snapshot.gen.go", Content: snapshotCode},
			{Path: "opensspm/runtime/v2/runtime.gen.go", Content: runtimeCode},
		},
	}
	out, err := json.Marshal(resp)
	if err != nil {
		fail(err)
	}
	os.Stdout.Write(out)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err.Error())
	os.Exit(1)
}

func generateSpecTypes(enumValues map[string][]string) (string, error) {
	rendered, err := renderTemplate("spec_types", specTypesTemplate, struct {
		EnumBlock string
	}{
		EnumBlock: renderAllEnums(enumValues),
	})
	if err != nil {
		return "", fmt.Errorf("render spec types template: %w", err)
	}

	formatted, err := format.Source([]byte(rendered))
	if err != nil {
		return "", fmt.Errorf("format spec types: %w", err)
	}
	return string(formatted), nil
}

func generateRuntimeTypes(enumValues map[string][]string) (string, error) {
	rendered, err := renderTemplate("runtime_types", runtimeTypesTemplate, struct {
		DatasetErrorKindEnumBlock string
		ScopeKindEnumBlock        string
	}{
		DatasetErrorKindEnumBlock: renderNamedEnum("DatasetErrorKind", enumValues["DatasetErrorKind"]),
		ScopeKindEnumBlock:        renderNamedEnum("ScopeKind", enumValues["ScopeKind"]),
	})
	if err != nil {
		return "", fmt.Errorf("render runtime types template: %w", err)
	}

	formatted, err := format.Source([]byte(rendered))
	if err != nil {
		return "", fmt.Errorf("format runtime types: %w", err)
	}
	return string(formatted), nil
}

func renderTemplate(name, src string, data any) (string, error) {
	tmpl, err := template.New(name).Option("missingkey=error").Parse(src)
	if err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}
	var out bytes.Buffer
	if err := tmpl.Execute(&out, data); err != nil {
		return "", fmt.Errorf("execute template: %w", err)
	}
	return out.String(), nil
}

func renderAllEnums(enumValues map[string][]string) string {
	names := make([]string, 0, len(enumValues))
	for name := range enumValues {
		names = append(names, name)
	}
	sort.Strings(names)

	blocks := make([]string, 0, len(names))
	for _, name := range names {
		blocks = append(blocks, renderNamedEnum(name, enumValues[name]))
	}
	return strings.Join(blocks, "\n")
}

func renderNamedEnum(name string, values []string) string {
	if len(values) == 0 {
		return ""
	}
	typeName := sanitizeGoIdent(name)

	v := append([]string(nil), values...)
	slices.Sort(v)
	v = slices.Compact(v)

	lines := make([]string, 0, len(v))
	for _, value := range v {
		constName := typeName + "_" + sanitizeGoIdent(strings.ToUpper(value))
		lines = append(lines, fmt.Sprintf("\t%s %s = %s", constName, typeName, quote(value)))
	}

	return fmt.Sprintf("type %s string\n\nconst (\n%s\n)\n", typeName, strings.Join(lines, "\n"))
}

func generateDescriptorSnapshot(desc types.Descriptor) (string, error) {
	hashHex, _, err := hash.HashObjectCanonicalYAML(desc)
	if err != nil {
		return "", fmt.Errorf("hash descriptor snapshot: %w", err)
	}
	descLiteral, err := renderGoLiteral(reflect.ValueOf(desc), true)
	if err != nil {
		return "", fmt.Errorf("render descriptor snapshot literal: %w", err)
	}

	tmpl, err := template.New("descriptor_snapshot").Option("missingkey=error").Parse(descriptorSnapshotTemplate)
	if err != nil {
		return "", fmt.Errorf("parse descriptor snapshot template: %w", err)
	}

	type descriptorSnapshotTemplateData struct {
		GeneratedDescriptorHash          string
		GeneratedDescriptorHashAlgorithm string
		GeneratedDescriptorLiteral       string
	}
	data := descriptorSnapshotTemplateData{
		GeneratedDescriptorHash:          hashHex,
		GeneratedDescriptorHashAlgorithm: "sha256",
		GeneratedDescriptorLiteral:       descLiteral,
	}

	var b bytes.Buffer
	if err := tmpl.Execute(&b, data); err != nil {
		return "", fmt.Errorf("execute descriptor snapshot template: %w", err)
	}

	formatted, err := format.Source(b.Bytes())
	if err != nil {
		return "", fmt.Errorf("format descriptor snapshot: %w", err)
	}
	return string(formatted), nil
}

func renderGoLiteral(v reflect.Value, includeType bool) (string, error) {
	if !v.IsValid() {
		return "nil", nil
	}

	t := v.Type()
	switch t.Kind() {
	case reflect.Interface:
		if v.IsNil() {
			return "nil", nil
		}
		return renderGoLiteral(v.Elem(), true)
	case reflect.Ptr:
		if v.IsNil() {
			return "nil", nil
		}
		inner, err := renderGoLiteral(v.Elem(), true)
		if err != nil {
			return "", err
		}
		return "generatedPtr(" + inner + ")", nil
	case reflect.Struct:
		var b strings.Builder
		if includeType {
			b.WriteString(sanitizeTypeString(t.String()))
		}
		b.WriteString("{")
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			if shouldOmitEmptyStringField(f, v.Field(i)) {
				continue
			}
			if b.Len() > 1 && b.String()[b.Len()-1] != '{' {
				b.WriteString(", ")
			}
			fieldIncludeType := needsExplicitTypeLiteral(f.Type)
			fieldLit, err := renderGoLiteral(v.Field(i), fieldIncludeType)
			if err != nil {
				return "", err
			}
			b.WriteString(f.Name)
			b.WriteString(": ")
			b.WriteString(fieldLit)
		}
		b.WriteString("}")
		return b.String(), nil
	case reflect.Slice:
		if v.IsNil() {
			return "nil", nil
		}
		var b strings.Builder
		if includeType {
			b.WriteString(sanitizeTypeString(t.String()))
		}
		b.WriteString("{")
		elemIncludeType := needsExplicitTypeLiteral(t.Elem())
		for i := 0; i < v.Len(); i++ {
			if i > 0 {
				b.WriteString(", ")
			}
			elemLit, err := renderGoLiteral(v.Index(i), elemIncludeType)
			if err != nil {
				return "", err
			}
			b.WriteString(elemLit)
		}
		b.WriteString("}")
		return b.String(), nil
	case reflect.Array:
		var b strings.Builder
		if includeType {
			b.WriteString(sanitizeTypeString(t.String()))
		}
		b.WriteString("{")
		elemIncludeType := needsExplicitTypeLiteral(t.Elem())
		for i := 0; i < v.Len(); i++ {
			if i > 0 {
				b.WriteString(", ")
			}
			elemLit, err := renderGoLiteral(v.Index(i), elemIncludeType)
			if err != nil {
				return "", err
			}
			b.WriteString(elemLit)
		}
		b.WriteString("}")
		return b.String(), nil
	case reflect.Map:
		if v.IsNil() {
			return "nil", nil
		}
		var b strings.Builder
		if includeType {
			b.WriteString(sanitizeTypeString(t.String()))
		}
		b.WriteString("{")
		keys := v.MapKeys()
		sort.Slice(keys, func(i, j int) bool {
			return mapKeySortValue(keys[i]) < mapKeySortValue(keys[j])
		})
		valueIncludeType := needsExplicitTypeLiteral(t.Elem())
		for i, k := range keys {
			if i > 0 {
				b.WriteString(", ")
			}
			keyLit, err := renderGoLiteral(k, false)
			if err != nil {
				return "", err
			}
			valLit, err := renderGoLiteral(v.MapIndex(k), valueIncludeType)
			if err != nil {
				return "", err
			}
			b.WriteString(keyLit)
			b.WriteString(": ")
			b.WriteString(valLit)
		}
		b.WriteString("}")
		return b.String(), nil
	case reflect.String:
		base := quote(v.String())
		if includeType {
			return sanitizeTypeString(t.String()) + "(" + base + ")", nil
		}
		return base, nil
	case reflect.Bool:
		base := "false"
		if v.Bool() {
			base = "true"
		}
		if includeType {
			return sanitizeTypeString(t.String()) + "(" + base + ")", nil
		}
		return base, nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		base := strconv.FormatInt(v.Int(), 10)
		if includeType {
			return sanitizeTypeString(t.String()) + "(" + base + ")", nil
		}
		return base, nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		base := strconv.FormatUint(v.Uint(), 10)
		if includeType {
			return sanitizeTypeString(t.String()) + "(" + base + ")", nil
		}
		return base, nil
	case reflect.Float32, reflect.Float64:
		bits := 64
		if t.Kind() == reflect.Float32 {
			bits = 32
		}
		base := strconv.FormatFloat(v.Float(), 'g', -1, bits)
		if includeType {
			return sanitizeTypeString(t.String()) + "(" + base + ")", nil
		}
		return base, nil
	default:
		return "", fmt.Errorf("unsupported literal type: %s", t.String())
	}
}

func needsExplicitTypeLiteral(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Struct, reflect.Array, reflect.Slice, reflect.Map, reflect.Interface:
		return true
	default:
		return false
	}
}

func shouldOmitEmptyStringField(f reflect.StructField, v reflect.Value) bool {
	if v.Kind() != reflect.String || v.String() != "" {
		return false
	}
	for _, opt := range strings.Split(f.Tag.Get("json"), ",")[1:] {
		if opt == "omitempty" {
			return true
		}
	}
	return false
}

func mapKeySortValue(v reflect.Value) string {
	switch v.Kind() {
	case reflect.String:
		return "s:" + v.String()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return "i:" + strconv.FormatInt(v.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return "u:" + strconv.FormatUint(v.Uint(), 10)
	case reflect.Bool:
		if v.Bool() {
			return "b:1"
		}
		return "b:0"
	default:
		return "x:" + fmt.Sprintf("%v", v.Interface())
	}
}

func sanitizeTypeString(s string) string {
	const pkgPath = "github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types."
	s = strings.ReplaceAll(s, pkgPath, "")
	s = strings.ReplaceAll(s, "types.", "")
	return s
}

func sanitizeGoIdent(s string) string {
	if s == "" {
		return "X"
	}
	// Allow only [A-Za-z0-9_], force leading to letter/underscore.
	var b strings.Builder
	for i, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_'
		if !ok {
			r = '_'
		}
		if i == 0 && (r >= '0' && r <= '9') {
			b.WriteByte('_')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
