package gengo

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"go/format"
	"slices"
	"sort"
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

type File struct {
	Path    string
	Content string
}

func Generate(desc types.Descriptor) ([]File, error) {
	enumValues := types.EnumValues()

	specCode, err := generateSpecTypes(enumValues)
	if err != nil {
		return nil, err
	}
	runtimeCode, err := generateRuntimeTypes(enumValues)
	if err != nil {
		return nil, err
	}
	snapshotCode, err := generateDescriptorSnapshot(desc)
	if err != nil {
		return nil, err
	}

	return []File{
		{Path: "opensspm/spec/v2/types.gen.go", Content: specCode},
		{Path: "opensspm/spec/v2/descriptor_snapshot.gen.go", Content: snapshotCode},
		{Path: "opensspm/runtime/v2/runtime.gen.go", Content: runtimeCode},
	}, nil
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
	}{
		DatasetErrorKindEnumBlock: renderNamedEnum("DatasetErrorKind", enumValues["DatasetErrorKind"]),
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
	descJSON, err := json.Marshal(desc)
	if err != nil {
		return "", fmt.Errorf("marshal descriptor snapshot: %w", err)
	}

	tmpl, err := template.New("descriptor_snapshot").Option("missingkey=error").Parse(descriptorSnapshotTemplate)
	if err != nil {
		return "", fmt.Errorf("parse descriptor snapshot template: %w", err)
	}

	type descriptorSnapshotTemplateData struct {
		GeneratedDescriptorHash          string
		GeneratedDescriptorHashAlgorithm string
		GeneratedDescriptorJSON          string
	}
	data := descriptorSnapshotTemplateData{
		GeneratedDescriptorHash:          hashHex,
		GeneratedDescriptorHashAlgorithm: "sha256",
		GeneratedDescriptorJSON:          quote(string(descJSON)),
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
