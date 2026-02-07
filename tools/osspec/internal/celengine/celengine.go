package celengine

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/google/cel-go/cel"
)

var (
	rowsCallRe       = regexp.MustCompile(`\brows\(\s*"([^"]+)"\s*\)`)
	hasDatasetCallRe = regexp.MustCompile(`\bhas_dataset\(\s*"([^"]+)"\s*\)`)
	paramCallRe      = regexp.MustCompile(`\bparam\(\s*"([^"]+)"\s*\)`)
)

type References struct {
	Datasets         []string
	RequiredDatasets []string
	Params           []string
}

type MissingDatasetError struct {
	Dataset string
}

func (e MissingDatasetError) Error() string {
	return fmt.Sprintf("dataset %q not found", e.Dataset)
}

type MissingParamError struct {
	Name string
}

func (e MissingParamError) Error() string {
	return fmt.Sprintf("param %q not found", e.Name)
}

type compiledExpression struct {
	program cel.Program
	refs    References
}

var compiledCache sync.Map // map[string]compiledExpression

func ExtractReferences(expression string) References {
	requiredDatasets := literalArgs(expression, rowsCallRe)
	datasets := append([]string{}, requiredDatasets...)
	datasets = append(datasets, literalArgs(expression, hasDatasetCallRe)...)
	params := normalizeStringSet(literalArgs(expression, paramCallRe))
	return References{
		Datasets:         normalizeStringSet(datasets),
		RequiredDatasets: normalizeStringSet(requiredDatasets),
		Params:           params,
	}
}

func ValidateExpression(expression string) error {
	_, err := compileExpression(expression)
	return err
}

func Evaluate(expression string, datasets map[string][]any, params map[string]any) (bool, error) {
	compiled, err := compileExpression(expression)
	if err != nil {
		return false, err
	}

	for _, dataset := range compiled.refs.RequiredDatasets {
		if _, ok := datasets[dataset]; !ok {
			return false, MissingDatasetError{Dataset: dataset}
		}
	}
	for _, param := range compiled.refs.Params {
		if _, ok := params[param]; !ok {
			return false, MissingParamError{Name: param}
		}
	}

	datasetsValue := make(map[string]any, len(datasets))
	for name, rows := range datasets {
		datasetsValue[name] = rows
	}
	paramsValue := make(map[string]any, len(params))
	for name, value := range params {
		paramsValue[name] = value
	}

	out, _, err := compiled.program.Eval(map[string]any{
		"datasets": datasetsValue,
		"params":   paramsValue,
	})
	if err != nil {
		return false, fmt.Errorf("evaluate CEL expression: %w", err)
	}
	result, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("CEL expression must return bool, got %T", out.Value())
	}
	return result, nil
}

func compileExpression(expression string) (compiledExpression, error) {
	expr := strings.TrimSpace(expression)
	if expr == "" {
		return compiledExpression{}, fmt.Errorf("CEL expression is required")
	}
	if cached, ok := compiledCache.Load(expr); ok {
		return cached.(compiledExpression), nil
	}

	env, err := cel.NewEnv(
		cel.Variable("datasets", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("params", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return compiledExpression{}, fmt.Errorf("create CEL environment: %w", err)
	}

	transformed := transformHelperCalls(expr)
	ast, iss := env.Compile(transformed)
	if iss != nil && iss.Err() != nil {
		return compiledExpression{}, fmt.Errorf("compile CEL expression: %w", iss.Err())
	}
	if ast == nil {
		return compiledExpression{}, fmt.Errorf("compile CEL expression: empty AST")
	}
	if !ast.OutputType().IsEquivalentType(cel.BoolType) {
		return compiledExpression{}, fmt.Errorf("CEL expression must return bool, got %s", ast.OutputType())
	}

	program, err := env.Program(ast)
	if err != nil {
		return compiledExpression{}, fmt.Errorf("build CEL program: %w", err)
	}
	compiled := compiledExpression{
		program: program,
		refs:    ExtractReferences(expr),
	}
	compiledCache.Store(expr, compiled)
	return compiled, nil
}

func transformHelperCalls(expression string) string {
	out := expression
	out = replaceLiteralCalls(out, rowsCallRe, func(name string) string {
		return fmt.Sprintf(`datasets[%s]`, strconv.Quote(name))
	})
	out = replaceLiteralCalls(out, hasDatasetCallRe, func(name string) string {
		return fmt.Sprintf(`(%s in datasets)`, strconv.Quote(name))
	})
	out = replaceLiteralCalls(out, paramCallRe, func(name string) string {
		return fmt.Sprintf(`params[%s]`, strconv.Quote(name))
	})
	return out
}

func literalArgs(expression string, re *regexp.Regexp) []string {
	matches := re.FindAllStringSubmatch(expression, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		name := strings.TrimSpace(match[1])
		if name == "" {
			continue
		}
		out = append(out, name)
	}
	return out
}

func replaceLiteralCalls(expression string, re *regexp.Regexp, fn func(name string) string) string {
	return re.ReplaceAllStringFunc(expression, func(match string) string {
		sub := re.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		name := strings.TrimSpace(sub[1])
		if name == "" {
			return match
		}
		return fn(name)
	})
}

func normalizeStringSet(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	set := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		set[value] = struct{}{}
	}
	if len(set) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}
