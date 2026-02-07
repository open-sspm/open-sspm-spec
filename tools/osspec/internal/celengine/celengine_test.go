package celengine

import (
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

func TestEvaluate_HasDatasetGuardDoesNotRequireDataset(t *testing.T) {
	ok, err := Evaluate(`!has_dataset("missing")`, map[string][]any{}, map[string]any{})
	if err != nil {
		t.Fatalf("expected no error for has_dataset guard, got %v", err)
	}
	if !ok {
		t.Fatalf("expected expression to pass when dataset is missing")
	}
}

func TestEvaluate_RowsStillRequiresDataset(t *testing.T) {
	_, err := Evaluate(`rows("missing").size() == 0`, map[string][]any{}, map[string]any{})
	if err == nil {
		t.Fatalf("expected missing dataset error for rows() reference")
	}
	if _, ok := err.(MissingDatasetError); !ok {
		t.Fatalf("expected MissingDatasetError, got %T (%v)", err, err)
	}
}

func TestEvaluatePredicate_RowAndParams(t *testing.T) {
	ok, err := EvaluatePredicate(`r["x"] >= int(param("min"))`, map[string]any{"x": 3}, map[string]any{"min": 2})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !ok {
		t.Fatalf("expected predicate to evaluate to true")
	}
}

func TestEvaluatePredicate_MissingParam(t *testing.T) {
	_, err := EvaluatePredicate(`r["x"] >= int(param("min"))`, map[string]any{"x": 3}, map[string]any{})
	if err == nil {
		t.Fatalf("expected missing param error")
	}
	if _, ok := err.(MissingParamError); !ok {
		t.Fatalf("expected MissingParamError, got %T (%v)", err, err)
	}
}

// --- field() function tests ---

func TestFieldNavigate_SimpleKey(t *testing.T) {
	val := types.DefaultTypeAdapter.NativeToValue(map[string]any{"name": "Alice"})
	result := fieldNavigate(val, "name")
	if result.Value() != "Alice" {
		t.Fatalf("expected 'Alice', got %v", result.Value())
	}
}

func TestFieldNavigate_NestedPath(t *testing.T) {
	val := types.DefaultTypeAdapter.NativeToValue(map[string]any{
		"a": map[string]any{"b": map[string]any{"c": 42}},
	})
	result := fieldNavigate(val, "a.b.c")
	got, ok := result.Value().(int64)
	if !ok {
		t.Fatalf("expected int64, got %T (%v)", result.Value(), result.Value())
	}
	if got != 42 {
		t.Fatalf("expected 42, got %v", got)
	}
}

func TestFieldNavigate_MissingIntermediateKey(t *testing.T) {
	val := types.DefaultTypeAdapter.NativeToValue(map[string]any{"a": map[string]any{}})
	result := fieldNavigate(val, "a.b.c")
	if result != types.NullValue {
		t.Fatalf("expected null for missing intermediate key, got %v", result.Value())
	}
}

func TestFieldNavigate_MissingLeafKey(t *testing.T) {
	val := types.DefaultTypeAdapter.NativeToValue(map[string]any{"a": map[string]any{"b": 1}})
	result := fieldNavigate(val, "a.c")
	if result != types.NullValue {
		t.Fatalf("expected null for missing leaf key, got %v", result.Value())
	}
}

func TestFieldNavigate_EmptyPath(t *testing.T) {
	val := types.DefaultTypeAdapter.NativeToValue(map[string]any{"x": 1})
	result := fieldNavigate(val, "")
	// Empty path returns the value itself.
	if result != val {
		t.Fatalf("expected same value for empty path, got %v", result.Value())
	}
}

func TestFieldNavigate_EmptySegment(t *testing.T) {
	val := types.DefaultTypeAdapter.NativeToValue(map[string]any{"x": 1})
	result := fieldNavigate(val, "a..b")
	if result != types.NullValue {
		t.Fatalf("expected null for path with empty segment, got %v", result.Value())
	}
}

func TestFieldNavigate_NonMapValue(t *testing.T) {
	val := types.DefaultTypeAdapter.NativeToValue("not a map")
	result := fieldNavigate(val, "key")
	if result != types.NullValue {
		t.Fatalf("expected null when navigating non-map, got %v", result.Value())
	}
}

func TestEvaluatePredicate_FieldFunction(t *testing.T) {
	ok, err := EvaluatePredicate(
		`field(r, "settings.password.minLength") >= 15`,
		map[string]any{"settings": map[string]any{"password": map[string]any{"minLength": 20}}},
		map[string]any{},
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !ok {
		t.Fatalf("expected field() predicate to evaluate to true")
	}
}

func TestEvaluatePredicate_FieldMissingReturnsNull(t *testing.T) {
	ok, err := EvaluatePredicate(
		`field(r, "missing.path") == null`,
		map[string]any{"other": 1},
		map[string]any{},
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !ok {
		t.Fatalf("expected field() on missing path to return null")
	}
}

// Ensure ref import is used.
var _ ref.Val = types.NullValue
