package celengine

import "testing"

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
