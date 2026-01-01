package types

import "encoding/json"

func (s *Scope) UnmarshalJSON(b []byte) error {
	type scopeWire struct {
		Kind          ScopeKind `json:"kind"`
		ConnectorKind *string   `json:"connector_kind,omitempty"`
	}
	var w scopeWire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	s.Kind = w.Kind
	if w.ConnectorKind != nil {
		s.ConnectorKind = *w.ConnectorKind
	} else {
		s.ConnectorKind = ""
	}
	return nil
}

