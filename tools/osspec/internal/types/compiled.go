package types

type Compiled[T any] struct {
	SourcePath string `json:"source_path"`
	Hash       string `json:"hash"`
	Object     T      `json:"object"`
}

type Descriptor struct {
	SchemaVersion     int                             `json:"schema_version"`
	Kind              string                          `json:"kind"`
	Version           Version                         `json:"version"`
	Rulesets          []Compiled[RulesetDoc]          `json:"rulesets"`
	EntityPolicyPacks []Compiled[EntityPolicyPackDoc] `json:"entity_policy_packs,omitempty"`
	Profiles          []Compiled[ProfileDoc]          `json:"profiles"`
}
