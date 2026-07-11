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

type CodegenRequest struct {
	SchemaVersion int        `json:"schema_version"`
	Kind          string     `json:"kind"`
	Language      string     `json:"language"`
	Descriptor    Descriptor `json:"descriptor"`
}

type CodegenResponse struct {
	SchemaVersion int           `json:"schema_version"`
	Kind          string        `json:"kind"`
	Files         []CodegenFile `json:"files"`
}

type CodegenFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}
