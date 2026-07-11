package rulecheck

import (
	"strings"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
)

// Resolve returns a copy of check with omitted package and Rego source inherited
// from policy. A rule-level Rego source or path always takes precedence.
func Resolve(policy *types.RegoPolicy, check *types.Check) *types.Check {
	if check == nil {
		return nil
	}

	effective := *check
	if policy == nil {
		return &effective
	}
	if strings.TrimSpace(effective.Package) == "" {
		effective.Package = policy.Package
	}
	if strings.TrimSpace(effective.Rego) == "" && strings.TrimSpace(effective.RegoPath) == "" {
		effective.Rego = policy.Rego
		effective.RegoPath = policy.RegoPath
	}
	return &effective
}
