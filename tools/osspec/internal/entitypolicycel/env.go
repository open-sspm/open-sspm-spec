package entitypolicycel

import (
	"github.com/google/cel-go/cel"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
)

func EnvOptions(domain types.EntityPolicyDomain, constants map[string][]string) []cel.EnvOption {
	opts := DomainEnvOptions(domain)
	for name := range constants {
		opts = append(opts, cel.Variable(name, cel.ListType(cel.StringType)))
	}
	return opts
}

func DomainEnvOptions(domain types.EntityPolicyDomain) []cel.EnvOption {
	switch domain {
	case types.EntityPolicyDomainCredential:
		return []cel.EnvOption{
			cel.Variable("source_kind", cel.StringType),
			cel.Variable("source_name", cel.StringType),
			cel.Variable("credential_kind", cel.StringType),
			cel.Variable("status", cel.StringType),
			cel.Variable("expires_at", cel.NullableType(cel.TimestampType)),
			cel.Variable("last_used_at", cel.NullableType(cel.TimestampType)),
			cel.Variable("created_at", cel.NullableType(cel.TimestampType)),
			cel.Variable("created_by_external_id", cel.StringType),
			cel.Variable("created_by_display_name", cel.StringType),
			cel.Variable("approved_by_external_id", cel.StringType),
			cel.Variable("approved_by_display_name", cel.StringType),
			cel.Variable("asset_ref_kind", cel.StringType),
			cel.Variable("asset_ref_external_id", cel.StringType),
			cel.Variable("scope_json", cel.DynType),
			cel.Variable("evaluated_at", cel.TimestampType),
		}
	case types.EntityPolicyDomainSaaS:
		return []cel.EnvOption{
			cel.Variable("canonical_key", cel.StringType),
			cel.Variable("display_name", cel.StringType),
			cel.Variable("primary_domain", cel.StringType),
			cel.Variable("vendor_name", cel.StringType),
			cel.Variable("source_kind", cel.StringType),
			cel.Variable("source_name", cel.StringType),
			cel.Variable("category", cel.StringType),
			cel.Variable("actors_30d", cel.IntType),
			cel.Variable("has_privileged_scope", cel.BoolType),
			cel.Variable("has_confidential_scope", cel.BoolType),
			cel.Variable("managed_state", cel.StringType),
			cel.Variable("managed_reason", cel.StringType),
			cel.Variable("owner_identity_id", cel.IntType),
			cel.Variable("governance_state", cel.StringType),
			cel.Variable("review_disposition", cel.StringType),
			cel.Variable("follow_up_due_date", cel.NullableType(cel.TimestampType)),
			cel.Variable("configured_business_criticality", cel.StringType),
			cel.Variable("configured_data_classification", cel.StringType),
			cel.Variable("effective_business_criticality", cel.StringType),
			cel.Variable("effective_data_classification", cel.StringType),
			cel.Variable("connector_binding_configured", cel.BoolType),
			cel.Variable("connector_binding_enabled", cel.BoolType),
			cel.Variable("connector_binding_stale", cel.BoolType),
			cel.Variable("connector_binding_healthy", cel.BoolType),
			cel.Variable("score", cel.IntType),
		}
	case types.EntityPolicyDomainIdentity:
		return []cel.EnvOption{
			cel.Variable("identity_id", cel.IntType),
			cel.Variable("principal_ref", cel.StringType),
			cel.Variable("principal_type", cel.StringType),
			cel.Variable("source_kind", cel.StringType),
			cel.Variable("source_name", cel.StringType),
			cel.Variable("display_name", cel.StringType),
			cel.Variable("primary_email", cel.StringType),
			cel.Variable("last_seen_at", cel.NullableType(cel.TimestampType)),
			cel.Variable("owner_presence", cel.StringType),
			cel.Variable("governance_state", cel.StringType),
			cel.Variable("linked_assets_count", cel.IntType),
			cel.Variable("linked_credentials_count", cel.IntType),
			cel.Variable("credential_signals", cel.ListType(cel.StringType)),
			cel.Variable("has_critical_credential", cel.BoolType),
			cel.Variable("has_high_risk_credential", cel.BoolType),
			cel.Variable("has_expired_credential", cel.BoolType),
			cel.Variable("has_expiring_credential", cel.BoolType),
			cel.Variable("has_unused_credential", cel.BoolType),
			cel.Variable("has_stale_evidence", cel.BoolType),
		}
	default:
		return nil
	}
}
