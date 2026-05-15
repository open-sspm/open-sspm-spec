package opensspm.entity.saas_app_overrides

entity := input.entity
primary_domain := lower(sprintf("%v", [object.get(entity, "primary_domain", "")]))
vendor_name := lower(sprintf("%v", [object.get(entity, "vendor_name", "")]))
owner_identity_id := object.get(entity, "owner_identity_id", 0)

github_domain if { primary_domain == "github.com" }
github_domain if { endswith(primary_domain, ".github.com") }
github_vendor if { vendor_name == "github" }
github_scoped if { github_domain }
github_scoped if { github_vendor }

default github_missing_owner := false
github_missing_owner if {
  github_scoped
  owner_identity_id == 0
}

signals := [{"id": "github_missing_owner", "severity": "critical", "title": "GitHub app has no accountable owner"}] if {
  github_missing_owner
}
signals := [] if {
  not github_missing_owner
}

risk_score := 20 if { github_missing_owner }
risk_score := 0 if { not github_missing_owner }

result := {
  "risk_level": "low",
  "risk_score": risk_score,
  "signals": signals,
}
