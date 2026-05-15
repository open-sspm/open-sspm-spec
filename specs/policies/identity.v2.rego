package opensspm.entity.identity_risk

entity := input.entity

default linked_critical_credential := false
linked_critical_credential if { object.get(entity, "has_critical_credential", false) == true }

default missing_accountable_owner := false
missing_accountable_owner if { lower(sprintf("%v", [object.get(entity, "owner_presence", "")])) == "unknown" }

default linked_high_risk_credential := false
linked_high_risk_credential if {
  object.get(entity, "has_high_risk_credential", false) == true
  object.get(entity, "has_critical_credential", false) != true
}

default linked_expired_credential := false
linked_expired_credential if { object.get(entity, "has_expired_credential", false) == true }

risky_evidence if {
  object.get(entity, "has_high_risk_credential", false) == true
}
risky_evidence if {
  object.get(entity, "has_expired_credential", false) == true
}
risky_evidence if {
  object.get(entity, "has_expiring_credential", false) == true
}
risky_evidence if {
  object.get(entity, "has_unused_credential", false) == true
}
risky_evidence if {
  object.get(entity, "has_stale_evidence", false) == true
}

default unreviewed_risky_principal := false
unreviewed_risky_principal if {
  lower(sprintf("%v", [object.get(entity, "governance_state", "")])) == "unreviewed"
  risky_evidence
}

default stale_or_unused_evidence := false
stale_or_unused_evidence if { object.get(entity, "has_expiring_credential", false) == true }
stale_or_unused_evidence if { object.get(entity, "has_unused_credential", false) == true }
stale_or_unused_evidence if { object.get(entity, "has_stale_evidence", false) == true }

signal_defs := [
  {"id": "linked_critical_credential", "severity": "critical", "title": "Linked credential is critical", "matched": linked_critical_credential},
  {"id": "missing_accountable_owner", "severity": "high", "title": "No accountable owner", "matched": missing_accountable_owner},
  {"id": "linked_high_risk_credential", "severity": "high", "title": "Linked credential is high risk", "matched": linked_high_risk_credential},
  {"id": "linked_expired_credential", "severity": "high", "title": "Linked credential is expired", "matched": linked_expired_credential},
  {"id": "unreviewed_risky_principal", "severity": "high", "title": "Unreviewed principal has risky evidence", "matched": unreviewed_risky_principal},
  {"id": "stale_or_unused_evidence", "severity": "medium", "title": "Principal has stale or aging evidence", "matched": stale_or_unused_evidence},
]

signals := [{"id": s.id, "severity": s.severity, "title": s.title} |
  s := signal_defs[_]
  s.matched
]

has_severity(level) if {
  signals[_].severity == level
}

risk_level := "critical" if { has_severity("critical") }
risk_level := "high" if {
  not has_severity("critical")
  has_severity("high")
}
risk_level := "medium" if {
  not has_severity("critical")
  not has_severity("high")
  has_severity("medium")
}
risk_level := "low" if {
  not has_severity("critical")
  not has_severity("high")
  not has_severity("medium")
}

result := {
  "risk_level": risk_level,
  "signals": signals,
}
