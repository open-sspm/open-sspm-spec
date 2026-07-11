package opensspm.rules.cis.okta.idaas_stig

signon_dataset := "okta:policies/sign-on"
admin_settings_dataset := "okta:apps/admin-console-settings"
password_dataset := "okta:policies/password"
app_signin_dataset := "okta:policies/app-signin"
log_streams_dataset := "okta:log-streams"
authenticators_dataset := "okta:authenticators"

dataset_ok(dataset) if {
  object.get(input.datasets, dataset, null) != null
  object.get(object.get(input.datasets, dataset, {}), "error", null) == null
}

rows(dataset) := object.get(object.get(input.datasets, dataset, {}), "rows", [])

dataset_error_result(dataset) := {"status": "unknown", "reason_code": "dataset_missing_dataset"} if {
  object.get(input.datasets, dataset, null) == null
}

dataset_error_result(dataset) := {"status": "unknown", "reason_code": sprintf("dataset_%s", [kind])} if {
  entry := object.get(input.datasets, dataset, {})
  err := object.get(entry, "error", null)
  err != null
  kind := object.get(err, "kind", "engine_error")
}

field_result(selected, _, _, on_empty) := {
  "status": "unknown",
  "reason_code": "empty_selection",
  "selected_count": 0,
  "passed_count": 0,
  "count_value": 0,
} if {
  count(selected) == 0
  on_empty == "unknown"
}

field_result(selected, _, _, on_empty) := {
  "status": "fail",
  "reason_code": "empty_selection",
  "selected_count": 0,
  "passed_count": 0,
  "count_value": 0,
} if {
  count(selected) == 0
  on_empty != "unknown"
}

field_result(selected, _, min_selected, _) := {
  "status": "fail",
  "reason_code": "min_selected_not_met",
  "selected_count": count(selected),
  "passed_count": 0,
  "count_value": count(selected),
  "target_value": min_selected,
} if {
  count(selected) > 0
  count(selected) < min_selected
}

field_result(selected, passed, min_selected, _) := {
  "status": "pass",
  "selected_count": count(selected),
  "passed_count": count(passed),
  "count_value": count(passed),
} if {
  count(selected) >= min_selected
  count(passed) == count(selected)
}

field_result(selected, passed, min_selected, _) := {
  "status": "fail",
  "selected_count": count(selected),
  "passed_count": count(passed),
  "count_value": count(passed),
} if {
  count(selected) >= min_selected
  count(passed) != count(selected)
}

count_result(selected, target) := {
  "status": "pass",
  "selected_count": count(selected),
  "passed_count": 1,
  "count_value": count(selected),
  "target_value": target,
} if {
  count(selected) >= target
}

count_result(selected, target) := {
  "status": "fail",
  "selected_count": count(selected),
  "passed_count": 0,
  "count_value": count(selected),
  "target_value": target,
} if {
  count(selected) < target
}

signon_default_priority1 := [r |
  r := rows(signon_dataset)[_]
  r.policy.name == "Default Policy"
  r.priority == 1
  r.name != "Default Rule"
]

active_password_policies := [r |
  r := rows(password_dataset)[_]
  r.status == "ACTIVE"
]

active_log_streams := [r |
  r := rows(log_streams_dataset)[_]
  r.status == "ACTIVE"
]

app_policies(label) := [r |
  r := rows(app_signin_dataset)[_]
  label in object.get(r, "app_labels", [])
]

authenticator_by_name(name) := [r |
  r := rows(authenticators_dataset)[_]
  r.name == name
]

results["OKTA-APP-000020"] := dataset_error_result(signon_dataset) if { not dataset_ok(signon_dataset) }
results["OKTA-APP-000020"] := field_result(signon_default_priority1, passed, 1, "fail") if {
  dataset_ok(signon_dataset)
  passed := [r |
    r := signon_default_priority1[_]
    r.actions.signon.session.maxSessionIdleMinutes == input.params.max_session_idle_minutes
  ]
}

results["OKTA-APP-000025"] := dataset_error_result(admin_settings_dataset) if { not dataset_ok(admin_settings_dataset) }
results["OKTA-APP-000025"] := field_result(selected, passed, 1, "unknown") if {
  dataset_ok(admin_settings_dataset)
  selected := rows(admin_settings_dataset)
  passed := [r | r := selected[_]; r.session_idle_timeout_minutes == 15]
}

results["OKTA-APP-000170"] := dataset_error_result(password_dataset) if { not dataset_ok(password_dataset) }
results["OKTA-APP-000170"] := field_result(active_password_policies, passed, 1, "unknown") if {
  dataset_ok(password_dataset)
  passed := [r | r := active_password_policies[_]; r.settings.password.lockout.maxAttempts == 3]
}

results["OKTA-APP-000180"] := dataset_error_result(app_signin_dataset) if { not dataset_ok(app_signin_dataset) }
results["OKTA-APP-000180"] := field_result(app_policies("Okta Dashboard"), passed, 1, "fail") if {
  dataset_ok(app_signin_dataset)
  passed := [r | r := app_policies("Okta Dashboard")[_]; r.requires_phishing_resistant == true]
}

results["OKTA-APP-000190"] := dataset_error_result(app_signin_dataset) if { not dataset_ok(app_signin_dataset) }
results["OKTA-APP-000190"] := field_result(app_policies("Okta Admin Console"), passed, 1, "fail") if {
  dataset_ok(app_signin_dataset)
  passed := [r | r := app_policies("Okta Admin Console")[_]; r.requires_phishing_resistant == true]
}

results["OKTA-APP-000560"] := dataset_error_result(app_signin_dataset) if { not dataset_ok(app_signin_dataset) }
results["OKTA-APP-000560"] := field_result(app_policies("Okta Admin Console"), passed, 1, "fail") if {
  dataset_ok(app_signin_dataset)
  passed := [r | r := app_policies("Okta Admin Console")[_]; r.requires_mfa == true]
}

results["OKTA-APP-000570"] := dataset_error_result(app_signin_dataset) if { not dataset_ok(app_signin_dataset) }
results["OKTA-APP-000570"] := field_result(app_policies("Okta Dashboard"), passed, 1, "fail") if {
  dataset_ok(app_signin_dataset)
  passed := [r | r := app_policies("Okta Dashboard")[_]; r.requires_mfa == true]
}

results["OKTA-APP-000650"] := dataset_error_result(password_dataset) if { not dataset_ok(password_dataset) }
results["OKTA-APP-000650"] := field_result(active_password_policies, passed, 1, "unknown") if {
  dataset_ok(password_dataset)
  passed := [r | r := active_password_policies[_]; r.settings.password.complexity.minLength >= 15]
}

results["OKTA-APP-000670"] := dataset_error_result(password_dataset) if { not dataset_ok(password_dataset) }
results["OKTA-APP-000670"] := field_result(active_password_policies, passed, 1, "unknown") if {
  dataset_ok(password_dataset)
  passed := [r | r := active_password_policies[_]; r.settings.password.complexity.minUpperCase >= 1]
}

results["OKTA-APP-000680"] := dataset_error_result(password_dataset) if { not dataset_ok(password_dataset) }
results["OKTA-APP-000680"] := field_result(active_password_policies, passed, 1, "unknown") if {
  dataset_ok(password_dataset)
  passed := [r | r := active_password_policies[_]; r.settings.password.complexity.minLowerCase >= 1]
}

results["OKTA-APP-000690"] := dataset_error_result(password_dataset) if { not dataset_ok(password_dataset) }
results["OKTA-APP-000690"] := field_result(active_password_policies, passed, 1, "unknown") if {
  dataset_ok(password_dataset)
  passed := [r | r := active_password_policies[_]; r.settings.password.complexity.minNumber >= 1]
}

results["OKTA-APP-000700"] := dataset_error_result(password_dataset) if { not dataset_ok(password_dataset) }
results["OKTA-APP-000700"] := field_result(active_password_policies, passed, 1, "unknown") if {
  dataset_ok(password_dataset)
  passed := [r | r := active_password_policies[_]; r.settings.password.complexity.minSymbol >= 1]
}

results["OKTA-APP-000740"] := dataset_error_result(password_dataset) if { not dataset_ok(password_dataset) }
results["OKTA-APP-000740"] := field_result(active_password_policies, passed, 1, "unknown") if {
  dataset_ok(password_dataset)
  passed := [r | r := active_password_policies[_]; r.settings.password.age.minAgeMinutes >= 1440]
}

results["OKTA-APP-000745"] := dataset_error_result(password_dataset) if { not dataset_ok(password_dataset) }
results["OKTA-APP-000745"] := field_result(active_password_policies, passed, 1, "unknown") if {
  dataset_ok(password_dataset)
  passed := [r | r := active_password_policies[_]; r.settings.password.age.maxAgeDays == 60]
}

results["OKTA-APP-001430"] := dataset_error_result(log_streams_dataset) if { not dataset_ok(log_streams_dataset) }
results["OKTA-APP-001430"] := count_result(active_log_streams, 1) if { dataset_ok(log_streams_dataset) }

results["OKTA-APP-001665"] := dataset_error_result(signon_dataset) if { not dataset_ok(signon_dataset) }
results["OKTA-APP-001665"] := field_result(signon_default_priority1, passed, 1, "fail") if {
  dataset_ok(signon_dataset)
  passed := [r | r := signon_default_priority1[_]; r.actions.signon.session.maxSessionLifetimeMinutes == 1080]
}

results["OKTA-APP-001670"] := dataset_error_result(authenticators_dataset) if { not dataset_ok(authenticators_dataset) }
results["OKTA-APP-001670"] := field_result(authenticator_by_name("Smart Card Authenticator"), passed, 1, "fail") if {
  dataset_ok(authenticators_dataset)
  passed := [r | r := authenticator_by_name("Smart Card Authenticator")[_]; r.status == "ACTIVE"]
}

results["OKTA-APP-001700"] := dataset_error_result(authenticators_dataset) if { not dataset_ok(authenticators_dataset) }
results["OKTA-APP-001700"] := field_result(authenticator_by_name("Okta Verify"), passed, 1, "fail") if {
  dataset_ok(authenticators_dataset)
  passed := [r | r := authenticator_by_name("Okta Verify")[_]; r.okta_verify_compliance_fips == "REQUIRED"]
}

results["OKTA-APP-001710"] := dataset_error_result(signon_dataset) if { not dataset_ok(signon_dataset) }
results["OKTA-APP-001710"] := field_result(signon_default_priority1, passed, 1, "fail") if {
  dataset_ok(signon_dataset)
  passed := [r | r := signon_default_priority1[_]; r.actions.signon.session.usePersistentCookie == false]
}

results["OKTA-APP-002980"] := dataset_error_result(password_dataset) if { not dataset_ok(password_dataset) }
results["OKTA-APP-002980"] := field_result(active_password_policies, passed, 1, "unknown") if {
  dataset_ok(password_dataset)
  passed := [r | r := active_password_policies[_]; r.settings.password.complexity.dictionary.common.exclude == true]
}

results["OKTA-APP-003010"] := dataset_error_result(password_dataset) if { not dataset_ok(password_dataset) }
results["OKTA-APP-003010"] := field_result(active_password_policies, passed, 1, "unknown") if {
  dataset_ok(password_dataset)
  passed := [r | r := active_password_policies[_]; r.settings.password.age.historyCount >= 5]
}
