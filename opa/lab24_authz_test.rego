package lab24.authz_test

import data.lab24.authz

principals := {
	"support_l1": {"allowed_tools": ["search_docs"], "purposes": ["summarize-tickets", "support-reply"]},
	"dpo": {"allowed_tools": ["search_docs", "read_customer"], "purposes": ["summarize-tickets", "support-reply", "privacy-audit"]},
}

base := {
	"data_classification": "restricted",
	"request_purpose": "support-reply",
	"agent_owner": "lab24-agent/run-b",
	"delegation_depth": 0,
	"egress_enabled": false,
	"principal_id": "dpo",
	"requested_tool": "read_customer",
	"agent_scopes": ["search_docs", "read_customer"],
	"parent_scopes": [],
	"expires_at": "2099-01-01T00:00:00+00:00",
}

test_dpo_can_read_for_valid_purpose if {
	authz.decision.allow with input as base with data.principals as principals
}

test_support_l1_cannot_read_restricted if {
	d := authz.decision with input as object.union(base, {"principal_id": "support_l1"})
		with data.principals as principals
	not d.allow
	d.reason == "deny: read_customer not in effective scopes"
}

test_restricted_egress_beats_full_authorization if {
	d := authz.decision with input as object.union(base, {"egress_enabled": true})
		with data.principals as principals
	not d.allow
	d.reason == "deny: restricted data with egress enabled"
}

test_delegation_cannot_expand_parent_scope if {
	d := authz.decision with input as object.union(base, {"delegation_depth": 1, "parent_scopes": ["search_docs"]})
		with data.principals as principals
	not d.allow
}

test_expired_unknown_and_garbage_expiry_are_denied if {
	every patch in [
		{"expires_at": "2000-01-01T00:00:00+00:00"},
		{"expires_at": "not-a-date"},
		{"principal_id": "nobody"},
	] {
		not authz.decision.allow with input as object.union(base, patch) with data.principals as principals
	}
}
