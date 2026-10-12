# Bonus — port agent/policy.py sang OPA/Rego (OPA v1.x, cú pháp Rego v1).
#
# Input  = các field của PolicyContext.
# data.principals = data/principals.json (nguồn tin cậy mô phỏng, KHÔNG nằm
# trong input để caller không tự khai quyền của mình).
#
# Chuỗi `else` giữ đúng thứ tự rule của check() bên Python: rule tối thiểu
# restricted + egress luôn được xét trước mọi quyền OBO. Mỗi reason là tiền
# tố của reason Python tương ứng, để test parity so được rule nào đã quyết.
package lab24.authz

classifications := {"public", "internal", "restricted"}

principal := data.principals[input.principal_id]

expiry_ns := time.parse_rfc3339_ns(input.expires_at)

delegated_scopes := {t | some t in input.parent_scopes}

base_scopes := {t | some t in principal.allowed_tools} & {t | some t in input.agent_scopes}

effective_scopes := base_scopes & delegated_scopes if input.delegation_depth > 0

effective_scopes := base_scopes if input.delegation_depth == 0

purposes := {p | some p in principal.purposes}

deny(reason) := {"allow": false, "reason": reason}

decision := deny("deny: restricted data with egress enabled") if {
	input.data_classification == "restricted"
	input.egress_enabled == true
} else := deny("deny: unknown data_classification") if {
	not input.data_classification in classifications
} else := deny("deny: invalid delegation_depth") if {
	input.delegation_depth < 0
} else := deny("deny: unknown principal") if {
	not principal
} else := deny("deny: missing or invalid expires_at") if {
	# parse lỗi -> expiry_ns undefined -> fail closed
	not expiry_ns
} else := deny("deny: delegation expired") if {
	expiry_ns <= time.now_ns()
} else := deny("deny: requested_tool is empty") if {
	input.requested_tool == ""
} else := deny(sprintf("deny: %s not in effective scopes", [input.requested_tool])) if {
	not input.requested_tool in effective_scopes
} else := deny("deny: purpose") if {
	not input.request_purpose in purposes
} else := {
	"allow": true,
	"reason": sprintf("allow: %s on %s data", [input.requested_tool, input.data_classification]),
}

# Đánh giá theo lô: input = {"cases": [ctx, ...]} -> một lần gọi opa.
batch := [d | some c in input.cases; d := decision with input as c]
