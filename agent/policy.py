"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PRINCIPALS_FILE = Path(__file__).resolve().parent.parent / "data" / "principals.json"
KNOWN_CLASSIFICATIONS = ("public", "internal", "restricted")


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def load_principals(path: Path | None = None) -> dict:
    """Nguồn tin cậy MÔ PHỎNG cho OBO — không phải xác thực production."""
    return json.loads((path or PRINCIPALS_FILE).read_text(encoding="utf-8"))


def _parse_expiry(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None
    # Thời điểm không kèm múi giờ là mơ hồ -> coi như không hợp lệ (fail closed).
    return parsed if parsed.tzinfo is not None else None


def effective_scopes(context: PolicyContext, principal: dict) -> set[str]:
    scopes = set(principal.get("allowed_tools", ())) & set(context.agent_scopes)
    if context.delegation_depth > 0:
        scopes &= set(context.parent_scopes)
    return scopes


def check(context: PolicyContext) -> tuple[bool, str]:
    """Deny-by-default: chỉ allow khi qua MỌI điều kiện; mọi nhánh có reason."""
    who = context.principal_id or "<none>"

    # Rule tối thiểu đứng đầu: không quyền OBO nào gỡ được nó.
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, (f"deny: restricted data with egress enabled "
                       f"(tool={context.requested_tool or '<none>'}, principal={who}, "
                       f"agent={context.agent_owner})")
    if context.data_classification not in KNOWN_CLASSIFICATIONS:
        return False, f"deny: unknown data_classification {context.data_classification!r}"
    if context.delegation_depth < 0:
        return False, f"deny: invalid delegation_depth {context.delegation_depth}"

    principals = load_principals()
    principal = principals.get(context.principal_id)
    if principal is None:
        return False, f"deny: unknown principal {who!r} (not in data/principals.json)"

    expiry = _parse_expiry(context.expires_at)
    if expiry is None:
        return False, f"deny: missing or invalid expires_at {context.expires_at!r}"
    if expiry <= datetime.now(timezone.utc):
        return False, f"deny: delegation expired at {context.expires_at}"

    if not context.requested_tool:
        return False, "deny: requested_tool is empty"
    scopes = effective_scopes(context, principal)
    if context.requested_tool not in scopes:
        chain = "principal ∩ agent_scopes" + (" ∩ parent_scopes" if context.delegation_depth > 0 else "")
        return False, (f"deny: {context.requested_tool} not in effective scopes "
                       f"{sorted(scopes)} ({chain}) for principal {who!r}")

    if context.request_purpose not in principal.get("purposes", ()):
        return False, (f"deny: purpose {context.request_purpose!r} not allowed for "
                       f"principal {who!r}")

    return True, (f"allow: {context.requested_tool} on {context.data_classification} data for "
                  f"principal {who!r}, purpose {context.request_purpose!r}, "
                  f"depth={context.delegation_depth}, egress={context.egress_enabled}")
