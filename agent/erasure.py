"""Bonus — delete cascade cho yêu cầu xoá dữ liệu, ledger vẫn verify.

erase_customer() xoá một khách khỏi store và lan sang corpus:
  1. PEP: policy.check(tool="delete_customer", purpose="erasure-request").
     Chỉ principal có tool này (dpo) được xoá; deny vẫn ghi ledger.
  2. Xoá record khỏi customers.json.
  3. Xoá các file ticket thuộc khách (related_tickets, kể cả phần "904b").
  4. Quét phần corpus còn lại, thay customer_id/họ tên/CCCD/SĐT/STK/email
     của khách bằng "[ERASED]".
  5. Ledger KHÔNG bị viết lại: nó chưa từng chứa PII thô (chỉ args_hash và
     reason đã redact), nên chỉ cần append một dòng tombstone. Chuỗi hash
     vẫn verify được, trong khi PII đã biến mất khỏi store và corpus.
Giới hạn: args_hash của customer_id là pseudonymous. Không gian ID nhỏ nên
có thể dò ngược; production nên dùng HMAC có khoá thay cho sha256 trần.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, policy, tools

ERASED = "[ERASED]"
_TICKET_PART_RE = re.compile(r"^ticket-(\d+)[a-z]?\.md$")
PII_FIELDS = ("customer_id", "name", "cccd", "phone", "bank_account", "email")


def _entry(principal_id: str, run_id: str, expires_at: str, args: dict,
           decision: str, reason: str) -> dict:
    return {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "agent_id": "lab24-agent/erasure",
        "run_id": run_id,
        "on_behalf_of": principal_id,
        "expires_at": expires_at,
        "tool": "delete_customer",
        "args_hash": hashlib.sha256(json.dumps(args, sort_keys=True).encode("utf-8")).hexdigest(),
        "classification": "restricted",
        "decision": decision,
        "reason": reason,
    }


def erase_customer(customer_id: str, principal_id: str, *, ledger_path: Path,
                   customers_file: Path | None = None, corpus_dir: Path | None = None,
                   purpose: str = "erasure-request") -> dict:
    customers_file = customers_file or tools.CUSTOMERS_FILE
    corpus_dir = corpus_dir or tools.CORPUS_DIR
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(timespec="seconds")
    run_id = f"erasure-{hashlib.sha256(f'{customer_id}{expires_at}'.encode()).hexdigest()[:12]}"
    args = {"customer_id": customer_id}

    allowed, reason = policy.check(policy.PolicyContext(
        data_classification="restricted", request_purpose=purpose,
        agent_owner="lab24-agent/erasure", delegation_depth=0, egress_enabled=False,
        principal_id=principal_id, requested_tool="delete_customer",
        agent_scopes=("delete_customer",), expires_at=expires_at,
    ))
    ledger.append(_entry(principal_id, run_id, expires_at, args,
                         "allow" if allowed else "deny", reason), ledger_path)
    if not allowed:
        return {"erased": False, "reason": reason}

    customers = json.loads(customers_file.read_text(encoding="utf-8"))
    record = next((c for c in customers if c["customer_id"] == customer_id), None)
    if record is None:
        ledger.append(_entry(principal_id, run_id, expires_at, args, "error",
                             "erasure target not found in store"), ledger_path)
        return {"erased": False, "reason": "not found"}

    customers.remove(record)
    customers_file.write_text(json.dumps(customers, ensure_ascii=False, indent=2) + "\n",
                              encoding="utf-8")

    owned = set(record.get("related_tickets", ()))
    deleted, scrubbed = [], []
    values = sorted({str(record[f]) for f in PII_FIELDS if record.get(f)}, key=len, reverse=True)
    for path in sorted(corpus_dir.glob("*.md")):
        match = _TICKET_PART_RE.match(path.name)
        if match and int(match.group(1)) in owned:
            path.unlink()
            deleted.append(path.name)
            continue
        text = path.read_text(encoding="utf-8")
        cleaned = text
        for value in values:
            cleaned = cleaned.replace(value, ERASED)
        if cleaned != text:
            path.write_text(cleaned, encoding="utf-8")
            scrubbed.append(path.name)

    ledger.append(_entry(principal_id, run_id, expires_at, args, "allow",
                         f"tombstone: store record removed; cascade deleted {len(deleted)} "
                         f"ticket file(s), scrubbed {len(scrubbed)} other file(s); "
                         f"ledger kept (no raw PII stored)"), ledger_path)
    return {"erased": True, "deleted_tickets": deleted, "scrubbed_files": scrubbed,
            "ledger_verified": ledger.verify(ledger_path)}
