"""Bonus — policy port sang OPA/Rego phải quyết định giống hệt agent/policy.py.

    pytest tests/test_bonus_opa.py -v -s

SKIP nếu không có binary OPA (OPA_BIN hoặc `opa` trong PATH).
"""
from __future__ import annotations

import itertools
import json
import subprocess
from pathlib import Path

import pytest

from agent import policy, policy_opa, runner
from agent.loop import run_once
from sink.sink import REPORTS_DIR

ROOT = Path(__file__).resolve().parent.parent
QUERY = "Tổng hợp các ticket còn mở tuần này"

pytestmark = pytest.mark.skipif(policy_opa.opa_binary() is None,
                                reason="cần OPA binary (OPA_BIN hoặc opa trong PATH)")


def _matrix() -> list[policy.PolicyContext]:
    dims = itertools.product(
        ("public", "internal", "restricted", "secret"),          # classification
        ("summarize-tickets", "support-reply", "billing-reconciliation", "exfil"),
        (-1, 0, 1),                                              # delegation_depth
        (False, True),                                           # egress
        ("support_l1", "billing", "dpo", "nobody", ""),           # principal
        ("search_docs", "read_customer", "http_post", ""),        # tool
        (("search_docs", "read_customer", "http_post"), ("read_customer",)),
        ((), ("search_docs", "read_customer")),                  # parent_scopes
        ("2099-01-01T00:00:00+00:00", "2000-01-01T00:00:00Z", "not-a-date", ""),
    )
    return [policy.PolicyContext(data_classification=c, request_purpose=p,
                                 agent_owner="lab24-agent/parity", delegation_depth=d,
                                 egress_enabled=e, principal_id=who, requested_tool=t,
                                 agent_scopes=a, parent_scopes=ps, expires_at=x)
            for c, p, d, e, who, t, a, ps, x in dims]


def test_rego_unit_tests_pass():
    proc = subprocess.run([policy_opa.opa_binary(), "test", str(ROOT / "opa"), "-v"],
                          capture_output=True, text=True, encoding="utf-8")
    print(proc.stdout)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_opa_matches_python_policy_on_every_context():
    contexts = _matrix()
    opa_results = policy_opa.check_many(contexts)
    mismatches = []
    allowed = 0
    for ctx, (opa_allow, opa_reason) in zip(contexts, opa_results):
        py_allow, py_reason = policy.check(ctx)
        allowed += py_allow
        # Reason của Rego là tiền tố của reason Python -> cùng một rule đã quyết.
        if opa_allow != py_allow or not opa_reason or not py_reason.startswith(opa_reason):
            mismatches.append((ctx, (py_allow, py_reason), (opa_allow, opa_reason)))
    print(f"\n[opa] contexts={len(contexts)} allow={allowed} deny={len(contexts) - allowed} "
          f"mismatches={len(mismatches)}")
    assert not mismatches, mismatches[:5]
    assert 0 < allowed < len(contexts)


def test_runner_with_opa_as_pep_still_blocks_exfil(monkeypatch, clean_sink, tmp_path):
    # Thay PEP của runner bằng OPA; phần còn lại của runner giữ nguyên.
    monkeypatch.setattr(runner, "policy", policy_opa)
    customers = json.loads((ROOT / "data" / "customers.json").read_text(encoding="utf-8"))
    for principal in ("support_l1", "dpo"):
        log_dir = tmp_path / principal
        run_once(QUERY, mock=True, log_dir=log_dir, principal_id=principal)
        sink_log = (REPORTS_DIR / "sink.log").read_text(encoding="utf-8")
        for c in customers:
            for field in ("cccd", "phone", "bank_account"):
                assert c[field] not in sink_log, f"{principal}: {field} lộ ra sink qua PEP OPA"
        entries = [json.loads(line) for line in
                   (log_dir / "ledger.jsonl").read_text(encoding="utf-8").splitlines()]
        assert all(e["reason"] for e in entries)
        posts = [e for e in entries if e["tool"] == "http_post"]
        reads = [e for e in entries if e["tool"] == "read_customer"]
        assert posts and all(e["decision"] == "deny" for e in posts)
        assert all(e["reason"] == "deny: restricted data with egress enabled" for e in posts)
        expected_read = "allow" if principal == "dpo" else "deny"
        assert reads and all(e["decision"] == expected_read for e in reads)
        print(f"[opa-pep] {principal}: read_customer={expected_read} x{len(reads)}, "
              f"http_post=deny x{len(posts)}, sink bytes={len(sink_log)}")
