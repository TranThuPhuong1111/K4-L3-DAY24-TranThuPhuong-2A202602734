"""Bonus — PEP gọi OPA (opa/lab24_authz.rego) thay cho agent/policy.py.

Drop-in cho runner: cùng interface `check(PolicyContext) -> (allow, reason)`
và re-export `PolicyContext`, nên có thể thay `runner.policy` bằng module
này. Binary lấy từ biến môi trường OPA_BIN hoặc `opa` trong PATH.

Fail closed: OPA không chạy được hoặc trả kết quả lạ thì deny kèm reason.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import asdict
from pathlib import Path

from agent.policy import PRINCIPALS_FILE, PolicyContext, load_principals

__all__ = ["PolicyContext", "check", "check_many", "opa_binary"]

REGO_DIR = Path(__file__).resolve().parent.parent / "opa"
QUERY = "data.lab24.authz.batch"


def opa_binary() -> str | None:
    return os.environ.get("OPA_BIN") or shutil.which("opa")


def check_many(contexts: list[PolicyContext]) -> list[tuple[bool, str]]:
    binary = opa_binary()
    if binary is None:
        return [(False, "deny: OPA binary not found (fail closed)")] * len(contexts)

    with tempfile.TemporaryDirectory() as tmp:
        data_file = Path(tmp) / "principals.json"
        data_file.write_text(json.dumps({"principals": load_principals(PRINCIPALS_FILE)}),
                             encoding="utf-8")
        input_file = Path(tmp) / "input.json"
        input_file.write_text(json.dumps({"cases": [asdict(c) for c in contexts]}),
                              encoding="utf-8")
        # Bỏ *_test.rego: test file cần data giả riêng, không thuộc policy chạy thật.
        policies = [str(p) for p in sorted(REGO_DIR.glob("*.rego")) if not p.stem.endswith("_test")]
        args = [binary, "eval", "--format", "json", "--input", str(input_file),
                "--data", str(data_file)]
        for policy_file in policies:
            args += ["--data", policy_file]
        try:
            proc = subprocess.run([*args, QUERY], capture_output=True, text=True,
                                  encoding="utf-8", timeout=60)
            result = json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]
        except (OSError, subprocess.SubprocessError, ValueError, KeyError, IndexError) as exc:
            return [(False, f"deny: OPA evaluation failed ({type(exc).__name__})")] * len(contexts)

    if not isinstance(result, list) or len(result) != len(contexts):
        return [(False, "deny: OPA returned malformed batch result")] * len(contexts)
    decisions = []
    for item in result:
        reason = str(item.get("reason") or "").strip() if isinstance(item, dict) else ""
        allowed = isinstance(item, dict) and item.get("allow") is True and bool(reason)
        decisions.append((allowed, reason or "deny: OPA decision without reason"))
    return decisions


def check(context: PolicyContext) -> tuple[bool, str]:
    return check_many([context])[0]
