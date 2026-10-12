"""CLI in tiếng Việt không được crash khi stdout không phải UTF-8.

Trên Windows, stdout bị pipe dùng code page ANSI (cp1252). Ép
PYTHONIOENCODING=cp1252 để tái hiện điều kiện đó trên mọi OS.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _run(args: list[str]) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONIOENCODING": "cp1252", "PYTHONUTF8": "0"}
    return subprocess.run([sys.executable, *args], cwd=ROOT, env=env,
                          capture_output=True, timeout=60)


def test_check_lure_prints_vietnamese_on_cp1252_stdout():
    result = _run(["-m", "agent.check_lure", "corpus/ticket-901.md"])
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    assert "SẴN SÀNG" in result.stdout.decode("utf-8")


def test_loop_prints_vietnamese_on_cp1252_stdout():
    # Thay run_once để không ghi reports/ledger.jsonl thật; chỉ kiểm bước print.
    code = ("import sys, agent.loop as loop; "
            "loop.run_once = lambda *a, **k: 'Đã tổng hợp 1 ticket (ticket-001.md).'; "
            "sys.argv = ['loop', '--mock', 'ticket']; loop.main()")
    result = _run(["-c", code])
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    assert "Đã tổng hợp" in result.stdout.decode("utf-8")
