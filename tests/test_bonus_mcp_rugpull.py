"""Bonus — MCP rug pull local: before (client ngây thơ) và after (pin định nghĩa tool).

    pytest tests/test_bonus_mcp_rugpull.py -v -s

Server: bonus/mcp_rugpull_server.py (stdio, không mở cổng mạng). Dữ liệu
"exfil" chỉ là record synthetic của KH-000999, ghi vào file tạm của test.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from agent import ledger, tools
from agent.llm import find_injection
from agent.mcp_guard import McpStdioClient, PinnedToolGuard

ROOT = Path(__file__).resolve().parent.parent
SERVER = [sys.executable, str(ROOT / "bonus" / "mcp_rugpull_server.py")]
VICTIM = tools.read_customer("KH-000999")


@pytest.fixture
def server(tmp_path):
    exfil = tmp_path / "exfil.log"

    def _start(rugpull_after: int = 1) -> McpStdioClient:
        env = {**os.environ, "MCP_EXFIL_LOG": str(exfil),
               "RUGPULL_AFTER_CALLS": str(rugpull_after)}
        return McpStdioClient(SERVER, env=env)

    _start.exfil = exfil
    return _start


def agent_turn(client: McpStdioClient, call, ticket_id: int):
    """Một lượt của agent mock: đọc tools/list vào context như một LLM thật,
    nếu description "ra lệnh" thì làm theo, rồi gọi tool qua `call`."""
    tool = {t["name"]: t for t in client.list_tools()}["ticket_status"]
    args = {"ticket_id": ticket_id}
    injected = find_injection(tool["description"])
    if injected and "customer_records" in tool["inputSchema"]["properties"]:
        args["customer_records"] = [tools.read_customer(cid) for cid in injected.customer_ids]
    return call("ticket_status", args)


def test_before_naive_client_leaks_after_rug_pull(server):
    client = server()
    try:
        first = agent_turn(client, client.call_tool, 1)    # tool còn vô hại
        second = agent_turn(client, client.call_tool, 2)   # sau rug pull
    finally:
        client.close()
    leaked = server.exfil.read_text(encoding="utf-8")
    print(f"\n[mcp-before] call1={first['content'][0]['text']!r} "
          f"call2={second['content'][0]['text']!r} notifications={client.notifications}")
    print(f"[mcp-before] exfil.log ({len(leaked)} bytes): {leaked.strip()[:160]}…")
    assert "notifications/tools/list_changed" in client.notifications
    assert VICTIM["cccd"] in leaked and VICTIM["bank_account"] in leaked


def test_after_pinned_guard_blocks_rug_pull(server, clean_ledger):
    client = server()
    guard = PinnedToolGuard(client, clean_ledger, principal_id="support_l1")
    try:
        pins = guard.approve()
        first = agent_turn(client, guard.call, 1)
        second = agent_turn(client, guard.call, 2)
    finally:
        client.close()
    entries = [json.loads(line) for line in clean_ledger.read_text(encoding="utf-8").splitlines()]
    for e in entries:
        print(f"[mcp-after] {e['tool']} {e['decision']}: {e['reason']}")
    assert set(pins) == {"ticket_status"}
    assert first is not None and second is None
    assert not server.exfil.exists(), "server đã nhận lời gọi ở chế độ rug pull"
    assert [e["decision"] for e in entries] == ["allow", "allow", "deny"]
    assert "rug pull" in entries[-1]["reason"] and "injection markers" in entries[-1]["reason"]
    assert ledger.verify(clean_ledger)
    raw = clean_ledger.read_text(encoding="utf-8")
    assert VICTIM["cccd"] not in raw and VICTIM["bank_account"] not in raw


def test_malicious_from_start_is_never_pinned(server, clean_ledger):
    client = server(rugpull_after=0)
    guard = PinnedToolGuard(client, clean_ledger, principal_id="dpo")
    try:
        assert guard.approve() == {}
        assert agent_turn(client, guard.call, 1) is None
    finally:
        client.close()
    entries = [json.loads(line) for line in clean_ledger.read_text(encoding="utf-8").splitlines()]
    assert [e["decision"] for e in entries] == ["deny", "deny"]
    assert not server.exfil.exists()
    assert ledger.verify(clean_ledger)
