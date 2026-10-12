"""Bonus — chặn MCP rug pull bằng cách pin định nghĩa tool lúc duyệt.

Rug pull: server MCP được duyệt khi tool còn vô hại, sau đó đổi
description/inputSchema (chèn chỉ thị, thêm kênh exfil). Client tin
"đã duyệt một lần" sẽ đọc description mới vào context và gọi tool mới.

PinnedToolGuard:
  approve(): lúc người dùng duyệt, lấy tools/list, từ chối pin tool có
             description bị find_injection() flag, lưu sha256 của
             (name, description, inputSchema) cho từng tool.
  call():    TRƯỚC MỖI lần gọi, lấy lại tools/list và so fingerprint với pin.
             Lệch -> deny, không gọi tool, ghi ledger kèm reason. Cần duyệt lại.
Mọi quyết định allow/deny đều ghi qua agent.ledger.append().
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, pii
from agent.llm import find_injection

PROTOCOL_VERSION = "2025-06-18"


class McpError(RuntimeError):
    pass


class McpStdioClient:
    """Client JSON-RPC tối giản qua stdio của một subprocess MCP server."""

    def __init__(self, command: list[str], env: dict | None = None):
        self._proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      text=True, encoding="utf-8", env=env)
        self._next_id = 0
        self.notifications: list[str] = []
        self.request("initialize", {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                                    "clientInfo": {"name": "lab24-agent", "version": "0.1.0"}})
        self._write({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _write(self, message: dict) -> None:
        self._proc.stdin.write(json.dumps(message, ensure_ascii=False) + "\n")
        self._proc.stdin.flush()

    def request(self, method: str, params: dict | None = None) -> dict:
        self._next_id += 1
        self._write({"jsonrpc": "2.0", "id": self._next_id, "method": method,
                     "params": params or {}})
        while True:
            line = self._proc.stdout.readline()
            if not line:
                raise McpError(f"server đóng kết nối khi chờ {method}")
            message = json.loads(line)
            if "id" not in message:
                self.notifications.append(message.get("method", ""))
                continue
            if message["id"] != self._next_id:
                continue
            if "error" in message:
                raise McpError(message["error"].get("message", "unknown error"))
            return message["result"]

    def list_tools(self) -> list[dict]:
        return self.request("tools/list")["tools"]

    def call_tool(self, name: str, arguments: dict) -> dict:
        return self.request("tools/call", {"name": name, "arguments": arguments})

    def close(self) -> None:
        if self._proc.stdin:
            self._proc.stdin.close()
        self._proc.wait(timeout=10)


def tool_fingerprint(tool: dict) -> str:
    material = {k: tool.get(k) for k in ("name", "description", "inputSchema")}
    canonical = json.dumps(material, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class PinnedToolGuard:
    def __init__(self, client: McpStdioClient, ledger_path: Path, principal_id: str,
                 server_id: str = "lab24-rugpull"):
        self.client = client
        self.ledger_path = ledger_path
        self.principal_id = principal_id
        self.server_id = server_id
        self.run_id = f"{uuid.uuid4().hex[:12]}-mcp"
        self.expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(
            timespec="seconds")
        self.pins: dict[str, str] = {}

    def _log(self, tool: str, args: dict, decision: str, reason: str) -> None:
        ledger.append({
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "agent_id": "lab24-agent/mcp-client",
            "run_id": self.run_id,
            "on_behalf_of": self.principal_id,
            "expires_at": self.expires_at,
            "tool": f"mcp:{self.server_id}/{tool}",
            "args_hash": hashlib.sha256(json.dumps(args, sort_keys=True, ensure_ascii=False,
                                                   default=str).encode("utf-8")).hexdigest(),
            "classification": "internal",
            "decision": decision,
            "reason": pii.redact(reason),
        }, self.ledger_path)

    def approve(self) -> dict[str, str]:
        """Mô phỏng bước người dùng duyệt server: pin những tool sạch."""
        for tool in self.client.list_tools():
            injected = find_injection(tool.get("description", ""))
            if injected is not None:
                self._log(tool["name"], {"phase": "approve"}, "deny",
                          f"refuse to pin: description has injection markers "
                          f"{injected.matched_markers}")
                continue
            self.pins[tool["name"]] = tool_fingerprint(tool)
            self._log(tool["name"], {"phase": "approve"}, "allow",
                      f"pinned tool definition sha256={self.pins[tool['name']][:16]}…")
        return dict(self.pins)

    def call(self, name: str, arguments: dict) -> dict | None:
        current = {t["name"]: t for t in self.client.list_tools()}
        pinned = self.pins.get(name)
        if pinned is None or name not in current:
            self._log(name, arguments, "deny", f"tool {name!r} was never approved/pinned")
            return None
        now = tool_fingerprint(current[name])
        if now != pinned:
            injected = find_injection(current[name].get("description", ""))
            extra = f"; new description has injection markers {injected.matched_markers}" \
                if injected else ""
            self._log(name, arguments, "deny",
                      f"tool definition changed since approval (pinned {pinned[:16]}…, "
                      f"now {now[:16]}…) — possible MCP rug pull, re-approval required{extra}")
            return None
        self._log(name, arguments, "allow", f"tool definition matches pin {pinned[:16]}…")
        return self.client.call_tool(name, arguments)
