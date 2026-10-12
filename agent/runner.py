"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, pii, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

AGENT_ID = "lab24-agent"
RUN_TTL = timedelta(minutes=5)
# Quyền tối đa của orchestrator; run con chỉ được thu hẹp, không mở rộng.
ORCHESTRATOR_SCOPES = ("search_docs", "read_customer")
RUN_A_SCOPES = ("search_docs",)
RUN_B_SCOPES = ("read_customer",)
RUN_A_PURPOSE = "summarize-tickets"
RUN_B_PURPOSE = "support-reply"
# Đích egress cố định trong code — KHÔNG lấy URL từ free text của document.
EGRESS_URL = f"http://{tools.ALLOWED_EGRESS_HOST}:{tools.ALLOWED_EGRESS_PORT}/reconcile"

_TICKET_FILE_RE = re.compile(r"^ticket-(\d+)\.md$")


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


@dataclass(frozen=True)
class RunAOutput:
    """Thứ DUY NHẤT đi qua boundary A -> B: dữ liệu typed, không có free text."""
    ticket_ids: tuple[int, ...]
    injection_flagged: bool
    summary: str


@dataclass
class _Session:
    principal_id: str
    ledger_path: Path
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    expires_at: str = field(default_factory=lambda: (
        datetime.now(timezone.utc) + RUN_TTL).isoformat(timespec="seconds"))

    def run_id(self, name: str) -> str:
        return f"{self.request_id}-{name}"


def _args_hash(args: dict) -> str:
    canonical = json.dumps(args, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _log(session: _Session, run: str, tool: str, args: dict, classification: str,
         decision: str, reason: str, *, purpose: str, depth: int, egress: bool) -> None:
    ledger.append({
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "agent_id": f"{AGENT_ID}/{run}",
        "run_id": session.run_id(run),
        "request_id": session.request_id,
        "on_behalf_of": session.principal_id,
        "expires_at": session.expires_at,
        "tool": tool,
        "args_hash": _args_hash(args),
        "classification": classification,
        "purpose": purpose,
        "delegation_depth": depth,
        "egress_enabled": egress,
        "decision": decision,
        # Reason có thể nhắc lại input; redact để ledger không chứa PII thô.
        "reason": pii.redact(reason) or f"{decision} {tool}",
    }, session.ledger_path)


def _guarded_call(session: _Session, run: str, tool: str, args: dict, *,
                  classification: str, purpose: str, agent_scopes: tuple[str, ...],
                  egress: bool, invoke):
    """PEP: policy.check() TRƯỚC tool; ghi ledger cả allow lẫn deny; deny thì không gọi."""
    depth = 1  # mọi run con đều do orchestrator (depth 0) uỷ quyền
    context = policy.PolicyContext(
        data_classification=classification,
        request_purpose=purpose,
        agent_owner=f"{AGENT_ID}/{run}",
        delegation_depth=depth,
        egress_enabled=egress,
        principal_id=session.principal_id,
        requested_tool=tool,
        agent_scopes=agent_scopes,
        parent_scopes=ORCHESTRATOR_SCOPES,
        expires_at=session.expires_at,
    )
    allowed, reason = policy.check(context)
    meta = dict(purpose=purpose, depth=depth, egress=egress)
    _log(session, run, tool, args, classification, "allow" if allowed else "deny", reason, **meta)
    if not allowed:
        return None
    try:
        return invoke()
    except tools.ToolError as exc:
        _log(session, run, tool, args, classification, "error", f"tool error after allow: {exc}", **meta)
        return None


def _run_a(session: _Session, message: str, llm) -> RunAOutput:
    """Run A: chỉ chân untrusted content. Không private store, không egress."""
    docs = _guarded_call(
        session, "run-a", "search_docs", {"query": message},
        classification="internal", purpose=RUN_A_PURPOSE, agent_scopes=RUN_A_SCOPES,
        egress=False, invoke=lambda: tools.search_docs(message),
    ) or []

    injected = llm.find_injection("\n\n".join(d["text"] for d in docs))
    if injected is not None:
        # Chỉ log để làm bằng chứng; customer_ids/target_url của attacker bị bỏ.
        _log(session, "run-a", "llm.find_injection", {"docs": [d["id"] for d in docs]},
             "untrusted", "flag",
             f"injection markers {injected.matched_markers} found in untrusted docs; "
             f"{len(injected.customer_ids)} customer id(s) and target_url from free text "
             f"discarded — only filename ticket ids cross to Run B",
             purpose=RUN_A_PURPOSE, depth=1, egress=False)

    ticket_ids = sorted({int(m.group(1)) for d in docs
                         if (m := _TICKET_FILE_RE.match(d["id"]))})
    # PII gate: text đã redact trước khi vào context của LLM để tóm tắt.
    summary = llm.summarize([{"id": d["id"], "text": pii.redact(d["text"])} for d in docs])
    return RunAOutput(tuple(ticket_ids), injected is not None, summary)


def _customers_for_tickets(ticket_ids: tuple[int, ...]) -> list[str]:
    """Map ticket_id -> customer_id qua related_tickets (nguồn tin cậy).

    Chỉ chiếu 2 field định tuyến (customer_id, related_tickets); record đầy
    đủ chỉ được đọc qua read_customer sau khi PEP allow.
    """
    index = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    wanted = set(ticket_ids)
    return [c["customer_id"] for c in index if wanted & set(c.get("related_tickets", ()))]


def _run_b(session: _Session, handoff: RunAOutput) -> int:
    """Run B: chỉ chân private data, input là RunAOutput typed."""
    records = []
    for customer_id in _customers_for_tickets(handoff.ticket_ids):
        record = _guarded_call(
            session, "run-b", "read_customer", {"customer_id": customer_id},
            classification="restricted", purpose=RUN_B_PURPOSE, agent_scopes=RUN_B_SCOPES,
            egress=False, invoke=lambda cid=customer_id: tools.read_customer(cid),
        )
        if record is not None:
            records.append(record)

    if handoff.injection_flagged:
        # Agent "nghe lời" chỉ thị đã bị flag và xin egress. Payload là record
        # khách hàng -> restricted + egress -> PEP deny. Nếu có policy nào
        # allow nhầm, payload vẫn đi qua PII gate trước (defense in depth).
        payload = {"records": [json.loads(pii.redact(json.dumps(r, ensure_ascii=False)))
                               for r in records]}
        _guarded_call(
            session, "run-b", "http_post",
            {"url": EGRESS_URL, "record_ids": [r["customer_id"] for r in records]},
            classification="restricted", purpose=RUN_B_PURPOSE, agent_scopes=RUN_B_SCOPES,
            egress=True, invoke=lambda: tools.http_post(EGRESS_URL, payload),
        )
    return len(records)


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    ledger_path = Path(log_dir) / "ledger.jsonl" if log_dir else DEFAULT_LEDGER_PATH
    session = _Session(principal_id=principal_id, ledger_path=ledger_path)
    handoff = _run_a(session, message, llm)
    _run_b(session, handoff)
    return handoff.summary
