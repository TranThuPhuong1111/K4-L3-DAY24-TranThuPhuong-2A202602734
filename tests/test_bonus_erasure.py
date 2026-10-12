"""Bonus — delete cascade: xoá khách khỏi store + corpus mà ledger vẫn verify.

    pytest tests/test_bonus_erasure.py -v -s

Chạy trên BẢN SAO của data/customers.json và corpus/ trong tmp_path; file
thật không bị đụng tới.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from agent import ledger, tools
from agent.erasure import ERASED, PII_FIELDS, erase_customer
from agent.loop import run_once

ROOT = Path(__file__).resolve().parent.parent
QUERY = "Tổng hợp các ticket còn mở tuần này"


@pytest.fixture
def sandbox(tmp_path, monkeypatch, clean_sink):
    customers = tmp_path / "customers.json"
    corpus = tmp_path / "corpus"
    shutil.copy(ROOT / "data" / "customers.json", customers)
    shutil.copytree(ROOT / "corpus", corpus)
    monkeypatch.setattr(tools, "CUSTOMERS_FILE", customers)
    monkeypatch.setattr(tools, "CORPUS_DIR", corpus)
    ledger_path = tmp_path / "ledger.jsonl"
    run_once(QUERY, mock=True, log_dir=tmp_path, principal_id="dpo")  # ledger có sẵn lịch sử đọc
    return customers, corpus, ledger_path


def _pii(record: dict) -> list[str]:
    return [str(record[f]) for f in PII_FIELDS if record.get(f)]


@pytest.mark.parametrize("customer_id", ["KH-000999", "KH-000006"])
def test_cascade_erases_store_and_corpus_but_ledger_still_verifies(sandbox, customer_id):
    customers, corpus, ledger_path = sandbox
    record = tools.read_customer(customer_id)
    # Ticket không thuộc khách nhưng có nhắc tới họ -> phải được scrub, không bị xoá.
    mention = corpus / "ticket-050.md"
    mention.write_text(f"# Ticket #050 — chuyển tiếp\n\nLiên quan {customer_id}, "
                       f"email {record['email']}, SĐT {record['phone']}.\n", encoding="utf-8")
    before_lines = ledger_path.read_text(encoding="utf-8").splitlines()
    assert ledger.verify(ledger_path)

    denied = erase_customer(customer_id, "support_l1", ledger_path=ledger_path)
    assert denied["erased"] is False
    assert tools.read_customer(customer_id)  # support_l1 không xoá được gì

    result = erase_customer(customer_id, "dpo", ledger_path=ledger_path)
    print(f"\n[erasure] {customer_id}: {result}")
    assert result["erased"] and result["ledger_verified"]

    with pytest.raises(tools.ToolError):
        tools.read_customer(customer_id)
    owned = {f"ticket-{n:03d}.md" for n in record["related_tickets"]}
    assert owned.issubset(set(result["deleted_tickets"]) | {"ticket-905.md"})
    assert result["scrubbed_files"] == ["ticket-050.md"]
    assert mention.read_text(encoding="utf-8").count(ERASED) == 3
    corpus_text = "\n".join(p.read_text(encoding="utf-8") for p in corpus.glob("*.md"))
    store_text = customers.read_text(encoding="utf-8")
    ledger_text = ledger_path.read_text(encoding="utf-8")
    for value in _pii(record):
        assert value not in corpus_text, f"{value} còn trong corpus sau cascade"
        assert value not in store_text, f"{value} còn trong store"
        assert value not in ledger_text, f"{value} nằm trong ledger"

    after_lines = ledger_text.splitlines()
    assert after_lines[: len(before_lines)] == before_lines, "ledger cũ bị viết lại"
    assert [json.loads(line)["decision"] for line in after_lines[len(before_lines):]] == \
        ["deny", "allow", "allow"]
    assert ledger.verify(ledger_path)


def test_after_erasure_runner_can_no_longer_read_the_customer(sandbox, tmp_path, monkeypatch):
    _, _, ledger_path = sandbox
    erase_customer("KH-000999", "dpo", ledger_path=ledger_path)
    seen = []
    real_read = tools.read_customer
    monkeypatch.setattr(tools, "read_customer", lambda cid, *a, **k: seen.append(cid) or real_read(cid))
    run_once(QUERY, mock=True, log_dir=tmp_path / "after", principal_id="dpo")
    assert seen and "KH-000999" not in seen
    print(f"\n[erasure] runner sau khi xoá đọc {len(seen)} khách, không còn KH-000999")


def test_naive_erasure_by_deleting_ledger_lines_breaks_the_chain(sandbox):
    # Vì sao không được ghi PII vào ledger: nếu phải xoá dòng để xoá PII thì chuỗi gãy.
    _, _, ledger_path = sandbox
    lines = ledger_path.read_text(encoding="utf-8").splitlines()
    ledger_path.write_text("\n".join(lines[:2] + lines[3:]) + "\n", encoding="utf-8")
    assert ledger.verify(ledger_path) is False
