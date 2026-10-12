"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re

# Thứ tự ưu tiên khi các match chồng nhau: pattern đứng trước thắng.
# STK có ngữ cảnh đứng đầu vì một STK 12 chữ số trông y hệt CCCD — chỉ từ
# khoá "STK"/"số tài khoản" ngay trước mới phân biệt được hai loại.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("VN_BANK_ACCOUNT", re.compile(
        r"(?i)(?:\bSTK|s[oố]\s+t[aà]i\s+kho[aả]n|\bt[aà]i\s+kho[aả]n|\baccount)"
        r"[\s:.#-]{0,5}(?:l[aà]\s+)?(?P<value>(?<!\d)\d{8,16}(?!\d))"
    )),
    ("VN_CCCD", re.compile(r"(?<!\d)\d{12}(?!\d)")),
    # 0xxxxxxxxx (10 số) hoặc +84xxxxxxxxx, cho phép dấu cách/chấm/gạch giữa nhóm.
    ("VN_PHONE", re.compile(r"(?<![\d+])(?:\+84|0)(?:[\s.-]?\d){9}(?!\d)")),
    # Lưới an toàn: chuỗi 8–16 chữ số còn sót lại coi như STK, để redact
    # theo hướng fail-closed (thà che nhầm một mã số còn hơn lộ STK).
    ("VN_BANK_ACCOUNT", re.compile(r"(?<!\d)\d{8,16}(?!\d)")),
]


def detect(text: str) -> list[dict]:
    entities: list[dict] = []
    taken: list[tuple[int, int]] = []
    for entity_type, pattern in _PATTERNS:
        for match in pattern.finditer(text):
            group = "value" if "value" in pattern.groupindex else 0
            start, end = match.span(group)
            if any(start < t_end and t_start < end for t_start, t_end in taken):
                continue
            taken.append((start, end))
            entities.append({"type": entity_type, "start": start, "end": end})
    return sorted(entities, key=lambda e: e["start"])


def redact(text: str) -> str:
    # detect() đã loại overlap; thay từ cuối về đầu để offset không lệch.
    for entity in sorted(detect(text), key=lambda e: e["start"], reverse=True):
        text = text[: entity["start"]] + f"[REDACTED_{entity['type']}]" + text[entity["end"]:]
    return text
