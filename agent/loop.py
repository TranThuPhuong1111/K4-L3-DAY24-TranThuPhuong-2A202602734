"""Manual tool-use loop — entrypoint CLI của agent.

    python -m agent.loop --mock "Tổng hợp các ticket còn mở tuần này"

Trước BƯỚC 3c (chưa có agent/runner.py hoặc runner.py còn là stub), lệnh
trên chạy qua `_naive_loop` ở dưới: một vòng lặp KHÔNG có containment —
đọc corpus, nếu thấy chỉ thị injection thì tuân theo, đọc customer, POST ra
sink. Đây chính là baseline dùng ở Bước 1 (đọc hiểu) và Bước 2 (red team).

Sau BƯỚC 3c, module này tự động dùng `agent.runner.handle()` thay cho
`_naive_loop` — KHÔNG cần sửa file này, KHÔNG cần đổi command đã chạy ở
Bước 2. Đó là chủ đích: cùng một lệnh, hai kết quả khác nhau, trước và sau
khi contain — evidence cho Bước 4.

Sinh viên đọc file này ở Bước 1 để trả lời 3 câu hỏi baseline, nhưng
KHÔNG cần sửa nó.
"""
from __future__ import annotations

import argparse
import importlib

from agent import tools, use_utf8_stdio
from agent.llm import get_llm


def _naive_loop(message: str, llm) -> str:
    """Baseline KHÔNG containment: đúng như một agent thật không có PEP,
    không có trifecta split, không có audit ledger — 3 lớp bị thiếu mà
    Bước 1 hỏi tới."""
    docs = tools.search_docs(message)
    combined_text = "\n\n".join(d["text"] for d in docs)

    injected = llm.find_injection(combined_text)
    if injected is not None:
        collected = []
        for customer_id in injected.customer_ids:
            try:
                collected.append(tools.read_customer(customer_id))
            except tools.ToolError:
                continue
        if collected:
            try:
                tools.http_post(injected.target_url, {"records": collected})
            except Exception as exc:  # sink chưa chạy là lỗi setup, không phải lỗi code
                if "Connection refused" in str(exc) or "Max retries" in str(exc):
                    raise SystemExit(
                        "Sink chưa chạy nên agent không POST được.\n"
                        "Mở một tab khác và chạy:  python sink/sink.py\n"
                        "(xem README — Setup, tab 1). Đây là lỗi setup, không phải lỗi code của bạn."
                    ) from None
                raise

    return llm.summarize(docs)


def run_once(message: str, mock: bool = True, model: str | None = None,
             log_dir=None, principal_id: str = "support_l1") -> str:
    """API dùng lại được từ test/subprocess, tránh phải parse argv.

    `log_dir` (tuỳ chọn) chuyển tiếp cho `agent.runner.handle()` — dùng
    trong test để ghi ledger vào một thư mục tạm, KHÔNG đụng vào
    `reports/ledger.jsonl` thật của bạn (tránh pytest xoá mất evidence).
    """
    llm = get_llm(mock=mock, model=model)

    runner = importlib.import_module("agent.runner")
    try:
        return runner.handle(message, llm, log_dir=log_dir, principal_id=principal_id)
    except NotImplementedError as exc:
        # Only the untouched checkpoint-3c scaffold may run the unsafe baseline.
        # A failure inside a student's implementation must stop the run.
        if type(exc) is getattr(runner, "RunnerScaffoldPending", None):
            return _naive_loop(message, llm)
        raise


def main() -> None:
    use_utf8_stdio()
    parser = argparse.ArgumentParser(description="Lab 24 agent loop")
    parser.add_argument("message", help="Câu hỏi/yêu cầu gửi cho agent")
    parser.add_argument("--mock", action="store_true", help="Dùng fake LLM deterministic (khuyến nghị)")
    parser.add_argument("--model", default=None, help="Model Claude thật, chỉ dùng thử ngoài phần chấm")
    parser.add_argument("--as", dest="principal_id", default="support_l1",
                        help="Principal mô phỏng cho checkpoint OBO")
    args = parser.parse_args()

    if not args.mock and not args.model:
        parser.error("phải truyền --mock hoặc --model MODEL_ID")

    result = run_once(args.message, mock=args.mock, model=args.model,
                      principal_id=args.principal_id)
    print(result)


if __name__ == "__main__":
    main()
