# DPIA-lite — checkpoint 5

**Hệ thống đánh giá:** agent hỗ trợ khách hàng trong repo này, chạy `--mock` trên dữ liệu **synthetic**. Đây là bài tập đánh giá tác động rút gọn cho một mô phỏng, không phải hồ sơ đánh giá tác động theo mẫu pháp định. Điều khoản pháp luật đã đối chiếu với bản Công báo, kèm các điểm còn `chưa xác minh`, xem `reports/compliance-mapping.md`. Cấu trúc 4 mục dưới đây bám một phần nội dung báo cáo DPIA ở NĐ 356/2025/NĐ-CP Điều 19 khoản 3 (điểm c, đ, g), nhưng **không** theo Mẫu số 10.

## 1. Loại dữ liệu và phân loại

| Nguồn | Nội dung | Phân loại trong runner | Ghi chú |
|---|---|---|---|
| `corpus/ticket-*.md` (45 file) | Nội dung ticket do khách/attacker viết, **có lẫn PII** (STK, SĐT trong ticket thường) và có 4 lure 901–904b | `internal` cho `search_docs`; nội dung coi là **untrusted** (`llm.find_injection` decision `flag`) | Là bề mặt tấn công prompt injection |
| `data/customers.json` (26 khách synthetic) | Họ tên, **CCCD** (số định danh cá nhân), SĐT, **STK** ngân hàng, email, `related_tickets` | `restricted` cho `read_customer` và mọi `http_post` mang record | `KH-000999` là nạn nhân của lure, `KH-000777` không gắn ticket nào |
| `data/principals.json` | Vai trò, `allowed_tools`, `purposes` | Cấu hình tin cậy **mô phỏng** | Không phải danh tính thật |

**Đối chiếu phân loại pháp lý [Công báo]:** NĐ 356/2025 Điều 3 xếp họ tên (khoản 1), **số điện thoại và số định danh cá nhân** (khoản 7) vào dữ liệu cá nhân **cơ bản**. Điều 4 khoản 1 điểm k xếp thông tin thẻ, lịch sử giao dịch và thông tin tài chính tại tổ chức tín dụng vào dữ liệu **nhạy cảm**. Điểm i chỉ coi *hình ảnh* thẻ căn cước là nhạy cảm, còn *số* CCCD thì không. Lab vẫn phân loại toàn bộ record là `restricted`, **chặt hơn** mức pháp lý tối thiểu, vì CCCD + SĐT + STK đi cùng nhau đủ để chiếm đoạt tài khoản. Việc một STK đứng riêng có tính là "thông tin tài chính" nhạy cảm hay không vẫn `chưa xác minh`.
| `reports/ledger.jsonl` | Metadata tool call: principal, run, tool, `args_hash`, decision, reason | Audit log, không chứa PII thô | Reason được `pii.redact()` |

## 2. Mục đích xử lý và principal

| Principal (`--as`, mô phỏng) | Tool được phép | Purpose được phép | Kết quả trên lab |
|---|---|---|---|
| `support_l1` | `search_docs` | `summarize-tickets`, `support-reply` | Tóm tắt ticket được. **Mọi** `read_customer` bị deny (`reports/ledger.jsonl:27-47`) nên không chạm CCCD/STK |
| `dpo` | `search_docs`, `read_customer`, `delete_customer` (bonus) | `summarize-tickets`, `support-reply`, `privacy-audit`, `erasure-request` (bonus) | Đọc 21 khách gắn với ticket hợp lệ, purpose `support-reply` (`reports/ledger.jsonl:3-23`). Là principal duy nhất xoá được khách (`agent/erasure.py`) |
| `billing` | `search_docs`, `read_customer` | `summarize-tickets`, `billing-reconciliation` | Không chạy trong lab. Runner dùng purpose `support-reply` cho Run B nên `billing` sẽ bị deny vì purpose |

Mục đích của Run A là `summarize-tickets`, của Run B là `support-reply`. Không principal nào có `http_post` trong `allowed_tools`, và không purpose nào cần egress.

## 3. Dữ liệu đi qua những run/tool nào, endpoint nào

```
user query ──► Run A (agent_id lab24-agent/run-a, scopes {search_docs})
                 search_docs(corpus/)  ── PEP allow ──► ledger
                 find_injection(text)  ── flag ───────► ledger (customer_id/URL của attacker bị bỏ)
                 pii.redact(text) ──► llm.summarize ──► câu trả lời cho user
                 │
                 └─ RunAOutput{ticket_ids: list[int] từ TÊN FILE, injection_flagged: bool}
                      (không có free text nào qua boundary)
                                   ▼
               Run B (agent_id lab24-agent/run-b, scopes {read_customer})
                 ticket_id ─► related_tickets (data/customers.json) ─► customer_id
                 read_customer(id)  ── PEP: OBO scope ∩ parent ∩ purpose ∩ TTL ──► ledger
                 http_post(http://127.0.0.1:10024/reconcile)
                                    ── PEP: restricted + egress ⇒ DENY ──► ledger
```

- **Endpoint duy nhất:** `http://127.0.0.1:10024/*` (sink local, `sink/sink.py`), bị allowlist cứng trong `agent/tools.py:77-83`. URL egress của runner là hằng số `agent/runner.py:84`, không lấy từ document.
- **Trước containment:** record đầy đủ của `KH-000999` tới sink (`reports/attack-before.log`, `reports/attack-before-variants.log`, cả 4 biến thể).
- **Sau containment:** không request nào tới sink (`reports/attack-after.log` 0 byte; `reports/attack-after-variants.log`: 8/8 lần chạy `sink lines=0`).
- Không có dữ liệu nào rời máy: không gọi API LLM (`--mock`), không cloud.

## 4. Bằng chứng deny/allow và giới hạn của mock

**Bằng chứng:**
- `reports/ledger.jsonl` (48 dòng, `verify()` = True): dòng 1 và 25 là `search_docs` allow. Dòng 2 và 26 là `llm.find_injection` flag. Dòng 3–23 là `dpo` `read_customer` allow. Dòng 27–47 là `support_l1` `read_customer` deny (`not in effective scopes []`). Dòng 24 (`dpo`) và 48 (`support_l1`) là `http_post` **deny** với reason `deny: restricted data with egress enabled …`. Mọi dòng có `reason`, `on_behalf_of`, `run_id`, `expires_at`.
- Sửa dòng 24 từ `deny` thành `allow` trên một bản sao mà không tính lại hash thì `verify()` trả False.
- `python -m pytest tests/ -q`: 45 passed, gồm 10 test bonus (xem `reports/verification.md`).
- **Xoá theo yêu cầu (bonus, Luật 91 Điều 14; NĐ 356 Điều 5 khoản 4):** `agent/erasure.py` xoá record, xoá ticket thuộc khách, scrub nơi khác nhắc tới khách. Ledger **không** phải viết lại vì chưa từng chứa PII thô, và vẫn `verify()` True (`reports/bonus/erasure.log`). Xoá dòng ledger để "xoá PII" sẽ làm gãy chuỗi, nên không ghi PII vào ledger là điều kiện tiên quyết.

**Rủi ro còn lại và giới hạn:**
1. **Mock ≠ model thật.** `find_injection` là heuristic ≥2 marker. Một model thật có thể bị hijack bằng lure không chứa marker nào. Containment vẫn đứng vì Run B không đọc free text và PEP không dựa vào việc phát hiện injection. Nhưng chất lượng tóm tắt và hành vi khác của model thật chưa được đánh giá.
2. **Principal là mô phỏng.** `--as` không xác thực ai cả. TTL 5 phút do runner tự cấp. Production cần IdP, token ký số và scope do hệ thống phân quyền cấp.
3. **Lure gắn vào hồ sơ nạn nhân.** `KH-000999` có `related_tickets` 901–905, nên dưới `dpo` hồ sơ vẫn được **đọc** hợp lệ. Chỉ rule egress chặn rò rỉ. Nếu sau này có purpose cần egress, phải có thêm kiểm soát payload (redact đã có ở `agent/runner.py:220`) và allowlist đích.
4. **PII regex** đạt precision/recall 1.000 trên 118 entity synthetic theo mẫu, nhưng chưa có PERSON, địa chỉ, ngày sinh. Dữ liệu thật sẽ có định dạng lệch mẫu. Lưới an toàn "8–16 chữ số ⇒ STK" có thể che nhầm mã đơn hàng.
5. **Ledger** chỉ tamper-evident trong file: không phát hiện được cắt đuôi hoặc viết lại toàn chuỗi khi không có mốc tin cậy bên ngoài, và không phải log bất biến.
6. **Corpus chứa PII** (STK/SĐT trong ticket thường) và được đọc ở dạng thô trong Run A. Hiện chỉ redact trước khi tóm tắt. Production nên redact ngay lúc ingest.
7. Quyền xoá mới ở mức bonus: thực hiện ngay, không mô hình hoá tiếp nhận, xác minh người yêu cầu, thời hạn 02/20/30 ngày (NĐ 356 Điều 5 khoản 4), không wipe an toàn và không dọn lịch sử Git/backup. Chưa xử lý thời hạn lưu trữ, căn cứ pháp lý/đồng ý, thông báo xử lý tự động (NĐ 356 Điều 10 khoản 3).
8. `args_hash` (sha256 trần của customer_id) là dữ liệu bút danh: không gian ID nhỏ nên có thể dò ngược. Production nên dùng HMAC có khoá.
