# Bonus

Ba mục bonus, mỗi mục có test và log riêng. Theo RUBRIC tổng là 4 + 4 + 3 = 11, tối đa được tính **10** điểm. Không mục nào thay cho điều kiện trượt. Mục GLiNER so với regex (3đ) **không làm**: cần cài torch và tải model, chưa thử trên Python 3.14/Windows.

| Mục | Điểm RUBRIC | Code | Test | Log |
|---|---:|---|---|---|
| Port policy sang OPA | 4 | `opa/lab24_authz.rego`, `opa/lab24_authz_test.rego`, `agent/policy_opa.py` | `tests/test_bonus_opa.py` (3) + `opa test opa/` (5) | `reports/bonus/opa.log` |
| MCP rug pull local | 4 | `bonus/mcp_rugpull_server.py`, `agent/mcp_guard.py` | `tests/test_bonus_mcp_rugpull.py` (3) | `reports/bonus/mcp_rugpull.log` |
| Delete cascade giữ ledger verify | 3 | `agent/erasure.py`, `data/principals.json` (cấp `delete_customer` + `erasure-request` cho `dpo`) | `tests/test_bonus_erasure.py` (4) | `reports/bonus/erasure.log` |

Tái hiện: `python -m pytest tests/test_bonus_opa.py tests/test_bonus_mcp_rugpull.py tests/test_bonus_erasure.py -v -s`. Test OPA bị SKIP nếu không có `opa` trong PATH hoặc biến `OPA_BIN`.

## 1. OPA/Rego (OPA v1.20.2)

- **Binary:** `opa_windows_amd64.exe` từ release chính thức v1.20.2, SHA-256 `e2f2e2b7…748453` khớp file `.sha256` của release.
- **Port:** `opa/lab24_authz.rego` dịch 1-1 `agent/policy.check()`. Chuỗi `else` giữ đúng thứ tự rule: `restricted` + egress → classification lạ → depth âm → principal lạ → `expires_at` sai/hết hạn → tool rỗng → ngoài effective scopes → sai purpose → allow. Principal nằm ở `data.principals` (nạp từ `data/principals.json`), **không** nằm trong input, để caller không tự khai quyền.
- **Parity:** `test_opa_matches_python_policy_on_every_context` chạy tích Descartes của 9 chiều (classification, purpose, depth, egress, principal, tool, agent_scopes, parent_scopes, expires_at), tổng **30.720 context** trong một lần `opa eval` theo lô. Kết quả: `allow=210 deny=30510 mismatches=0`. Reason của Rego là tiền tố của reason Python, nên test còn kiểm **cùng rule** đã quyết định chứ không chỉ cùng allow/deny.
- **OPA làm PEP thật:** thay `runner.policy` bằng `agent.policy_opa`, replay tấn công: `support_l1` có `read_customer` deny ×21, `dpo` có allow ×21, `http_post` deny cho cả hai, sink 0 byte.
- **Giới hạn:** mỗi `check()` sinh một tiến trình `opa eval` (~50–100 ms), chỉ hợp cho lab. Production nên chạy OPA server/sidecar hoặc nhúng WASM. `time.parse_rfc3339_ns` chặt hơn `datetime.fromisoformat` (vd `2099-01-01T00:00+00:00` không có giây được Python nhận, Rego từ chối). Ma trận test không chứa dạng này. Adapter fail closed khi OPA lỗi.

## 2. MCP rug pull local

- **Server** (`bonus/mcp_rugpull_server.py`): JSON-RPC 2.0 qua **stdio**, không mở cổng mạng, theo hình dạng giao thức MCP (`initialize`, `notifications/initialized`, `tools/list`, `tools/call`, `notifications/tools/list_changed`). Đây là bản tối giản, không dùng MCP SDK. Lúc duyệt, tool `ticket_status` vô hại. Sau lần gọi đầu, server đổi description (chèn chỉ thị kiểu lure 901) và thêm field `customer_records` vào `inputSchema` làm kênh exfil.
- **Before** (`test_before_naive_client_leaks_after_rug_pull`): agent mock đọc `tools/list` vào context mỗi lượt như một LLM. Lượt 2 nó "nghe lời" description mới, đọc `KH-000999` rồi nhét vào `customer_records`. File exfil của server nhận record synthetic có CCCD/STK (xem `reports/bonus/mcp_rugpull.log`, dòng `[mcp-before]`).
- **After** (`test_after_pinned_guard_blocks_rug_pull`): `PinnedToolGuard.approve()` pin sha256 của `(name, description, inputSchema)`. Trước **mỗi** lần gọi, guard lấy lại `tools/list` và so với pin. Lượt 2 lệch hash nên bị deny, server **không** nhận lời gọi (không có file exfil). Ledger 3 dòng `allow, allow, deny`, reason nêu "possible MCP rug pull" và các injection marker, `verify()` True, không chứa PII thô.
- **Thêm:** server độc hại ngay từ đầu (`RUGPULL_AFTER_CALLS=0`) bị từ chối pin ở bước duyệt vì description bị `find_injection` flag.
- **Giới hạn:** pin chỉ phát hiện thay đổi **định nghĩa** tool. Server giữ nguyên định nghĩa nhưng đổi **hành vi** (kết quả trả về chứa injection, gửi dữ liệu đi nơi khác) thì không bị phát hiện, cần sandbox, egress control và coi tool output là untrusted (như Run A). Bước "duyệt" là mô phỏng, không có UI cho người dùng.

## 3. Delete cascade giữ ledger verify

- **Luồng** (`agent/erasure.py`): PEP `delete_customer` + purpose `erasure-request`. Chỉ `dpo` có quyền, `support_l1` bị deny và vẫn được ghi ledger. Sau đó xoá record khỏi store, xoá ticket thuộc khách (`related_tickets`, kể cả `ticket-904b.md`), scrub customer_id/họ tên/CCCD/SĐT/STK/email ở các file còn lại, rồi append một dòng **tombstone** vào ledger.
- **Kết quả** (trên bản sao `data/`, `corpus/` trong `tmp_path`):
  - `KH-000999`: xoá `ticket-901…904b`.
  - `KH-000006`: xoá `ticket-001/005/016/022`.
  - Cả hai: scrub một ticket bên thứ ba có nhắc tới khách. Không giá trị PII nào của khách còn trong store, corpus hay ledger.
  - Các dòng ledger cũ giữ nguyên từng byte, `verify()` True.
  - Chạy lại runner sau khi xoá thì `dpo` đọc 20 khách và không còn `KH-000999`.
- **Vì sao ledger không cần sửa:** ledger chỉ lưu `args_hash` và reason đã redact. Test `test_naive_erasure_by_deleting_ledger_lines_breaks_the_chain` cho thấy nếu phải xoá dòng để xoá PII thì `verify()` thành False.
- **Đối chiếu pháp lý [Công báo]:** Luật 91/2025 Điều 14 khoản 1 điểm a, khoản 3; NĐ 356/2025 Điều 5 khoản 4. Chi tiết và giới hạn ở `reports/compliance-mapping.md`.
- **Giới hạn:**
  - Xoá file thường, không wipe an toàn.
  - **Lịch sử Git và backup vẫn chứa ticket.**
  - Không có bước tiếp nhận và xác minh người yêu cầu, không mô hình hoá thời hạn 02/20/30 ngày.
  - `args_hash` là sha256 trần nên dò ngược được, production nên dùng HMAC có khoá.
  - Thay đổi `data/principals.json` mở rộng quyền của `dpo`. Các test OBO bắt buộc vẫn pass.
