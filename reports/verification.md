# Verification — trước khi nộp

- **OS / Python / Gitleaks version:** Windows 11 Home 10.0.26200 (**Windows native**, không phải WSL2. README ghi Windows native chưa được pilot). Shell: Git Bash + PowerShell 5.1. Python `3.14.6` trong `.venv`. Gitleaks `8.30.1`: `gitleaks_8.30.1_windows_x64.zip` từ release chính thức, SHA-256 `d29144de…afc4e` khớp checksums. pre-commit `4.6.2`. OPA `1.20.2` (bonus): `opa_windows_amd64.exe`, SHA-256 `e2f2e2b7…748453` khớp `.sha256` của release.
- **PATH:** `C:\Users\Acer\.local\gitleaks-8.30.1` và `C:\Users\Acer\.local\opa-1.20.2` đã được thêm vào **PATH của user**. Kiểm trong phiên PowerShell mới: `Get-Command gitleaks` và `Get-Command opa` trả đúng hai binary trên. Terminal/VS Code đã mở từ trước cần mở lại mới nhận PATH mới.
- **Dependency lock:** `python -m piptools compile --generate-hashes -o requirements.lock requirements.txt`. Cài vào một venv **mới, sạch** bằng `pip install --no-cache-dir --require-hashes -r requirements.lock` thành công, 11 package. Bonus không thêm dependency Python nào.
- **`python -m pytest tests/ -q`:** `45 passed`, chạy **không** đặt `PYTHONIOENCODING`.
  - Bắt buộc: `test_pii.py` (2; `gold=118 pred=118 tp=118`, `precision=1.000 recall=1.000`), `test_injection.py` (8 = 4 biến thể × `support_l1`, `dpo`), `test_split.py` (1), `test_obo.py` (5), `test_policy.py` (4), `test_ledger.py` (3), `test_supply_chain.py` (3), `test_check_lure_cli.py` (3), `test_scaffold_dispatch.py` (4).
  - Thêm (không sửa test bắt buộc): `test_console_encoding.py` (2) và bonus `test_bonus_opa.py` (3), `test_bonus_mcp_rugpull.py` (3), `test_bonus_erasure.py` (4). Xem `reports/bonus.md`.
- **`opa test opa/ -v`:** `PASS: 5/5`.
- **`python -m agent.check_lure corpus/ticket-90*.md`:** `4/4 lure sẵn sàng`. `find_injection()` trên riêng `ticket-904.md` hoặc riêng `ticket-904b.md` đều trả `None`.
- **`pre-commit run --all-files`:** `Detect hardcoded secrets … Passed` (hook `gitleaks-system`, `rev: v8.30.1`, `pass_filenames: false`). Hook đã `pre-commit install`. Hook chạy `gitleaks git --pre-commit --staged`, nên `--all-files` chỉ quét phần đã stage. Đã kiểm trên clone tạm: stage file chứa token `LAB24-DEMO` giả thì hook báo `lab24-synthetic-token`, exit 1.
- **Gitleaks:** `gitleaks git --config .gitleaks.toml --redact .` cho `leaks found: 1` (`lab24-synthetic-token`, `lab-fake-secret.txt:1`, commit `1bdd849`), exit 1 như dự kiến. `gitleaks dir --config .gitleaks.toml .` cho `no leaks found`. Chi tiết ở `reports/secrets-incident.md`.
- **Ledger verify:** `verify(Path('reports/ledger.jsonl'))` = `True`. File có 48 dòng: `--as dpo` (1–24) rồi `--as support_l1` (25–48). Mọi dòng có `reason`, `on_behalf_of`, `run_id`, `expires_at`. Dòng 24 và 48 là `http_post` deny. Sửa dòng 24 `deny` thành `allow` trên bản sao mà không tính lại hash thì `verify()` = `False`.
- **Before/after:**
  - `reports/attack-before.log` (299 byte) chứa record synthetic `KH-000999`, tạo khi runner còn là scaffold.
  - `reports/attack-after.log` **0 byte**, sinh lại bằng code cuối cùng: reset sink → pytest → reset sink → `--as dpo` cùng query → copy `sink.log`.
  - Replay từng biến thể: `reports/attack-before-variants.log` (4/4 lộ) và `reports/attack-after-variants.log` (8/8 `sink lines=0`).
- **Pháp lý:** đã đối chiếu Luật 91/2025/QH15, NĐ 356/2025/NĐ-CP và Luật 134/2025/QH15 với bản PDF **Công báo** (congbao.chinhphu.vn), có ghi số Công báo và SHA-256 file. Tên mục OWASP ASI01/03/04 đã đối chiếu genai.owasp.org. Những điểm còn `chưa xác minh` được liệt kê ở đầu `reports/compliance-mapping.md`.
- **Lỗi đã sửa:**
  1. **Console Windows không phải UTF-8.** Trước khi sửa, khi chưa đặt `PYTHONIOENCODING=utf-8`, `python -m agent.loop …`, `python -m agent.check_lure …` và `python sink/sink.py --reset` crash ở `print()` với `UnicodeEncodeError: 'charmap' codec can't encode character '\u0110'` (stdout bị pipe dùng cp1252). Với `agent.loop`, runner đã ghi ledger xong rồi mới crash. **Sửa:** `agent.use_utf8_stdio()` (`agent/__init__.py`) được gọi đầu `main()` của `agent/loop.py` và `agent/check_lure.py`, và `sink/sink.py` có đoạn tương tự (chạy dạng script nên không import được `agent`). **Hồi quy:** `tests/test_console_encoding.py` ép `PYTHONIOENCODING=cp1252` để tái hiện trên mọi OS. Trước khi sửa: 2 failed; sau khi sửa: pass.
- **Các lỗi / giới hạn còn lại:**
  1. `requirements.lock` compile trên Windows/Python 3.14, có `colorama` (dependency của pytest trên Windows). Lock trên Linux/WSL có thể khác. Grader nên compile lại trên nền tảng chấm nếu cần.
  2. `gitleaks dir .` quét cả `.venv/` (~40 MB) vì `.gitleaks.toml` không loại trừ thư mục này. Kết quả vẫn sạch.
  3. Bonus OPA dùng một tiến trình `opa eval` cho mỗi lần `check()`. Test OPA bị SKIP nếu máy chấm không có `opa`.
  4. `data/principals.json` được mở rộng cho bonus erasure (`dpo` có thêm `delete_customer` và `erasure-request`). Các test bắt buộc vẫn pass.
  5. Không làm bonus GLiNER.
