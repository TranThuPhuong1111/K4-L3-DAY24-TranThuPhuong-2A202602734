# Secret giả trong lịch sử Git — checkpoint 4

- **Scanner và phiên bản:** Gitleaks `8.30.1` (`gitleaks version`), binary Windows x64 tải từ release chính thức v8.30.1. SHA-256 của zip `d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e` khớp với `gitleaks_8.30.1_checksums.txt`. Config: `.gitleaks.toml` (`useDefault = true` + rule `lab24-synthetic-token`).
- **Commit chứa token giả:** `1bdd849922156c868a5ee9293d68f5b72e242d2c` (`1bdd849`, "chore: seed student lab with synthetic secret exercise"). File bị xoá ở commit kế tiếp `ece6ca4`.
- **File, rule và kết quả quét lịch sử:** `gitleaks git --config .gitleaks.toml --redact --verbose .` báo **1 finding** và exit code `1`, đúng như dự kiến:
  - RuleID: `lab24-synthetic-token`
  - File: `lab-fake-secret.txt`, Line 1
  - Commit: `1bdd849922156c868a5ee9293d68f5b72e242d2c`
  - Fingerprint: `1bdd849922156c868a5ee9293d68f5b72e242d2c:lab-fake-secret.txt:lab24-synthetic-token:1`
  - Giá trị đã được `--redact` che. Đây là token giả có định dạng `LAB24-DEMO-…`, vô hiệu theo thiết kế, **không phải sự cố bảo mật thật**.
- **Kết quả quét file hiện tại:** `gitleaks dir --config .gitleaks.toml .` cho `no leaks found` (exit 0). `pre-commit run --all-files` với hook `gitleaks-system` (pin `rev: v8.30.1`, `pass_filenames: false`) cho `Passed`. Hook chạy `gitleaks git --pre-commit --staged`, nên nó chặn ở thời điểm commit. Đã thử trên một bản clone tạm: stage một file chứa token `LAB24-DEMO` giả thì hook báo `lab24-synthetic-token` và exit 1, tức commit bị chặn.
- **Nếu đây là credential thật, cần xử lý thế nào:**
  1. Coi credential là đã lộ ngay từ lúc push `1bdd849`. **Thu hồi / rotate** ở hệ thống phát hành: revoke key cũ, cấp key mới, cập nhật nơi dùng qua secret manager, không qua file trong repo.
  2. Tra log truy cập của hệ thống đó từ thời điểm commit tới lúc revoke để tìm việc sử dụng trái phép.
  3. Sau khi đã rotate, có thể dọn lịch sử (`git filter-repo` / BFG), force-push và yêu cầu mọi bản clone/fork làm theo; báo nền tảng xoá cache/PR refs nếu cần. Bước này chỉ giảm phơi nhiễm về sau, không thay thế bước rotate.
  4. Ghi sự cố (thời điểm, phạm vi, người xử lý), thêm rule hoặc allowlist phù hợp, và bật hook/CI scan để lần sau chặn được trước khi push.
- **Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:** Xoá file ở commit sau chỉ đổi snapshot mới nhất. Blob vẫn nằm trong lịch sử `1bdd849` và trong mọi clone, fork, cache đã có, nên ai có repo đều đọc lại được (đúng như `gitleaks git` vừa tìm ra). Pin dependency bằng `requirements.lock` + `--require-hashes` và pin hook `rev: v8.30.1` bảo vệ **chuỗi cung ứng** (không cài nhầm package hay hook bị thay), nhưng không làm một secret đã lộ mất hiệu lực. Hook pre-commit cũng chỉ ngăn commit **mới**. Chỉ có thu hồi/rotate tại nơi phát hành mới vô hiệu hoá được credential đã lộ.
