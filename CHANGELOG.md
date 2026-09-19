# CHANGELOG

## [660802b] - 2026-09-19 08:06:09 UTC

### Thêm test
- `regress_test/test_cwd_invariance.sh`: cùng một workflow chạy từ hai thư mục khác
  nhau phải cho output giống hệt.
- 

## [b4e16ce] - 2026-09-09 10:06 UTC
### Fix Bug
- _resolve_file_path giả định layout .github/workflows/ nên tính repo root cách hai mức, không xử lý được layout workflows/ cạnh scripts/. Bỏ fallback resolve theo thư mục hiện hành vì nó che lỗi: kết quả phụ thuộc vào nơi chạy lệnh.

## [RELEASED] - 2026-09-08 22:30 UTC

**Commit:** `5279e4d99ec7dbe3e200336076afab8665f36dcf`  
**Phạm vi kiểm thử:** Chỉ Dataset B + unit test. **Chưa chạy trên Dataset A. Chưa đọc** `data/adjudication.csv` hay `data/ground_truth.csv`.

### Thêm - Sink

| Rule | Category | Nội dung | File |
|---|---|---|---|
| SNK-07 | K_file | `scp`, `rsync`, `gsutil cp/rsync/mv`, `azcopy`, `aws s3 cp/sync/mv`, `gh release upload`, `curl -T/--upload-file` | `catalogs.py`, `analyzers/bash_analyzer.py` |
| SNK-06 | K_artifact | `actions/upload-artifact` — **có riêng**, không góp vào network sink | `analyzers/yaml_analyzer.py` |
| SNK-05 | K_scm | Thu hẹp stupid `git push`. `aws s3` đã chuyển sang SNK-07 vì nó không phải SCM. | `catalogs.py` |

Sink `K_file` đối chiếu payload với `FileTaintState` thay vì tìm biến trong argv. Đó là lý do 5 sink này trước đây đều bỏ sót: payload của chúng là đường dẫn file.

### Thêm - Propagation

- Engine `file_taint.py` (**đã thêm**). Taint cấp FILE, phạm vi JOB: `> f`, `>> f`, `| tee f`, `--trace` của Playwright. Chuỗi secret → file → gửi đi.
- `$GITHUB_ENV`: secret ghi ở step N, đọc ở step N+1.
- `$GITHUB_OUTPUT` qua `${{ steps.<id>.outputs.* }}`.
- `iter_references()`: nhận diện `${{ env.X }}` và `${{ steps.id.outputs.k }}` trong `run:`. `VAR_REF_PATTERN` chỉ khớp `$VAR` / `${VAR}`.
- SRC-07/SRC-08: nguồn `S_dyntu` IMDS (169.254.169.254, ECS, GCP, Azure) và secret-store CLI (`vault read`, `aws secretsmanager`, `az keyvault`).

### Sửa lỗi

- **`_resolve_file_path` giải sai đường dẫn.** Script được giải theo thư mục workflow (`.github/workflows/scripts/...`) thay vì repo root. Làm nhánh phân tích script ngoài không bao giờ chạy. Ảnh hưởng P17, P18.
- **`os.getenv` / `process.env` không kế thừa taint.** Nhánh `elif env_match` luôn tạo nguồn mẹ `S_prog`, gây hai lỗi cùng lúc: secret thật bị chấm thấp (`S_prog 2.0` thay vì `S_ctx 3.0`), và `os.getenv("HOME")` cũng thành nguồn. Nay kiểm tra `env_match` trong `tainted` trước.
- **`classify_destination` chỉ trả về 2 tầng.** Nhánh "không có URL literal" luôn trả `untrusted_external`, nên tầng `external (1.0)` không bao giờ được dùng. Đã thêm nhận diện hostname literal.
- **Context tên trùng giữa các job.** `step_2` của job A và job B không phân biệt được, làm hỏng khóa dedupe. Nay là `{job}.step_{n}`.
- **Nhân đôi detection.** CẤP 1 (YAML-only) và CẤP 2 (Bash) cùng quét một dòng mà không loại trừ nhau → mọi lệnh `curl` có secret sinh 2 finding. CẤP 1 giờ chỉ chạy khi `enable_bash = False` (dùng ngữ nghĩa ablation Config 1).
- **Regex ReDoS.** Splitter statement dùng lookahead alternation với long quantifier → backtracking nhiều. Thay bằng scanner tuyến tính O(n).
- **`\bhost\b` khớp `host` trong các câu lệnh không liên quan.** Nay yêu cầu đổi sơ giống hostname.

### Thay đổi hành vi chấm điểm

- `finding_type` (`engine/models.py`) tách loại finding khỏi risk score: `EXFIL`, `FILE_EXFIL`, `EXPOSURE`, `SUPPLY_CHAIN`, `CREDENTIAL_EXCHANGE`, `INFO`. `FINDING_TYPE_SCORE_CAP` chặn finding `INFO` mang điểm cao.
- **Phân loại vai trò argument** (`engine/arg_roles.py`, **đã thêm**). Secret ở vị trí payload (`-d`, `-H`, `-F`, `-T`) → `EXFIL`. Secret **chỉ** ở vị trí destination (webhook URL) → `INFO`. Trước đây, mọi `curl` có secret đều sinh detection, bất kể vai trò.
- `unresolved_secret` → `untrusted_external` (không còn → allowlisted). Map cũ làm chìm oan mọi lệnh không có URL literal, điển hình là DNS.
- `BENCHMARK_EXFIL_CONFIG`: `min_risk_level="INFO"` + chỉ `EXFIL_CLASS_TYPES`. Khi đó detection benchmark **không được lọc theo risk level**.

### Còn treo

- `external_literal` nên là `external (1.0)` hay `untrusted_external (1.2)`? Đặc tả 3.6 mô tả 3 tầng nhưng không định nghĩa rõ tầng giữa. **Chờ chốt.** Hiện đặt `external`. Đổi một dòng trong `arg_roles.classify_destination_roles`.
- SRC-03/04/05 lexical qualifier: có `CREDENTIAL_LEXICAL_PATTERN` và `enable_lexical_source`, **tắt mặc định** (bật lên sẽ coi `CACHE_KEY`, `SORT_KEY` là nhạy cảm).
- T_5 (script argument handoff) chỉ cài cho `.sh` (`$1`). Chưa có `sys.argv[1]` / `process.argv[2]`.
- T_6 (function argument-to-return) chưa cài.
- Export SARIF chưa cài.
- Rule ID trong `catalogs.py` và Bảng I/II của báo cáo **đánh số khác nhau**.
- Báo cáo mô tả "AST-based extraction" nhưng implementation dùng regex.

### Kết quả kiểm thử (unit test, KHÔNG phải Dataset A)

**Bộ regression (5 Negative / 4 Positive):** 9/9

**P16-P22 (6 Positive):** 6/7 (P21 FN - đang tìm nguyên nhân)

**Task 26-33 probe (8 Positive):** 8/8

**Hash sanitizer probe (4 Positive):** 4/4

**`os.getenv("HOME")` false-source:** 0 detection (đúng)

**Sink_Category sinh ra:** `K_artifact`, `K_cli`, `K_dns`, `K_file`, `K_lib`, `K_scm`

**Source_Category sinh ra:** `S_ctx`, `S_dyn`, `S_inp`

### Ghi chú cho bài báo

**Hash KHÔNG phải sanitizer.** ExfilGuard không mô hình hóa bất kỳ sanitizer nào. `sha256sum`, `base64`, `md5sum`, `hashlib.sha256().hexdigest()`, nối chuỗi — taint xuyên qua hết (4/4 detect). Case "hash rồi gửi HTTP" của Dataset B là TP, **không** bỏ sót oan.

Nên ghi đây là **over-approximation có chủ ý** (không có sanitizer set), chứ không phải đã cân nhắc rồi kết luận hash không khử taint.

Mặt trái cần ghi kèm: nếu Dataset A mới có trường hợp hash đúng nghĩa khử taint (HMAC làm signature rồi gửi digest công khai) thì đó sẽ là FP, và tool hiện không phân biệt được.
