# CHANGELOG

## [9c61afa]([https://github.com/Hacker3707/ExfilGuard-static-taint-analysis/commit/16f417b2f1a8192eccc9e20a2ba73ba6e2533f51](https://github.com/Hacker3707/ExfilGuard-static-taint-analysis/commit/9c61afa01db13de6167f03bd51c9f288d68a213e)) -  2026-09-23 03:40:14

- ### Added
- `run_ablation.py`: Added `--dataset` argument to run ablation experiments on a specified dataset, enabling reproduction of Figure 4 using Dataset B while preserving the existing default behavior on `testcases/`.

## [16f417b](https://github.com/Hacker3707/ExfilGuard-static-taint-analysis/commit/16f417b2f1a8192eccc9e20a2ba73ba6e2533f51) - 2026-09-22 16:53:00 UTC

### Thêm reproduction package và .gitignore
- `replication`: Chứa cả datasets, ground truth, scripts, baseline outputs và các file phục vụ tái chạy Table/Figure.
- `.gitignore`: Bỏ qua thư mục __pycache__ ở root của project. Không commit Python cache.

## [e891def](https://github.com/Hacker3707/ExfilGuard-static-taint-analysis/commit/e891defea199b5097c4409fb1bc42ce142280e85) - 2026-09-19 12:28:29 UTC

### Refactor
- `catalogs.py`: Tập trung định nghĩa và ánh xạ Source Rule ID và Sink Rule ID theo từng category, giúp catalog trở thành nguồn thống nhất cho Rule ID được sử dụng trong quá trình phân tích và đánh giá.
- `evaluate.py`: Rút gọn logic xử lý Rule ID bằng cách sử dụng các helper từ `catalogs.py` thay vì duy trì mapping trực tiếp trong evaluator. Evaluator tập trung vào việc chạy benchmark, tổng hợp kết quả và hiển thị detection details.

## [f14b1bd](https://github.com/Hacker3707/ExfilGuard-static-taint-analysis/commit/f14b1bd3799d6ccf8facb14dc0c540b30289783f) - 2026-09-19 11:58:48 UTC

### Sửa lỗi
- `analyzers/yaml_analyzer.py`: Sửa lỗi resolve script path đối với layout `testcases/positive` và `testcases/negative`. Trước đó, các external script được workflow trong `testcases/positive` tham chiếu không được resolve đúng, khiến các test case P10–P22 bị đánh dấu False Negative.
- P21 vẫn là False Negative do còn thiếu propagation rule cho GitHub Actions step outputs. Workflow truyền `${{ inputs.internal_token }}` qua `$GITHUB_OUTPUT` với tên `staged_val`, sau đó tham chiếu giá trị này bằng `${{ steps.step_source.outputs.staged_val }}` tại DNS sink. Analyzer hiện chưa propagate taint từ giá trị được ghi qua `$GITHUB_OUTPUT` sang expression tương ứng `steps.<step_id>.outputs.<output_name>`.

## [660802b](https://github.com/Hacker3707/ExfilGuard-static-taint-analysis/commit/660802b46d2c0d91983af9283e58dc786ae42c49) - 2026-09-19 08:06:09 UTC

### Thêm test
- `regress_test/test_cwd_invariance.sh`: cùng một workflow chạy từ hai thư mục khác
  nhau phải cho output giống hệt.

## [b4e16ce](https://github.com/Hacker3707/ExfilGuard-static-taint-analysis/commit/b4e16cef929912f52069d098accb1d0863145727) - 2026-09-09 10:06 UTC
### Fix Bug
- _resolve_file_path giả định layout .github/workflows/ nên tính repo root cách hai mức, không xử lý được layout workflows/ cạnh scripts/. Bỏ fallback resolve theo thư mục hiện hành vì nó che lỗi: kết quả phụ thuộc vào nơi chạy lệnh.

## [RELEASED](https://github.com/Hacker3707/ExfilGuard-static-taint-analysis/commit/5279e4d99ec7dbe3e200336076afab8665f36dcf) - 2026-09-08 22:30 UTC

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
