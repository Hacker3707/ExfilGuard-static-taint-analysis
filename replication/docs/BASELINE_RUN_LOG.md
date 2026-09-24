# Nhật ký chạy baseline — Dataset A

Ground truth khóa 09/09, SHA256 `e9e819f983635503db923d4c2fb5368571d2f9c436f7a0e35072a3ea0b2bae15`.
`--verify` sạch trước khi chạy (`data/verify-before-run.log`).

Tập: 300 mẫu (265 eval + 35 UNCLEAR). Script 12 tách hai nhóm khi tính metric.

## Phiên bản công cụ

| Tool | Version | Cách cài |
|---|---|---|
| gitleaks | 8.30.1 | binary tu GitHub release |
| zizmor | 1.30.0 | pipx / venv |
| poutine | chưa chạy | binary Go, không có trong apt |
| ExfilGuard | chờ Hà | — |

Positive control cho gitleaks: `out/controls/gitleaks-positive-control.json` — file mồi
chứa GitHub PAT giả, gitleaks bắt đúng rule `github-pat` dòng 8. Chứng minh lệnh và
parser hoạt động, nên con số thấp bên dưới là kết quả thật chứ không phải lỗi cấu hình.

---

## gitleaks — 4/300 cảnh báo (1,3%)

Cả 4 đều rơi vào ca có nhãn NO_EXFIL. Trên tập eval 265 mẫu: FP = 4, TN = 261,
**FPR ≈ 1,5%**, detection = 0.

| sample_id | Số finding | Rule |
|---|---|---|
| A0039 | 8 | `discord-client-id` |
| A0235 | 2 | `generic-api-key` |
| A0251 | 1 | `generic-api-key` |
| A0259 | 1 | `generic-api-key` |

Kiểm tra bằng tay cho thấy đây là **chuỗi entropy cao công khai theo thiết kế**, không
phải credential — vân tay khóa GPG (A0259 dòng 162, 40 ký tự hex, đăng lên keyserver để
người dùng verify), commit SHA pin action (A0235 dòng 30/83, chính là best practice bảo
mật), và ID công khai khác.

Giải thích: workflow tham chiếu secret qua `${{ secrets.X }}`, không hardcode. Gitleaks
chỉ tìm **secret literal**, nên trên corpus này gần như không có gì để bắt. Đây không
phải "gitleaks kém" — nó không nhìn thấy lớp rủi ro mà bài đang hỏi.

---

## zizmor — hai quy đổi

**Quy đổi thô** (mọi finding = cảnh báo): **272/300 = 90,7%**.

**Quy đổi lọc** (chỉ rule nói về luồng secret: `secrets-inherit`,
`overprovisioned-secrets`, `github-env`): **12/300 = 4,0%**.

Phân bố 2312 finding trên 300 workflow:

| Rule | Số finding | Liên quan exfiltration? |
|---|---|---|
| unpinned-uses | 922 | không (supply chain) |
| artipacked | 561 | không (credential persistence) |
| template-injection | 406 | không (code injection, hướng ngược lại) |
| excessive-permissions | 225 | không (least privilege) |
| self-repository | 62 | không |
| cache-poisoning | 58 | không |
| adhoc-packages | 15 | không |
| superfluous-actions | 14 | không |
| dangerous-triggers | 13 | không (trigger risk) |
| **github-env** | **12** | **có** |
| unpinned-images | 7 | không |
| **overprovisioned-secrets** | **6** | **có** |
| github-app | 5 | không |
| use-trusted-publishing | 3 | không |
| **secrets-inherit** | **3** | **có** |

**21 / 2312 finding (0,9%)** chạm tới luồng secret.

Đây là cách đo coverage gap thuyết phục hơn FPR: không phải "zizmor sai 90,7%" mà là
"zizmor gần như không nói về chuyện này". Zizmor kiểm **cấu hình** workflow; ExfilGuard
kiểm **khả năng tới được** của secret. Hai câu hỏi khác nhau.

⛔ Không đưa 90,7% vào bảng xếp hạng chung với ExfilGuard. Bảng baseline phải có cột
"thuộc tính được phát hiện" bên cạnh cột FPR, đúng nhận xét mục 8 của thầy.

---

## Lưu ý kỹ thuật khi đọc log

Cột `loi` trong output của `13_run_detectors.py` **báo động giả với zizmor**: zizmor trả
mã thoát khác 0 khi có finding và in log INFO/WARN ra stderr, script hiểu nhầm là lỗi.
Số `loi` luôn bằng số cảnh báo. Parse JSON vẫn đúng — kiểm bằng `rules` trong
`out/zizmor_findings.jsonl`, thấy tên rule hợp lệ. Với gitleaks thì `loi = 0` thật.

---

## Còn lại

- [ ] poutine — cài binary Go rồi chạy. Poutine đọc cả repo nên script dựng repo giả tạm cho từng file.
- [ ] ExfilGuard — chờ lệnh CLI từ Hà: `python3 src/13_run_detectors.py --tool exfilguard --cmd "<lenh> {file}"`
- [ ] `--verify` sau khi chạy hết, lưu `data/verify-after-run.log`
- [ ] `12_build_master_results.py --merge` rồi `--metrics`

---

## Đối chiếu phiên bản gitleaks

Chạy Dataset A hai lần: gitleaks 8.16.0 (apt) và 8.30.1 (binary, khớp phiên bản Hà
dùng ở bộ demo). **Cả hai đều ra 4/300**, positive control bắt đúng `github-pat` ở cả
hai bản. Toàn bài thống nhất báo cáo 8.30.1. Kết quả ổn định qua 14 minor version —
đáng một câu trong Limitations về độ ổn định của baseline.

---

## Dataset B (30 ca: 18 exploit / 12 benign)

Khác Dataset A, Dataset B **có positive** nên P/R/F1 tính được.

| Tool | TP | FP | TN | FN | Precision | Recall | FPR |
|---|---|---|---|---|---|---|---|
| gitleaks | 0 | 0 | 12 | 18 | n/a | **0,0%** | 0,0% |
| zizmor | 16 | 11 | 1 | 2 | 59,3% | 88,9% | **91,7%** |

**Gitleaks bỏ sót toàn bộ 18 ca exploit.** Nhất quán với Dataset A: Dataset B tham
chiếu secret qua `${{ secrets.API_KEY }}`, không hardcode, nên secret-literal scanner
không có gì để bắt. Recall 0% ở đây không phải lỗi cấu hình — positive control đã
chứng minh tool hoạt động.

**Zizmor báo động 11/12 ca benign**, gồm cả bốn hard negative được dựng riêng để
KHÔNG có đường taint:

| Ca | Pattern | Vì sao là benign |
|---|---|---|
| B05 | `dummy_named_secret` | biến tên giống secret, giá trị không từ `secrets.*` |
| B09 / B14 / B30 | `masked_before_logging` | secret bị mask, không tới sink mạng |
| B10 / B19 | `secret_hash_only` | chỉ hash một chiều rồi log |
| B20 / B25 / B29 | `fixed_http` / `fixed_dns` | URL cố định, không có secret |

Recall danh nghĩa 88,9% của zizmor **không phản ánh khả năng phân biệt**: nó báo động
gần như mọi file. Bằng chứng độc lập là bộ demo 2 ca của Hà — zizmor cho **đúng 3
finding giống hệt nhau** (`artipacked`, `excessive-permissions`, `unpinned-uses`) trên
cả `exfil_positive.yml` lẫn `benign.yml`. Cùng đầu ra trên hai lớp đối lập nghĩa là
không có sức phân biệt trên thuộc tính đang xét.

Câu dùng cho bài:

> Zizmor flags 11 of 12 benign cases, including hard negatives constructed specifically
> to contain no taint path — a dummy variable with a secret-like name, a masked value, a
> hash-only flow, and a fixed URL with no secret. Its high nominal recall reflects
> near-universal alerting rather than discrimination of the property under test.

### Ca sai chi tiết


**gitleaks** (18 ca sai)

| case | loai | difficulty | pattern |
|---|---|---|---|
| B01 | FN | easy | direct_secret_to_curl |
| B02 | FN | medium | direct_secret_to_curl |
| B03 | FN | hard | concatenated_secret_to_curl |
| B06 | FN | easy | one_hop_propagation |
| B07 | FN | medium | three_hop_propagation |
| B08 | FN | hard | base64_then_curl |
| B11 | FN | medium | embedded_bash_http |
| B12 | FN | hard | bash_base64_http |
| B13 | FN | hard | bash_multi_hop_http |
| B16 | FN | medium | python_requests_post |
| B17 | FN | hard | python_json_propagation |
| B18 | FN | hard | python_hash_then_http |
| B21 | FN | medium | node_fetch_body |
| B22 | FN | hard | node_concat_http |
| B23 | FN | hard | node_multihop_http |
| B26 | FN | medium | nslookup_secret_subdomain |
| B27 | FN | hard | dig_secret_subdomain |
| B28 | FN | hard | python_dns_sink |

**zizmor** (13 ca sai)

| case | loai | difficulty | pattern |
|---|---|---|---|
| B02 | FN | medium | direct_secret_to_curl |
| B05 | FP | medium | dummy_named_secret |
| B09 | FP | hard | masked_before_logging |
| B10 | FP | medium | secret_hash_only |
| B14 | FP | hard | masked_bash_log |
| B15 | FP | hard | dummy_bash_http |
| B19 | FP | hard | python_hash_only |
| B20 | FP | medium | python_fixed_http |
| B24 | FP | hard | node_dummy_http |
| B25 | FP | medium | node_fixed_http |
| B27 | FN | hard | dig_secret_subdomain |
| B29 | FP | hard | fixed_dns_lookup |
| B30 | FP | hard | secret_masked_no_dns |


### Còn thiếu

- [ ] poutine 1.1.6 trên cả A và B
- [ ] **ExfilGuard trên cả A và B** — chặn toàn bộ bảng comparison
- [ ] Chốt policy hash: Dataset B gán B18 (hash → HTTP) là exploit, B10/B19 (hash → log)
      là benign, tức hash KHÔNG phải sanitizer. Nếu ExfilGuard coi hash là barrier thì
      B18 thành FN oan. README Dataset B yêu cầu ghi rõ policy này trong bài.

---

## Đính chính

Bảng phân bố rule của zizmor ở trên liệt kê 15 rule, cộng lại được 2312. Đếm lại
đầy đủ từ `out/zizmor_findings.jsonl` thì tổng là **2318**: bảng bỏ sót năm rule
hiếm là `unpinned-tools` (2), `bot-conditions` (1), `obfuscation` (1), `misfeature`
(1) và `unsound-ternary` (1). Số finding liên quan secret vẫn đúng là **21**, nên
tỉ lệ 21/2318 = 0,9% không đổi. Poutine: 555 finding, trong đó 4 thuộc rule
`job_all_secrets`, tức 0,7%.

Log này được viết ở giai đoạn ground truth v1 (SHA `e9e819f9`, 265 eval + 35
UNCLEAR) nên vài con số trung gian trong đó phản ánh v1. Kết quả cuối cùng trong
bài lấy theo v2 (262 eval + 38 UNCLEAR), tính bằng `src/12_build_master_results.py`.
