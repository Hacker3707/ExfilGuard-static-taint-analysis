# Dataset A — Real-world GitHub Actions Workflows

Bộ công cụ hoàn chỉnh để xây Dataset A cho mục 4.1 của paper ExfilGuard. Gồm 6 script chạy
tuần tự, sinh ra tập dữ liệu, bảng thống kê, và ground truth đã gán nhãn tay.

Bao trùm cả task #10 (thu thập) và task #13 (lọc, gán nhãn, hoàn thiện).

---

## Kết quả cuối cùng nhận được

| File | Nội dung |
|------|----------|
| `data/dataset_a.csv` | Dataset A — mỗi dòng một workflow, kèm đặc trưng đã trích |
| `data/dataset_a_full.jsonl` | Bản đầy đủ mọi trường, dùng cho phân tích sâu |
| `data/stats_4_1.md` | 7 bảng thống kê, dán thẳng vào mục 4.1 |
| `data/filter_log.md` | Số lượng bị loại ở từng bước, dùng vẽ sơ đồ luồng dữ liệu |
| `data/ground_truth.csv` | Nhãn cuối cùng sau khi hai người gán nhãn và trọng tài |
| `data/agreement_report.md` | Cohen's kappa và danh sách bất đồng |
| `data/raw/` | Toàn bộ file YAML gốc đã tải |

---

## Chuẩn bị

```bash
pip install -r requirements.txt
```

Tạo Personal Access Token trên GitHub (Settings → Developer settings → Personal access
tokens → Fine-grained hoặc Classic, chỉ cần quyền đọc repo công khai), rồi:

```bash
export GITHUB_TOKEN=ghp_xxxxxxxxxxxx      # Linux, macOS, WSL
# PowerShell:  $env:GITHUB_TOKEN="ghp_xxx"
```

Không có token thì giới hạn chỉ 60 request/giờ, không đủ để crawl.

**Chạy toàn bộ trong WSL2 nếu máy là Windows.** Các script đều chạy được trên Windows thuần
nhưng đường dẫn và encoding hay gây lỗi vặt.

---

## Quy trình 6 bước

### Bước 1 — Tìm repository ứng viên

```bash
python src/01_search_repos.py
```

Thời gian: khoảng 20–40 phút cho 4000 repo. Ra `data/repos.jsonl`.

Script tìm theo từng ô phân tầng gồm ngôn ngữ × dải sao. Lý do: GitHub Search API chỉ trả
tối đa **1000 kết quả cho một truy vấn**, dù tổng số khớp là bao nhiêu. Một truy vấn duy
nhất sẽ mãi mãi chỉ cho 1000 repo, và toàn là repo nhiều sao nhất. Chia ô vừa vượt được
trần đó vừa tránh thiên lệch về phía repo nổi tiếng.

Có thể dừng giữa chừng bằng Ctrl+C rồi chạy lại — script đọc lại file cũ và bỏ qua repo đã có.

### Bước 2 — Tải file workflow

```bash
python src/02_fetch_workflows.py
```

Thời gian: khoảng 2–4 giờ cho 4000 repo. Ra `data/raw/` và `data/workflow_index.jsonl`.

Đây là bước lâu nhất. Cứ để chạy nền, script tự xử lý rate limit và tự nghỉ khi hết quota.
Nếu máy tắt giữa chừng, chạy lại là tiếp tục từ chỗ dừng.

Kỳ vọng: khoảng 40–60% repo có thư mục `.github/workflows/`, mỗi repo trung bình 3–5 file.
Với 4000 repo ứng viên, kết quả thường rơi vào 6.000–10.000 file YAML.

### Bước 3 — Trích đặc trưng

```bash
python src/03_extract_features.py
```

Thời gian: vài phút. Ra `data/features.jsonl`.

Phân tích YAML từng file, xác định file nào thực sự là workflow, tìm tham chiếu secret,
nhận diện ngôn ngữ script nhúng, và tìm ứng viên sink mạng **bên trong khối `run:`**.

### Bước 4 — Lọc, khử trùng lặp, xuất dataset và thống kê

```bash
python src/04_build_dataset.py
```

Thời gian: vài giây. Ra `dataset_a.csv`, `stats_4_1.md`, `filter_log.md`.

Bước khử trùng lặp là bắt buộc. Workflow bị sao chép giữa các repo rất nhiều; nếu để nguyên
thì một template phổ biến bị đếm hàng trăm lần và mọi tỉ lệ phần trăm trong mục 4.1 đều sai.

### Bước 5 — Lấy mẫu để gán nhãn tay

```bash
python src/05_sample_review.py
```

Ra `data/review_sheet.csv` và `data/review_snippets/`.

Lấy mẫu phân tầng, mặc định 240 workflow: 120 từ tầng có cả secret lẫn sink, 60 từ tầng chỉ
có secret, 30 chỉ có sink, 30 không có gì. Đổi số lượng trong `config.py` nếu cần.

Mỗi mẫu kèm một file trích đoạn code liên quan, người gán nhãn không phải mở cả file dài.

### Bước 6 — Gán nhãn và tính độ đồng thuận

Đọc `docs/ANNOTATION_GUIDE.md` trước. Hai người gán nhãn độc lập, điền các cột
`annotator1_*` và `annotator2_*` trong `data/review_sheet.csv`, rồi:

```bash
python src/06_agreement.py
```

Ra `data/agreement_report.md`. Nếu kappa dưới 0.60 thì phải thống nhất lại định nghĩa và
gán nhãn lại — đừng chỉnh vài dòng cho khớp nhau.

Sau khi trọng tài điền cột `final_label`, chạy lại để sinh `data/ground_truth.csv`.

---

## Điều chỉnh quy mô

Mọi tham số nằm trong `src/config.py`. Ba tham số hay phải đổi nhất:

| Tham số | Mặc định | Ghi chú |
|---|---|---|
| `TARGET_CANDIDATE_REPOS` | 4000 | Giảm còn 1000 nếu muốn chạy thử nhanh trong 1 giờ |
| `PUSHED_AFTER` | 2025-09-01 | Nới ra nếu số repo thu được quá ít |
| `REVIEW_STRATA` | 240 mẫu | Giảm còn 120 nếu chỉ có một người gán nhãn |

Sau khi đổi bất cứ tham số nào, phải chạy lại từ bước bị ảnh hưởng và cập nhật lại con số
trong bài — số liệu trong paper phải khớp với `stats_4_1.md`.

---

## Ba điều dễ làm hỏng tập dữ liệu

**1. Không khử trùng lặp.** Đây là lỗi phổ biến nhất trong các bài về hệ sinh thái phần mềm.
Template workflow được sao chép rất nhiều; giữ nguyên bản trùng sẽ khiến tỉ lệ phần trăm
phản ánh mức độ phổ biến của template chứ không phản ánh thực tế.

**2. Dùng chính công cụ của mình để sinh ground truth.** Các heuristic trong
`03_extract_features.py` chỉ dùng để **phân tầng khi lấy mẫu**, không phải để gán nhãn.
Nhãn phải do người đọc và quyết định. Nếu lấy đầu ra của ExfilGuard làm nhãn đúng rồi đo
ExfilGuard trên nhãn đó thì Precision sẽ là 100% và hoàn toàn vô nghĩa. Điều này phải được
nói rõ trong mục 4.1.

**3. Không cố định hạt giống ngẫu nhiên.** `RANDOM_SEED` trong `config.py` bảo đảm chạy lại
cho ra đúng mẫu cũ. Không có nó thì không ai tái lập được kết quả, kể cả chính nhóm.

---

## Lưu ý về đạo đức và pháp lý

Chỉ thu thập nội dung công khai và chỉ lưu file workflow. Nếu trong quá trình gán nhãn phát
hiện một secret thật bị lộ trong repo công khai, **không đưa giá trị đó vào bất kỳ file nào
của bộ dữ liệu và không đưa vào bài báo**. Ghi lại repo trong một danh sách riêng và cân nhắc
báo cho chủ repo. Khi công bố dataset, chỉ công bố đường dẫn repo và băm nội dung, không
công bố giá trị secret. Nêu điều này trong phần Ethics của bài.
