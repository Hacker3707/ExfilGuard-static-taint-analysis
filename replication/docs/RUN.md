# Dataset A — chạy từ đầu tới cuối

Bộ này đã vá sẵn. Không cần sửa gì trong `src/`.

## Trước khi chạy

```bash
cd dataset_a
pip install -r requirements.txt
export GITHUB_TOKEN=ghp_xxxxxxxx        # PowerShell: $env:GITHUB_TOKEN="ghp_xxx"
./kiem_tra.sh                            # phải thấy 3 dòng [OK] ở mục 1
```

Nếu đã chạy hôm trước: **giữ nguyên thư mục `data/`**, đừng xoá. Script 01 và 02 đọc file cũ
rồi bỏ qua phần đã làm, nên phần đã tải không phải tải lại.

## Sáu bước

| Bước | Lệnh | Thời gian |
|---|---|---|
| 1. Tìm repo | `python src/01_search_repos.py` | 40–60 phút |
| 2. Tải workflow | `nohup python src/02_fetch_workflows.py > fetch.log 2>&1 &` | 2–3 giờ (chạy nền) |
| 3. Trích đặc trưng | `python src/03_extract_features.py` | 2 phút |
| 4. Lọc + thống kê | `python src/04_build_dataset.py` | 10 giây |
| — | `./kiem_tra.sh` ← **cổng kiểm tra, xem bên dưới** | |
| 5. Lấy mẫu gán nhãn | `python src/05_sample_review.py` | 10 giây |
| 6. Tính kappa | `python src/06_agreement.py` (sau khi gán nhãn) | 5 giây |

Theo dõi bước 2: `tail -f fetch.log`. Máy tắt giữa chừng thì chạy lại, nó tiếp tục từ chỗ dừng.

## Cổng kiểm tra sau bước 4

Chạy `./kiem_tra.sh`. **Chỉ đi tiếp khi mục 2 báo `[OK] Khung lay mau DAT`**, nghĩa là:

- đủ 8 ngôn ngữ và 6 dải sao
- không ngôn ngữ nào chiếm quá 45%

Chưa đạt thì chạy lại bước 1 rồi bước 2. Đây là chỗ hỏng lần trước: tập dữ liệu ra toàn repo
Python ở hai dải sao thấp nhất, mà bảng "Tiêu chí lựa chọn" lại ghi 8 ngôn ngữ — hai chỗ đá nhau.

Một dấu hiệu tốt cần để ý: tỉ lệ trùng lặp trong `filter_log.md` **tăng lên** so với lần chạy
hẹp. Trùng 3–8% là bình thường và cho thấy đã chạm tới phần đa dạng thật của hệ sinh thái.

## Gán nhãn (bước 6)

Cả hai người đọc `docs/ANNOTATION_GUIDE.md` **trước khi bắt đầu**. Bỏ qua bước này thì kappa
sẽ thấp và phải làm lại từ đầu.

1. Hai người gán nhãn **độc lập**, điền `annotator1_*` và `annotator2_*` trong
   `data/review_sheet.csv`. Không nhìn cột của nhau.
2. Chia 3 phiên, mỗi phiên 100 mẫu. **Sau phiên đầu chạy `06_agreement.py` ngay** để phát hiện
   sớm nếu hai người hiểu khác nhau, thay vì phát hiện sau khi đã gán hết 300 mẫu.
3. Kappa dưới 0,60 thì dừng: rà 10 ca bất đồng đầu tiên, bổ sung quy tắc vào ANNOTATION_GUIDE,
   gán lại toàn bộ. Đừng sửa vài dòng cho khớp nhau.
4. Người thứ ba làm trọng tài, điền `final_label`. Chạy lại `06_agreement.py` để sinh
   `data/ground_truth.csv`.

## Nộp gì cho task #10 và #13

| File | Nội dung |
|---|---|
| `data/dataset_a.csv` | Dataset A, mỗi dòng một workflow |
| `data/stats_4_1.md` | 7 bảng thống kê, dán thẳng vào mục 4.1 |
| `data/filter_log.md` | Số bị loại từng bước, để vẽ sơ đồ luồng dữ liệu |
| `data/ground_truth.csv` | Nhãn cuối sau trọng tài |
| `data/agreement_report.md` | Cohen's kappa và danh sách bất đồng |
| `docs/SELECTION_CRITERIA_AND_ETHICS.md` | Tiêu chí chọn + ghi chú đạo đức, cho mục 4.1 và Ethics |

Bốn con số bắt buộc nêu trong bài: số repository, số workflow duy nhất, Cohen's kappa, phân bố
nhãn cuối cùng.

## Đúng yêu cầu thầy chưa

Thầy yêu cầu ghi rõ: số repositories, số workflows, số YAML files, ngôn ngữ embedded script,
tiêu chí lựa chọn. Cả năm nằm trong `stats_4_1.md` (Bảng 1, 2 và mục Tiêu chí ở cuối file).

Lưu ý phân biệt hai con số thầy liệt kê riêng: **số YAML files** là mọi file tải về từ
`.github/workflows/`; **số workflows** là các file parse được và có cả `on:` lẫn `jobs:`.
Chênh lệch giữa hai số nằm trong `filter_log.md`.
