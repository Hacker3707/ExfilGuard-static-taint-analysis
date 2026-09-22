# Chạy trên Ubuntu — từ nhãn A1/A2 tới ground truth đã khóa

Chỉ dùng thư viện chuẩn của Python 3, không cần cài gì thêm.

## 0. Cài bản vá

```bash
cd ~/Dataset_A_Final          # thu muc dang co src/ data/ docs/
unzip -o ~/Downloads/Dataset_A_Adjudication_Patch.zip -d .
python3 --version             # can >= 3.8
```

Bản vá **ghi đè** `src/06_agreement.py` và `src/08_merge_labels.py` (đã sao lưu tự động khi chạy), **thêm mới** `src/09,10,11` và 3 file trong `docs/`. Không đụng tới `data/`.

Nếu có thư mục `data/raw/` (các file YAML gốc), để nguyên chỗ cũ — công cụ trọng tài cần nó để xem toàn văn. Không có cũng chạy được, nhưng ca nào không đủ dữ liệu thì phải gán `U4`.

## 1. Gộp nhãn + tính kappa

```bash
python3 src/08_merge_labels.py
python3 src/06_agreement.py
less data/agreement_report.md
```

Bản vá tự đổi `data/ground_truth.csv` (đang là review sheet) thành `data/review_sheet.csv`. Từ đây `ground_truth.csv` chỉ do bước 11 sinh ra.

## 2. Dựng hàng đợi rà soát

```bash
python3 src/09_build_adjudication_queue.py
less data/adjudication_queue.md
```

Với dữ liệu hiện tại: **65 ca** phải rà (1 EXFIL claim + 3 bất đồng + 31 UNCLEAR + 30 spot-check), 235 ca lấy nhãn đồng thuận.

Muốn spot-check nhiều/ít hơn:

```bash
python3 src/09_build_adjudication_queue.py --spotcheck 45 --seed 20260908
```

## 3. Trọng tài (~2–3 tiếng cho 65 ca)

```bash
python3 src/10_adjudicate.py --arbiter nhi
```

Làm theo nhóm cho đỡ mệt:

```bash
python3 src/10_adjudicate.py --arbiter nhi --bucket B1_EXFIL_CLAIM
python3 src/10_adjudicate.py --arbiter nhi --bucket B2_DISAGREE
python3 src/10_adjudicate.py --arbiter nhi --bucket B3_UNCLEAR
python3 src/10_adjudicate.py --arbiter nhi --bucket B4_SPOTCHECK
```

Phím: `e`/`n`/`u` gán nhãn · `p` bảng bằng chứng (lọc dòng có secret / lệnh mạng) · `f` xem toàn văn file · `g` tóm tắt guideline · `b` lùi · `s` bỏ qua · `q` thoát. Ghi ngay sau mỗi ca vào `data/adjudication.csv`, tắt giữa chừng không mất gì.

Sửa lại một ca:

```bash
python3 src/10_adjudicate.py --arbiter nhi --id A0299 --redo
```

## 4. Chốt + khóa

```bash
python3 src/11_finalize_ground_truth.py
less data/GROUND_TRUTH_LOCK.md
```

Script chặn nếu: còn ca chưa trọng tài, gán EXFIL mà thiếu G1/G2/G3, mã lý do không khớp nhãn, UNCLEAR không ghi lý do.

## 5. Chỉ bây giờ mới chạy detector

```bash
python3 src/11_finalize_ground_truth.py --verify   # truoc khi chay
# ... chay ExfilGuard va baseline tren data/ground_truth_eval.csv ...
python3 src/11_finalize_ground_truth.py --verify   # sau khi chay
```

Lưu output hai lệnh `--verify` vào log thí nghiệm. Đó là bằng chứng ground truth không bị sửa theo output công cụ.

## File nộp

| File | Nội dung |
|---|---|
| `docs/ANNOTATION_GUIDELINE_v1.0.md` | Guideline đã khóa (Bước 1 của thầy) |
| `data/adjudication_queue.md` | Ca nào phải rà và vì sao (Bước 2) |
| `data/adjudication.csv` | Bằng chứng G1/G2/G3 từng ca (Bước 3) |
| `data/ground_truth.csv` | final_label + adjudication_note, 300 dòng |
| `data/ground_truth_eval.csv` | Tập tính P/R/F1/FPR (đã loại UNCLEAR) |
| `data/GROUND_TRUTH_LOCK.md` | SHA256 + thời điểm khóa + phân bố nhãn (Bước 4) |
| `data/agreement_report.md` | Cohen's kappa + danh sách bất đồng |
