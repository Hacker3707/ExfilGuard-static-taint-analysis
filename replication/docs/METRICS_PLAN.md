# Kế hoạch metric sau khi khóa ground truth — ĐỌC TRƯỚC KHI VIẾT SECTION 4

Ground truth Dataset A đã khóa lúc 09/09. Phân bố cuối:

| Nhãn | Số ca |
|---|---|
| NO_EXFIL | 265 |
| UNCLEAR | 35 |
| **EXFIL** | **0** |

Tập tính metric (`data/ground_truth_eval.csv`, đã loại UNCLEAR): **265 mẫu, 0 positive**.

---

## 1. Điều này đổi cấu trúc Section 4

Với 0 positive, ba đại lượng sau **không định nghĩa được** trên Dataset A — mẫu số bằng 0:

- **Recall** = TP / (TP + FN), mà TP + FN = 0
- **F1**, vì nó cần Recall

**Precision** tính được về mặt số học nhưng vô nghĩa: mọi cảnh báo trên tập này đều là false positive theo định nghĩa, nên Precision luôn = 0%. Báo cáo con số đó như một phép đo chất lượng là sai; nó chỉ nói lại rằng không có positive.

⛔ **Không viết** "ExfilGuard đạt Precision X%, Recall Y%, F1 Z% trên Dataset A". Không có bảng nào như vậy trong bài.

---

## 2. Dataset A báo cáo cái gì

Ba đại lượng tính được và có nghĩa:

| Đại lượng | Công thức | Ý nghĩa |
|---|---|---|
| **FPR** | FP / (FP + TN) | Tỉ lệ báo động nhầm trên workflow lành |
| **Cảnh báo / 1000 workflow** | (TP + FP) / N × 1000 | Chi phí vận hành: một đội phải xử lý bao nhiêu cảnh báo |
| **Cảnh báo rơi vào nhóm UNCLEAR** | đếm trên 35 ca | Không vào FPR, phải báo riêng kẻo biến mất |

Cộng thêm phần định tính: **error analysis theo `path_type`** — cảnh báo nhầm tập trung ở hình dạng đường đi nào.

`src/12_build_master_results.py --metrics` tính sẵn cả bốn thứ này và ghi ra `data/metrics.md`.

---

## 3. Recall lấy từ đâu

**Hoàn toàn từ Dataset B**, bảng riêng, tiêu đề riêng, không gộp chung bảng với Dataset A. Đúng như thầy dặn ở mục 3 và 14: *Dataset B validates implemented capabilities; Dataset A exposes unsupported patterns and real-world ambiguity.*

Câu chốt dùng thống nhất trong bài:

> On the controlled benchmark, ExfilGuard correctly classified all applicable scenarios; on the manually labelled real-world subset no confirmed positive remained after independent adjudication, so that subset measures false-positive behaviour and coverage rather than recall.

---

## 4. Vì sao 0 EXFIL không phải là kết quả xấu

Đây là điểm phải nói rõ trong bài, không né:

Nhãn cũ có 13 EXFIL. Sau khi khóa guideline (source + propagation path + external sink, cả ba) và rà thủ công 65 ca, không ca nào giữ được nhãn EXFIL. Nguyên nhân là nhãn cũ gán theo **đồng hiện diện** — file có secret và có lệnh mạng — chứ không lần theo đường đi. Đó chính là điều thầy chỉ ra ở mục 1.

Kết quả này **củng cố** luận điểm trung tâm của bài chứ không phá nó: nếu co-occurrence đủ để kết luận thì đã có 13 positive; lần theo path thì còn 0. Khoảng cách giữa 13 và 0 chính là thứ ExfilGuard tồn tại để đo.

Nó cũng phù hợp với thực tế: 300 workflow lấy ngẫu nhiên từ repo công khai, exfiltration thật là sự kiện hiếm. Một dataset công khai mà có 4% workflow đang rò rỉ secret mới là điều đáng nghi.

---

## 5. Ba con số khác phải nêu trong Limitations

**35 ca UNCLEAR (11,7%)** — phân tách theo mã: U1 (script trong repo), U2 (action/reusable workflow), U3 (giá trị runtime), U5 (không xác định được chủ sở hữu endpoint). Đây là số đo trực tiếp giới hạn của phân tích chỉ trên file YAML.

**3/30 ca spot-check sai nhãn (~10%)** — mẫu ngẫu nhiên có seed từ nhóm hai annotator đồng thuận NO_EXFIL. Suy ra khoảng 20 ca trong 235 ca lấy tự động có thể còn sai. Nêu ra để trung thực về độ chính xác của dataset, kèm nguyên nhân cụ thể: cả ba ca đều do annotator dừng ở lệnh quen thuộc (`docker/login-action`, `gh api`, `yarn build`) mà không hỏi lệnh đó dẫn đi đâu.

**3 ca giao secret cho AI agent (1%)** — Claude Code action, opencode, và một workflow chạy một trong ba agent tùy cấu hình runtime. Ở lớp này G3 không tồn tại dưới dạng lệnh tĩnh: đích đến do mô hình quyết định lúc chạy. Định nghĩa external sink của guideline giả định sink là một lệnh trong file, và giả định đó không áp dụng được. Đưa vào Future Work.

---

## 6. Ảnh hưởng tới việc của từng người

**Ánh** — bảng baseline comparison không còn là bảng P/R/F1. Đổi thành bảng FPR + cảnh báo/1000 workflow, cộng một dòng nói mỗi tool phát hiện thuộc tính gì (mục 8 của thầy). Figure 3 đổi trục: FPR và alert rate, không phải Precision/Recall/F1.

**Khang** — phần contributions trong Intro không được hứa "high recall on real-world workflows". Nói đúng cái đo được: coverage gap và false-positive behaviour trên workflow thực tế, functional correctness trên benchmark có kiểm soát.

**Hà** — chạy tool xong xuất CSV hai cột `sample_id,result` (giá trị `EXFIL` hoặc `NO_EXFIL`) cho từng tool, rồi:

```bash
python3 src/12_build_master_results.py --merge \
  exfilguard=out/exfilguard.csv \
  zizmor=out/zizmor.csv \
  poutine=out/poutine.csv \
  gitleaks=out/gitleaks.csv
python3 src/12_build_master_results.py --metrics
```

Không tự tính metric bằng tay ở đâu khác.
