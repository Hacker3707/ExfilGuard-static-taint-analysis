# Quy trình trọng tài & khóa ground truth — Dataset A

Áp dụng `docs/ANNOTATION_GUIDELINE_v1.0.md`. Bốn bước dưới đây đúng theo thứ tự thầy yêu cầu.

## Bước 1 — Khóa guideline
`docs/ANNOTATION_GUIDELINE_v1.0.md` đã khóa. Không sửa. Sửa = tạo v1.1 + gán nhãn lại toàn bộ.

## Bước 2 — Rà lại thủ công theo guideline đã khóa
`src/09_build_adjudication_queue.py` chia 300 mẫu thành 5 nhóm:

| Nhóm | Nội dung | Xử lý |
|---|---|---|
| **B1_EXFIL_CLAIM** | Ít nhất một annotator gán EXFIL | **Bắt buộc** rà thủ công, phải điền đủ G1/G2/G3 |
| **B2_DISAGREE** | A1 ≠ A2 (và không thuộc B1) | **Bắt buộc** trọng tài |
| **B3_UNCLEAR** | Ít nhất một annotator gán UNCLEAR | **Bắt buộc** rà: xác nhận đúng là thiếu dữ liệu (U1–U5) hay thực ra quyết định được |
| **B4_SPOTCHECK** | Mẫu ngẫu nhiên có seed từ nhóm S1 mà cả hai đều NO_EXFIL | Kiểm tra false negative của khâu gán nhãn (S1 = có cả secret lẫn sink, chỗ dễ sót nhất) |
| **B0_AUTO** | Hai người đồng thuận, không thuộc nhóm trên | Lấy thẳng nhãn đồng thuận, note tự sinh |

Quy tắc khi rà: **không** mở output ExfilGuard/baseline. Không sửa từng ca cho khớp công cụ.

## Bước 3 — Thiếu dữ liệu thì UNCLEAR
Công cụ `src/10_adjudicate.py` bắt buộc chọn mã U1–U5 và mô tả *thiếu cái gì*. Không có đường tắt để gán EXFIL mà bỏ trống G1/G2/G3 — script `11` sẽ chặn.

## Bước 4 — Khóa rồi mới chạy detector
`src/11_finalize_ground_truth.py` sinh `data/ground_truth.csv`, `data/ground_truth_eval.csv` và `data/GROUND_TRUTH_LOCK.md` (chứa SHA256).

Sau đó, **trước và sau** mỗi lần chạy ExfilGuard/baseline:

```bash
python3 src/11_finalize_ground_truth.py --verify
```

Lệnh này in `[OK] ground truth khong doi` hoặc báo lỗi nếu file đã bị sửa. Dán kết quả này vào log thí nghiệm — đó là bằng chứng ground truth độc lập với detector.

---

## Định dạng `adjudication_note` (cố định, một dòng)

```
[MÃ] src=<...> | path=<...> | sink=<...> | why=<...> | basis=<...> | rev=v1.0
```

Ví dụ EXFIL:
```
[E1] src=SLACK_TOKEN@31 | path=secrets.SLACK_TOKEN@31 -> env TOKEN@31 -> $TOKEN@44 -> --data cua curl@44 | sink=curl@44 -> https://hooks.example.dev/ingest | why=token nam trong payload gui toi endpoint tu dat, khong phai xac thuc voi chu so huu | basis=arbiter | rev=v1.0
```

Ví dụ NO_EXFIL rà thủ công:
```
[N4] src=DOCKERHUB_TOKEN@103 | path=secrets.DOCKERHUB_TOKEN@103 -> with.password cua docker/login-action@102 | sink=docker/login-action@102 -> Docker Hub (sink loai tru 2.2) | why=xac thuc voi dung dich vu so huu secret | basis=arbiter | rev=v1.0
```

Ví dụ UNCLEAR:
```
[U1] src=DEPLOY_KEY@18 | path=secrets.DEPLOY_KEY@18 -> env DEPLOY_KEY@18 -> run ./scripts/deploy.sh@22 | sink=khong xac dinh duoc | why=noi dung deploy.sh khong co trong Dataset A | basis=arbiter | rev=v1.0
```

Dòng đồng thuận tự sinh:
```
[N-AUTO] src=- | path=- | sink=- | why=hai annotator dong thuan NO_EXFIL, khong thuoc dien ra soat | basis=agreement | rev=v1.0
```

**Viết note không dấu (ASCII)** để tránh lỗi encoding khi mở bằng Excel trên máy khác.

---

## Thứ tự lệnh

```bash
python3 src/08_merge_labels.py            # gộp nhãn A1/A2 vào review_sheet.csv
python3 src/06_agreement.py               # kappa + danh sach bat dong (KHONG sinh ground truth)
python3 src/09_build_adjudication_queue.py
python3 src/10_adjudicate.py --arbiter nhi
python3 src/11_finalize_ground_truth.py   # khoa + hash
python3 src/11_finalize_ground_truth.py --verify   # chay lai truoc/sau moi thi nghiem
```
