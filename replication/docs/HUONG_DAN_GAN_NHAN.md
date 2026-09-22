# Gán nhãn 300 mẫu — làm thế nào

## Câu hỏi duy nhất phải trả lời

> Trong workflow này, có tồn tại một đường đi từ một secret tới một thao tác mạng
> mà nội dung secret có thể bị đưa ra ngoài hay không?

Chỉ trả lời câu này. Không đánh giá workflow có an toàn nói chung không, không đánh giá
quyền, không đánh giá việc ghim action theo hash.

## Ba nhãn

| Nhãn | Khi nào dùng |
|---|---|
| `EXFIL` | Có ít nhất một đường đi hoàn chỉnh từ secret tới sink mạng. Phải chỉ ra được cả điểm đầu và điểm cuối |
| `NO_EXFIL` | Có secret, có thể có cả thao tác mạng, nhưng không đường nào nối được hai thứ đó |
| `UNCLEAR` | Không kết luận được vì đường đi phụ thuộc mã ngoài file (script trong repo, composite action) |

---

## Bốn câu hỏi, hỏi theo đúng thứ tự

Đọc xong mỗi mẫu thì chạy qua bốn câu này. Đừng đọc cả file rồi "cảm thấy" — hỏi theo thứ tự
sẽ nhanh hơn và hai người sẽ đồng thuận cao hơn.

**Câu 1 — Có secret thật không?**
Tìm `${{ secrets.* }}`, `secrets: inherit`, `GITHUB_TOKEN`. Không có → `NO_EXFIL`, xong.
Tên biến trông nhạy cảm nhưng không có nguồn `secrets.*` thì không tính.

**Câu 2 — Có thao tác mạng do workflow điều khiển không?**
`curl`, `wget`, `nc`, `dig`, `nslookup`, `scp`, `rsync`, `requests.post`, `fetch(`.
Không có → `NO_EXFIL`, xong.

**KHÔNG tính là sink:** `actions/checkout`, `npm ci`, `pip install`, `docker pull`,
`docker/login-action`, `docker/build-push-action`. Đích đến của chúng là hạ tầng cố định của
hệ sinh thái, không do người viết workflow chọn.

**Câu 3 — Secret có ĐI VÀO thao tác mạng đó không?**
Đây là câu quyết định. Lần theo: `secrets.X` → `env:` → biến shell → tham số của lệnh mạng.
Nếu secret chỉ nằm cùng file mà không chạm tới lệnh đó → `NO_EXFIL`.

**Câu 4 — Đích đến có chính đáng không?**
Secret đi tới đúng dịch vụ mà nó thuộc về (`NPM_TOKEN` cho npm registry, `DOCKERHUB_TOKEN` cho
Docker Hub, khoá SSH để vào chính máy chủ của mình) → `NO_EXFIL`.
Đích do workflow chọn tuỳ ý, hoặc secret nằm trong *nội dung* gửi đi chứ không phải để xác
thực với chính đích đó → `EXFIL`.

---

## Sáu trường hợp ranh giới — thống nhất trước

1. **Secret xác thực với dịch vụ chính đáng.** `docker login`, `npm publish`. → `NO_EXFIL`.
2. **Secret gửi tới webhook**, ví dụ thông báo Slack có kèm token trong payload. → `EXFIL`.
3. **Secret ghi vào `$GITHUB_ENV` hoặc `$GITHUB_OUTPUT` rồi dùng ở step sau.** Phải lần theo
   tới step sau. Step sau đưa ra mạng → `EXFIL`.
4. **Secret in ra log bằng `echo`.** → **không** phải `EXFIL` theo định nghĩa của bài, vì log
   không phải kênh mạng. Ghi vào note, nhóm phân tích riêng.
5. **Secret bị base64 rồi mới gửi.** Vẫn `EXFIL`. Mã hoá không phải sanitizer.
6. **Đường đi nằm trong file script của repo**, ví dụ `run: ./deploy.sh` với secret trong env.
   → `UNCLEAR`, vì nội dung `deploy.sh` không có trong Dataset A.

---

## Ví dụ đã giải sẵn — mẫu A0001

Workflow này (Reviewer App Deployment) có **rất nhiều** secret và **rất nhiều** thao tác mạng.
Nhìn qua tưởng là `EXFIL`. Đáp án là `NO_EXFIL`. Lý do từng chỗ:

| Chỗ trong file | Phân tích |
|---|---|
| `docker/login-action` với `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN` | Xác thực với đúng Docker Hub. Câu 4 → không phải exfil |
| `build-args` truyền các `VITE_*` secret vào docker build | Không phải thao tác mạng. Câu 2 → không phải sink |
| `echo "${{ secrets.SSH_PRIVATE_KEY }}" > ~/.ssh/id_ed25519` | Ghi ra file trên runner, không ra mạng. Câu 2 → không phải sink |
| `ssh-keyscan -H ${{ secrets.VM_HOST }}` | Có ra mạng, nhưng secret ở đây là **địa chỉ đích**, không phải dữ liệu được gửi đi. Câu 3 → không phải exfil |
| `ssh ${{ secrets.VM_USER }}@${{ secrets.VM_HOST }}` | Đăng nhập vào chính máy chủ của mình bằng khoá của mình. Câu 4 → chính đáng |

Đây chính là loại ca mà mục 2.2.D của bài gọi là "co-occurrence is not enough": đủ secret, đủ
sink, nhưng không có đường nối. Ghi vào note: "nhieu secret + nhieu network op, khong co
duong noi; ssh/docker login la xac thuc chinh dang".

**Kỳ vọng chung: phần lớn tầng S1 sẽ là `NO_EXFIL`.** Tỉ lệ `EXFIL` thường chỉ 5-15%. Nếu gán
được 50 mẫu mà chưa thấy `EXFIL` nào thì vẫn bình thường, đừng nghĩ là mình làm sai.

---

## Chạy công cụ gán nhãn

Đừng mở từng file bằng `cat`. Dùng công cụ, nhanh hơn nhiều lần và không sai sót thứ tự.

```bash
python src/07_label.py --annotator 1     # người thứ nhất
python src/07_label.py --annotator 2     # người thứ hai, trên máy của họ
```

Công cụ hiện đoạn trích liên quan rồi hỏi nhãn. Phím:

```
e  EXFIL        n  NO_EXFIL      u  UNCLEAR
f  xem cả file  b  lùi lại 1 mẫu  s  bỏ qua  q  thoát
```

Ghi ngay sau mỗi mẫu vào `data/labels_a1.csv` hoặc `labels_a2.csv`, nên tắt giữa chừng không
mất gì. Chạy lại lệnh cũ là tiếp tục từ chỗ đang dở.

Hai người ghi ra hai file khác nhau nên không đụng nhau. **Gán nhãn độc lập, không nhìn màn
hình của nhau, không bàn bạc trong lúc làm.**

---

## Chia phiên và kiểm kappa sớm

Chia 3 phiên, mỗi phiên 100 mẫu. **Sau phiên đầu tiên, gộp và kiểm kappa ngay:**

```bash
python src/08_merge_labels.py
python src/06_agreement.py
```

Đọc `data/agreement_report.md`:

- **kappa ≥ 0,60** → tiếp tục hai phiên còn lại.
- **kappa < 0,60** → **dừng lại**. Hai người ngồi cùng nhau, mở 10 ca bất đồng đầu tiên trong
  báo cáo, xem tại sao hiểu khác nhau, bổ sung quy tắc vào phần "Sáu trường hợp ranh giới" ở
  trên, rồi **gán nhãn lại từ đầu** (xoá `labels_a1.csv` và `labels_a2.csv`).

Đừng sửa vài dòng cho khớp nhau để kappa đẹp lên. Đó là bịa số, và mất luôn ý nghĩa của việc
gán nhãn độc lập.

Kiểm sớm sau 100 mẫu là để nếu phải làm lại thì chỉ mất 100 mẫu, không mất 300.

---

## Bước cuối: trọng tài

Sau khi cả hai gán xong 300 mẫu:

```bash
python src/08_merge_labels.py
python src/06_agreement.py
```

Người thứ ba mở `data/review_sheet.csv`, tìm các dòng có `annotator1_label` khác
`annotator2_label`, quyết định và điền vào cột `final_label`. Các dòng hai người đã đồng ý thì
chép thẳng nhãn đó vào `final_label`.

Chạy lại `python src/06_agreement.py` lần cuối để sinh `data/ground_truth.csv`.

---

## Bốn con số phải báo cáo trong bài

1. Số mẫu được gán nhãn và cách phân tầng
2. Cohen's kappa và tỉ lệ đồng thuận thô
3. Số ca phải đưa trọng tài
4. Phân bố nhãn cuối cùng

Thiếu kappa là điểm phản biện chắc chắn hỏi tới.

---

## Ước lượng thời gian

Mỗi mẫu 1-2 phút. 300 mẫu ≈ 6-9 tiếng mỗi người. Chia 3 phiên, mỗi phiên khoảng 2-3 tiếng.
Đừng cố làm hết trong một buổi — gán nhãn mệt thì chất lượng tụt và kappa xuống theo.
