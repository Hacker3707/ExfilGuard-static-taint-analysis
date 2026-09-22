# ANNOTATION GUIDELINE v1.0 — Dataset A (ExfilGuard)

**Trạng thái: KHÓA (locked) từ 2026-09-08. Không sửa file này nữa.**
Mọi thay đổi phải tạo file mới `ANNOTATION_GUIDELINE_v1.1.md` và **gán nhãn lại toàn bộ**, không sửa tại chỗ.

Guideline này thay thế `docs/HUONG_DAN_GAN_NHAN.md` ở phần định nghĩa nhãn. File cũ giữ lại làm lịch sử.

---

## 1. Định nghĩa EXFIL (bắt buộc, 3 điều kiện)

Một workflow được gán `EXFIL` **khi và chỉ khi** chỉ ra được đồng thời cả ba thành phần, **trên các dòng cụ thể trong chính file YAML đó**:

| Ký hiệu | Thành phần | Yêu cầu tối thiểu |
|---|---|---|
| **G1** | **SOURCE xác định được** | Một giá trị bắt nguồn từ `${{ secrets.X }}`, `secrets: inherit` được tiêu thụ cụ thể, hoặc `GITHUB_TOKEN`. Phải ghi được `TÊN_SECRET@dòng`. |
| **G2** | **PROPAGATION PATH xác định được** | Chuỗi lan truyền tường minh từ G1 tới tham số/thân dữ liệu của G3. Phải ghi được từng chặng: `secrets.X@25 -> env SITE_TOKEN@25 -> $SITE_TOKEN@46 -> --data của curl@46`. |
| **G3** | **EXTERNAL SINK xác định được** | Một thao tác mạng mà **đích đến do người viết workflow chọn**, và **nội dung secret rời khỏi biên runner**. Phải ghi được `LỆNH@dòng -> ĐÍCH`. |

**Thiếu bất kỳ một trong ba → KHÔNG được gán EXFIL.**

### Điều cấm tuyệt đối
> **Không** được gán `EXFIL` vì lý do "file có secret **và** có lệnh mạng".
> Đồng hiện diện (co-occurrence) **không** phải bằng chứng. Đây là toàn bộ lý do tồn tại của bài báo (mục 2.2.D); nếu ground truth cũng dùng co-occurrence thì phần đánh giá vô nghĩa.

### Điều cấm thứ hai
> **Không** được xem output của ExfilGuard, SAST baseline, hay bất kỳ detector nào trong lúc gán nhãn/trọng tài. Ground truth phải độc lập với công cụ đang được đánh giá. Không sửa nhãn của một ca để khớp với output công cụ.

---

## 2. Quy tắc về SINK (G3)

### 2.1. Sink hợp lệ (external, do tác giả workflow chọn)
Webhook tùy ý, API endpoint tự đặt, URL lấy từ biến/secret/input, `nc`/`ncat`, `dig`/`nslookup` với dữ liệu nhúng trong tên miền, `scp`/`rsync`/`ssh` tới host không cố định, `curl`/`wget` tới domain do workflow chỉ định, `requests.post`, `fetch(`, `axios`, `Invoke-RestMethod`, `New-Object Net.WebClient`.

### 2.2. Sink bị loại trừ (hạ tầng cố định của hệ sinh thái) — mã **N3**
Đích đến không do tác giả chọn, không dùng để đánh giá exfiltration:

`actions/checkout` · `actions/cache` · `actions/upload-artifact` · `actions/download-artifact` · `setup-*` actions · `npm ci` / `npm install` / `yarn` / `pnpm` · `pip install` / `poetry install` · `apt-get` / `apk add` / `brew` · `go mod download` · `cargo fetch` / `mvn` / `gradle` · `docker pull` · `docker/login-action` · `docker/build-push-action` · `docker push` tới registry chính chủ · `gh release upload` trong chính repo · `codecov-action`.

### 2.3. Không phải sink mạng — mã **N2**
Ghi ra file trên runner (`> ~/.ssh/id_rsa`), `echo`/`printf` ra log, biến môi trường, `docker build --build-arg`, artifact nội bộ giữa các job.
Riêng secret bị `echo` ra log: **không** phải EXFIL theo định nghĩa bài này (log không phải kênh mạng), nhưng **phải ghi vào note** để mục Discussion phân tích riêng.

---

## 3. Quy tắc về PATH (G2)

**Được tính là lan truyền hợp lệ:**
- `secrets.X` → `env:` → biến shell → tham số lệnh mạng.
- `secrets.X` → ghi vào `$GITHUB_ENV` / `$GITHUB_OUTPUT` → step sau đọc ra → gửi đi (**mã E2**).
- `secrets.X` → ghi ra file trên runner → file đó được `curl --data-binary @file` / `scp` gửi đi.
- Có mã hóa/nén trung gian: `base64`, `gzip`, `openssl enc`, `xxd`, `jq -n --arg`. **Mã hóa KHÔNG phải sanitizer** (**mã E3**).

**Không được tính là lan truyền:**
- Secret chỉ xuất hiện ở `env:` của step nhưng lệnh mạng trong step đó không tham chiếu tới nó (**mã N6**).
- Secret là **địa chỉ đích hoặc định danh**, không phải dữ liệu được gửi: `ssh-keyscan $VM_HOST`, `ssh $VM_USER@$VM_HOST`, `curl "$SITE_URL/"` (**mã N5**).
- Secret dùng để **xác thực với đúng dịch vụ sở hữu nó**: `NPM_TOKEN` → npm registry, `DOCKERHUB_TOKEN` → Docker Hub, `AWS_*` → AWS, khóa SSH → máy chủ của chính tổ chức đó, `GITHUB_TOKEN` → api.github.com của chính repo (**mã N4**).

**Ranh giới N4 vs E4:** nếu **không xác định được tĩnh** endpoint có phải chủ sở hữu secret hay không (URL đến từ biến/secret không giải được), **không** được đoán → gán `UNCLEAR` mã **U5**.

---

## 4. Quy tắc UNCLEAR — khi nào bắt buộc dùng

Thiếu dữ liệu để quyết định thì **phải** gán `UNCLEAR`. Không được ép về `EXFIL` hay `NO_EXFIL`.

| Mã | Tình huống |
|---|---|
| **U1** | Đường đi nằm trong script của repo không có trong Dataset A (`run: ./deploy.sh`, `make deploy`, `npm run release`) và secret có trong `env:` của step đó. |
| **U2** | Đường đi nằm bên trong một third-party/composite action (`uses: someorg/some-action@v1`) được truyền secret qua `with:`/`env:`. |
| **U3** | Đích đến hoặc payload phụ thuộc giá trị runtime không giải được tĩnh (`${{ github.event.* }}`, `inputs.*`, biến sinh trong runtime). |
| **U4** | Đoạn trích bị cắt và không có file gốc trong `data/raw/` để đối chiếu. |
| **U5** | Không xác định được quyền sở hữu secret của endpoint (ranh giới N4/E4). |

`UNCLEAR` **không** bị loại khỏi dataset. Nó được báo cáo riêng và **loại khỏi tập tính Precision/Recall** (xem `ground_truth_eval.csv`), đúng chuẩn báo cáo dataset có nhãn không quyết định được.

---

## 5. Bảng mã lý do (bắt buộc điền khi trọng tài)

**EXFIL**
| Mã | Nghĩa |
|---|---|
| E1 | Giá trị secret nằm trong payload/body gửi tới endpoint do tác giả chọn (webhook, API tự đặt) |
| E2 | Secret đi qua `$GITHUB_ENV`/`$GITHUB_OUTPUT` sang step sau rồi ra mạng |
| E3 | Secret được encode/nén/biến đổi rồi mới gửi ra ngoài |
| E4 | Secret gửi tới bên thứ ba không sở hữu secret đó |

**NO_EXFIL**
| Mã | Nghĩa |
|---|---|
| N1 | Không có source (G1 fail) |
| N2 | Không có thao tác mạng; chỉ ghi file/log trên runner |
| N3 | Sink thuộc hạ tầng cố định bị loại trừ (mục 2.2) |
| N4 | Secret xác thực với đúng dịch vụ sở hữu nó |
| N5 | Secret chỉ là đích đến/định danh, không phải dữ liệu gửi đi |
| N6 | Đồng hiện diện secret + lệnh mạng nhưng không có đường nối (G2 fail) |

**UNCLEAR**: U1–U5 như mục 4.

---

## 6. Thứ tự phán đoán (bắt buộc theo đúng thứ tự)

```
Q1. Có G1 (source cụ thể, có dòng)?          không -> NO_EXFIL (N1), dừng
Q2. Có thao tác mạng nào không thuộc 2.2/2.3? không -> NO_EXFIL (N2 hoặc N3), dừng
Q3. Có G2 (chuỗi lan truyền tường minh)?      không -> NO_EXFIL (N6), dừng
                                              không đọc được vì mã ngoài file -> UNCLEAR (U1/U2/U3/U4)
Q4. Đích có sở hữu secret đó không?           có   -> NO_EXFIL (N4)
                                              không xác định được -> UNCLEAR (U5)
                                              không -> EXFIL (E1/E2/E3/E4)
```

---

## 7. Ví dụ chuẩn đã giải (dùng để hiệu chuẩn)

**A0001** — `vicharanashala/ajrasakha / build_and_deploy_reviewer.yml` → **NO_EXFIL**
- `docker/login-action` với `DOCKERHUB_TOKEN` → N4 (xác thực đúng chủ) + N3 (sink loại trừ).
- `VITE_*` truyền vào `build-args` → N2 (không phải thao tác mạng).
- `echo "${{ secrets.SSH_PRIVATE_KEY }}" > ~/.ssh/id_ed25519` → N2 (ghi file trên runner).
- `ssh-keyscan -H ${{ secrets.VM_HOST }}` → N5 (secret là đích, không phải dữ liệu).
- Kết luận: **N6/N4** — đủ secret, đủ network op, không có đường nối. Đây chính là ca "co-occurrence is not enough".

**A0299** — `ahtavarasmus/lightfriend / external-watchdog.yml` → **phải rà lại thủ công, không mặc định EXFIL**
- `MAINTENANCE_SECRET@26` → `env` → `-H "X-Maintenance-Secret: $MAINTENANCE_SECRET"@76` → `curl` tới `$SITE_URL/api/health/deep` — đây là **xác thực với chính dịch vụ của mình** (`SITE_URL` = `secrets.LIGHTFRIEND_URL`, mặc định `https://lightfriend.ai`) → hướng **N4**.
- `NOTIFY_SERVER_TOKEN@28` → `-H "Authorization: Bearer $NOTIFY_SERVER_TOKEN"@47` tới `${NOTIFY_SERVER_URL%/}/alert` — `NOTIFY_SERVER_URL` là secret, **không giải được tĩnh** endpoint là ai → hướng **U5**.
- Ghi đầy đủ G1/G2/G3 rồi mới chốt. **Không** được giữ nhãn EXFIL chỉ vì trước đó đã gán vậy.

---

## 8. Ghi chú giới hạn phải nêu trong bài

Với 300 mẫu lấy từ workflow thực tế công khai, số ca `EXFIL` rất nhỏ (thường 0–3). Hệ quả bắt buộc phải viết trong Limitations:

- Dataset A **không đủ positive để ước lượng Recall có ý nghĩa thống kê**. Dataset A trả lời câu hỏi: *công cụ hành xử thế nào trên workflow thực tế* → báo cáo **FPR**, **số cảnh báo/1000 workflow**, và **case study** trên các ca positive.
- **Recall phải lấy từ Dataset B** (bộ ca dựng có chủ đích / injected), báo cáo tách bạch, không gộp chung một bảng Precision/Recall như thể cùng một tập.
