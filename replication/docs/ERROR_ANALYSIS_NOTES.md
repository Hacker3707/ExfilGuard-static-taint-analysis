# Ghi chú error analysis — chất liệu cho Section 4 (RQ3)

Rút từ 65 ca rà thủ công khi khóa ground truth. Mọi quan sát dưới đây đều có ca cụ thể
kèm số dòng trong `data/adjudication.csv`, không phải suy diễn.

Số liệu chính xác lấy bằng lệnh, đừng gõ tay:

```bash
# Phan bo ma ly do tren 65 ca ra soat
awk -F, 'NR>1{print $4}' data/adjudication.csv | sort | uniq -c | sort -rn

# Phan bo tren ca 300 mau (gom ca 235 ca lay tu dong thuan)
awk -F, 'NR>1{print $7}' data/ground_truth.csv | sort | uniq -c | sort -rn

# Cac ca UNCLEAR va ma cua chung
awk -F, 'NR>1 && $6=="UNCLEAR"{print $1, $7}' data/ground_truth.csv
```

---

## 1. Vì sao 35 ca không kết luận được — bốn hình dạng

Đây là số đo trực tiếp giới hạn của phân tích chỉ trên file YAML. Mỗi mã là một
**ranh giới khác nhau**, và ba trong bốn ranh giới đó vá được, một thì không.

**U1 — đường đi thoát vào script của repo.** Secret nằm trong `env:` của step, lệnh
trong `run:` là `./deploy.sh`, `bash scripts/x.sh`, `poetry run <entrypoint>`,
`uv run main.py`, `yarn build:agent`, hoặc `. path/to/run` (source, không phải exec).
Nội dung script không có trong Dataset A vì Dataset A chỉ thu file workflow.
**Vá được** nếu mở rộng phạm vi thu thập sang toàn repo — nhưng đó là quyết định về
dataset, không phải về tool.

**U2 — đường đi thoát vào action hoặc reusable workflow.** Ba loại con, khác nhau về
mức độ vá được:
- Composite action **cùng repo** (`./.github/actions/x`) — vá được, chỉ cần đọc thêm `action.yml` trong cùng cây thư mục.
- Third-party action đã pin SHA — vá được nếu fetch action đó về, nhưng thành phân tích liên repo.
- Reusable workflow ở repo khác (`org/repo/.github/workflows/x.yml@main`) — như trên.

**U3 — đích đến phụ thuộc giá trị runtime.** Ví dụ điển hình: một workflow tải nội dung
từ URL là secret rồi commit vào repo. Không giải được tĩnh vì thông tin không tồn tại
trong file.

**U5 — không xác định được quyền sở hữu endpoint.** Đây là ranh giới **không vá được
bằng kỹ thuật**: `curl -H "Authorization: Bearer $TOKEN" "$ENDPOINT/alert"` trong đó
`ENDPOINT` cũng là secret. Ngay cả khi đọc được mọi script và mọi action, vẫn không biết
endpoint đó là hạ tầng chính chủ hay bên thứ ba. Câu hỏi "đích có sở hữu secret không"
là câu hỏi về **quan hệ tổ chức**, không phải về code.

Điểm để viết vào bài: tách U1/U2 (vá được, là capability gap) khỏi U3/U5 (không vá được,
là giới hạn thông tin) là cách trung thực hơn nhiều so với gộp chung thành "11,7% không
kết luận được".

---

## 2. Ba ca spot-check sai nhãn — cùng một nguyên nhân

Mẫu ngẫu nhiên có seed từ nhóm hai annotator đồng thuận NO_EXFIL. 3/30 sai, và cả ba
sai theo **cùng một cách**: annotator dừng ở lệnh quen thuộc mà không hỏi lệnh đó dẫn đi
đâu, trong khi trong cùng file còn một đường thứ hai chưa được xét.

- Ca OSV-Scanner bump: dừng ở `gh api` đọc public API, bỏ qua `peter-evans/create-pull-request` nhận token ghi.
- Ca Docker Hub description: dừng ở `docker/login-action` (quen thuộc, loại trừ), bỏ qua `peter-evans/dockerhub-description` nhận **cùng cặp credential**.
- Ca Ever Works agent build: dừng ở `docker/login-action`, bỏ qua `yarn build:agent:*` chạy electron-builder có publish thật lên GitHub Releases và DigitalOcean Spaces.

Suy ra khoảng 20 ca trong 235 ca lấy tự động có thể còn sai nhãn. Nêu trong Limitations
kèm nguyên nhân cụ thể này — nó biến một con số xấu thành một quan sát có ích: **lỗi gán
nhãn tập trung ở workflow có nhiều đường đi, khi một đường rõ ràng che khuất đường còn lại**.

---

## 3. Lớp workflow mà định nghĩa hiện tại không mô tả được: AI agent trong CI

Ba ca (1% mẫu). Cả ba đều có G1 và G2 xác định được, nhưng G3 **không tồn tại dưới dạng
lệnh trong file** — đích đến do mô hình ngôn ngữ quyết định lúc chạy.

- Workflow giao `CARGO_REGISTRY_TOKEN` + `PYPI_API_TOKEN` + SSH deploy key cho `anthropics/claude-code-action` chạy với `--dangerously-skip-permissions`, allowedTools có `Bash`, `WebFetch`, `WebSearch`.
- Workflow giao API key cho `opencode`, và nhét `$ISSUE_TITLE` / `$ISSUE_BODY` — nội dung do người ngoài viết — vào prompt của agent. Tác giả có câu phòng thủ bằng lời văn trong prompt, tức là **biết** rủi ro prompt injection.
- Workflow render 6 credential vào file config MCP rồi giao cho một trong ba agent (Claude/Codex/Cursor), agent nào chạy do backend bên ngoài quyết định qua HTTP.

Guideline v1.0 định nghĩa external sink là "thao tác mạng mà đích đến do người viết
workflow chọn". Giả định ngầm: đích đến là tĩnh. Với lớp này giả định đó sai. Đưa vào
Future Work, không cố ép vào định nghĩa hiện tại.

---

## 4. Anti-pattern lặp lại — quan sát phụ, đáng một đoạn ngắn

**Secret nội suy vào URL git remote** — 3 ca: `git remote set-url origin
https://x-access-token:${TOKEN}@github.com/...`. Token nằm trong `.git/config` và trong
process list. Không phải exfiltration theo định nghĩa bài (đích là GitHub chính chủ),
nhưng là rủi ro thật.

**Secret nội suy thẳng vào dòng `run:`** — `./transcrypt -p '${{ secrets.X }}'`,
`echo "${{ secrets.KEY }}" > file`. Lọt vào log nếu step bật `set -x`.

**Pinning không nhất quán** — trong cùng dataset có workflow pin mọi action theo SHA và
`persist-claim: false` khắp nơi, lại có workflow `curl | python3 -` từ repo bên khác,
nhánh `main`, không pin commit, chạy với `permissions: write-all`.

---

## 5. Hai ca dùng làm ví dụ minh họa trong bài

**Cho luận điểm "co-occurrence is not enough" (mục 2.2.D):** ca `diffsky` — hai secret
trong `env:` của step, hàng chục lệnh mạng trong cùng file (`pip install git+`, `wget` ×8,
`conda install`), nhưng không một lệnh nào tham chiếu tới secret. Đường đi đơn giản là
không tồn tại. Sạch hơn ca A0001 vì không phải lập luận N3/N4 gì cả.

**Cho RQ3 "where does this explanation fail":** ca `Layr-Labs/d-inference` — vòng lặp bash
dùng indirect expansion `value="${!primary:-}"` để chọn secret theo prefix runtime, ghi vào
`$GITHUB_ENV`, step sau đọc ra qua `${{ env.release_key }}`. Tên biến nguồn
(`PROD_RELEASE_KEY`) và tên biến đích (`release_key`) **không khớp nhau ở bất kỳ dòng nào**
— chúng chỉ nối được qua ngữ nghĩa của `${!var}` và `tr '[:upper:]' '[:lower:]'`. Đây là
giới hạn lý thuyết của static taint analysis, không phải lỗi implementation. Nếu ExfilGuard
bỏ sót ca này thì đó là dữ liệu cho Limitations, không phải điểm trừ.

---

## 6. Quan sát ngược chiều — đáng nêu để bài không một chiều

Trong 300 mẫu có những workflow **phòng thủ tốt**: `persist-credentials: false` ở mọi
checkout, `unset GITHUB_TOKEN` đầu mỗi step build, sanitize mọi thứ ghi vào step summary,
action pin theo SHA. Một ca còn dùng **vắng mặt secret** làm cơ chế bảo vệ có chủ đích:
comment giải thích dài rằng lane refresh cố ý không có `NPM_TOKEN` trong `env:` để
publishing "unreachable by construction" thay vì dựa vào điều kiện `if:`.

Hướng ứng dụng khác của cùng kỹ thuật: phân tích tĩnh có thể **xác nhận một thuộc tính
bảo mật tích cực** ("step này không có credential nào tới được"), không chỉ đi tìm lỗi.
Một câu trong Discussion là đủ.
