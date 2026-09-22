# AUDIT TRAIL — truy vết từng cảnh báo của ExfilGuard

Sinh tự động bằng `src/15_audit_trail.py` từ `ground_truth.csv`, `adjudication.csv`, `review_sheet.csv` và `out/*.csv`. Không nhập số bằng tay.

- Tổng mẫu: **300**
- ExfilGuard cảnh báo: **18**
- Ca được targeted audit (bucket `B6_TARGETED_AUDIT`): **13**
- Ca đổi nhãn sau audit: **3**

## Bảng truy vết — toàn bộ ca ExfilGuard cảnh báo

| workflow_id | repo / file | v1 label | v2 label | đổi nhãn | mã | trong mẫu số v1 | trong mẫu số v2 | phân loại v1 | phân loại v2 |
|---|---|---|---|---|---|---|---|---|---|
| A0099 | stefanko-ch/Nexus-Stack / spin-up.yml | UNCLEAR | UNCLEAR | — | U1 | không | không | alert-on-UNCLEAR | alert-on-UNCLEAR |
| A0108 | corosolto/client / staging.yml | NO_EXFIL | NO_EXFIL | — | N5 | có | có | FP | FP |
| A0111 | reloop-labs/reloop / be-campaigns.yml | NO_EXFIL | NO_EXFIL | — | N4 | có | có | FP | FP |
| A0120 | reloop-labs/reloop / be-mail.yml | NO_EXFIL | NO_EXFIL | — | N4 | có | có | FP | FP |
| A0121 | ourresearch/openalex-walden / build-dlt-utils-wheel.yml | NO_EXFIL | UNCLEAR | **có** | U5 | có | không | FP | alert-on-UNCLEAR |
| A0130 | corosolto/client / deploy-prod.yml | NO_EXFIL | NO_EXFIL | — | N4 | có | có | FP | FP |
| A0186 | yanet-platform/yanet2 / glm-review.yml | NO_EXFIL | NO_EXFIL | — | N4 | có | có | FP | FP |
| A0218 | zzstoatzz/plyr.fm / integration-tests.yml | NO_EXFIL | NO_EXFIL | — | N4 | có | có | FP | FP |
| A0219 | sipyourdrink-ltd/bernstein / bernstein-pr-review.yml | NO_EXFIL | NO_EXFIL | — | N3 | có | có | FP | FP |
| A0227 | reloop-labs/reloop / be-contacts.yml | NO_EXFIL | NO_EXFIL | — | N4 | có | có | FP | FP |
| A0228 | NeoZi12/dispatchseo / jobs.yml | NO_EXFIL | NO_EXFIL | — | N4 | có | có | FP | FP |
| A0230 | cijerezg/lerobot / latest_deps_tests.yml | UNCLEAR | UNCLEAR | — | U2 | không | không | alert-on-UNCLEAR | alert-on-UNCLEAR |
| A0256 | ad-naan/Adnify / release.yml | NO_EXFIL | NO_EXFIL | — | N4 | có | có | FP | FP |
| A0258 | NeoZi12/dispatchseo / seo-tools.yml | UNCLEAR | UNCLEAR | — | U2 | không | không | alert-on-UNCLEAR | alert-on-UNCLEAR |
| A0272 | ad-freiburg/qlever / sparql-conformance-uploader.yml | NO_EXFIL | NO_EXFIL | — | N4 | có | có | FP | FP |
| A0290 | Surfboardv2ray/Proxy-sorter / sorter.yml | NO_EXFIL | UNCLEAR | **có** | U1 | có | không | FP | alert-on-UNCLEAR |
| A0291 | Layr-Labs/d-inference / register-model.yml | NO_EXFIL | UNCLEAR | **có** | U3 | có | không | FP | alert-on-UNCLEAR |
| A0299 | ahtavarasmus/lightfriend / external-watchdog.yml | UNCLEAR | UNCLEAR | — | U5 | không | không | alert-on-UNCLEAR | alert-on-UNCLEAR |

## Trả lời bốn câu hỏi

**1. Ca nào được targeted audit?** 13 ca: `A0108`, `A0111`, `A0120`, `A0121`, `A0130`, `A0186`, `A0218`, `A0227`, `A0228`, `A0256`, `A0272`, `A0290`, `A0291`.

**2. Có phải cả 13 đều là ExfilGuard alert?** Có — cả 13 ca đều nằm trong danh sách cảnh báo.

**3. Tại sao v2 còn 11 FP chứ không phải 10?**

ExfilGuard cảnh báo **18** workflow, trong đó **14** rơi vào nhãn NO_EXFIL (v1) và **4** rơi vào UNCLEAR.
Trong 14 ca NO_EXFIL đó, **1** ca đã được trọng tài thủ công từ vòng rà đầu nên không thuộc diện audit lại: `A0219` (mã N3).
Vì vậy chỉ **13** ca được audit. Sau audit, **3** ca chuyển sang UNCLEAR, còn lại **14 − 3 = 11** false positive.

**4. Alerts/1,000 tính thế nào?** (TP + FP) / mẫu số × 1000 = (0 + 11) / 262 × 1000 = **42.0**. Mẫu số là tập đánh giá v2 sau khi loại UNCLEAR.

## Ba ca đổi nhãn

| workflow_id | v1 | v2 | mã | lý do |
|---|---|---|---|---|
| A0121 | NO_EXFIL | UNCLEAR | U5 | endpoint la secret nen khong xac dinh duoc co phai Databricks workspace chinh chu hay khong; cung hinh dang voi A0299 |
| A0290 | NO_EXFIL | UNCLEAR | U1 | noi dung python/sorter.py khong co trong Dataset A; VMESS_URL/VLESS_URL@56-57 chi la dia chi dich cua curl@60-61 (N5) |
| A0291 | NO_EXFIL | UNCLEAR | U3 | dich den lay tu workflow input nen khong giai duoc tinh |
