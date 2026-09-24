# Phân tích nhạy cảm — ground truth v1 so với v2

v1 = nhãn khóa **trước** khi chạy bất kỳ detector nào.
v2 = sau targeted audit trên các ca ExfilGuard cảnh báo.

- v1: 265 NO_EXFIL · 35 UNCLEAR · 0 EXFIL — mẫu số **265**
- v2: 262 NO_EXFIL · 38 UNCLEAR · 0 EXFIL — mẫu số **262**

## FPR dưới hai ground truth

| Tool | FP (v1) | FPR (v1) | FP (v2) | FPR (v2) | Δ FPR | Alerts/1k (v1) | Alerts/1k (v2) |
|---|---|---|---|---|---|---|---|
| exfilguard | 14 | 5.3% | 11 | 4.2% | -1.1 pp | 52.8 | 42.0 |
| gitleaks | 4 | 1.5% | 4 | 1.5% | +0.0 pp | 15.1 | 15.3 |
| poutine | 126 | 47.5% | 126 | 48.1% | +0.5 pp | 475.5 | 480.9 |
| zizmor | 238 | 89.8% | 236 | 90.1% | +0.3 pp | 898.1 | 900.8 |

## Cảnh báo rơi vào nhóm UNCLEAR

| Tool | v1 (trên 35 ca) | v2 (trên 38 ca) |
|---|---|---|
| exfilguard | 4 (11.4%) | 7 (18.4%) |
| gitleaks | 0 (0.0%) | 0 (0.0%) |
| poutine | 25 (71.4%) | 25 (65.8%) |
| zizmor | 34 (97.1%) | 36 (94.7%) |

## Kết luận

Chuyển từ v1 sang v2 làm FPR của ExfilGuard đổi từ **5.3%** xuống **4.2%**, tức 1.1 điểm phần trăm.
Thứ hạng giữa các công cụ không đổi và kết luận của bài giữ nguyên dưới cả hai ground truth, nên việc đổi mẫu số sau khi xem output detector không mang lại lợi thế cho ExfilGuard.

Câu dùng cho bài:

> Under the pre-detector labels (v1) ExfilGuard's false-positive rate is 5.3% (14/265); under the adjudicated labels (v2) it is 4.2% (11/262). The ordering of the four tools and every conclusion drawn in this section are unchanged under either version.
