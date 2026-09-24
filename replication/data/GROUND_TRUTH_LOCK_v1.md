# GROUND TRUTH LOCK v1 — khoa TRUOC khi chay bat ky detector nao

- Thoi diem khoa: 2026-09-09 (truoc lan chay ExfilGuard dau tien)
- Guideline: ANNOTATION_GUIDELINE_v1.0 (khoa)
- Phan bo: 300 mau — 265 NO_EXFIL, 35 UNCLEAR, 0 EXFIL
- Tap danh gia: 265
- Ca do trong tai: 65

## Hash
- `data/ground_truth.csv` : `e9e819f983635503db923d4c2fb5368571d2f9c436f7a0e35072a3ea0b2bae15`

## Ghi chu
Ban nay khoa truoc khi chay ExfilGuard/gitleaks/zizmor. Sau lan chay dau,
mot targeted audit ra soat 13 ca ExfilGuard canh bao, doi chieu voi guideline
v1.0 (khong xem output tool khi quyet dinh). Ket qua: 10 ca giu nguyen
NO_EXFIL, 3 ca (A0121, A0290, A0291) doi thanh UNCLEAR vi dich den khong giai
duoc tinh. Ban sau audit la v2, dung cho moi so lieu bao cao.
