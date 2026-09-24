# GROUND TRUTH LOCK — Dataset A

- Thoi diem khoa: **2026-09-17 09:33:50 +0700**
- Guideline: `ANNOTATION_GUIDELINE_v1.0` (khoa)
- Tong mau co nhan cuoi: **300** / 300
- Tap dung danh gia (loai UNCLEAR): **262**
- Ca do trong tai quyet dinh: **78** | lay tu dong thuan: **222**

## Hash (dung de chung minh ground truth doc lap voi detector)

- `data/ground_truth.csv` : `2aa0f8b7e153e67eedacb48b383dd2cbcf36ec93d0576633e8c5360106fdab35`
- `data/ground_truth_eval.csv` : `ff241b91f8ca3be89b2d12a847c7d5ed68065806dc475b7563750e0182bee2b3`
- `docs/ANNOTATION_GUIDELINE_v1.0.md` : `ca22d2921185f69ac34eada549c3990b1ccdb1a475a4af814ee5a40ab149f47d`

Kiem tra lai bat ky luc nao:

```bash
python3 src/11_finalize_ground_truth.py --verify
```

Chay lenh nay **truoc va sau** moi lan chay ExfilGuard/baseline va dan ket qua vao log thi nghiem.

## Phan bo nhan cuoi

| Nhan | So luong | Ti le |
|---|---|---|
| NO_EXFIL | 262 | 87.3% |
| UNCLEAR | 38 | 12.7% |

## Phan bo theo tang

| Tang | NO_EXFIL | UNCLEAR |
|---|---|---|
| S1_secret_and_sink | 124 | 26 |
| S2_secret_only | 58 | 12 |
| S3_sink_only | 40 | 0 |
| S4_neither | 40 | 0 |

## Ma ly do

| Ma | So luong |
|---|---|
| N-AUTO | 222 |
| N4 | 26 |
| U1 | 18 |
| U2 | 14 |
| N3 | 8 |
| U5 | 4 |
| N2 | 2 |
| N1 | 2 |
| U3 | 2 |
| N5 | 1 |
| N6 | 1 |

## Nguon quyet dinh

| Nguon | So luong |
|---|---|
| agreement | 222 |
| arbiter:nhi | 78 |

## Ghi chu bat buoc dua vao Limitations

- Chi co **0** ca EXFIL trong 262 mau danh gia. So positive nay **khong du de uoc luong Recall co y nghia thong ke** tren Dataset A.
- Dataset A dung de bao cao: **FPR**, **so canh bao / 1000 workflow**, va **case study** tren cac ca positive. **Recall lay tu Dataset B** va bao cao tach bang rieng.
- Neu bao cao Recall tren 0 positive, khoang tin cay se rong toi muc vo nghia — phan bien se hoi ngay diem nay.
- UNCLEAR duoc bao cao rieng, loai khoi tap tinh P/R/F1/FPR (`ground_truth_eval.csv`), khong ep ve EXFIL hay NO_EXFIL.
