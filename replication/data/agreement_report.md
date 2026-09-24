# Bao cao do dong thuan — Dataset A

- So mau duoc ca hai nguoi gan nhan: **300** / 300
- Ti le dong thuan tho (3 lop): **0.990**
- Cohen's kappa (3 lop: EXFIL/NO_EXFIL/UNCLEAR): **0.950**
- Cohen's kappa (2 lop, bo cac ca co UNCLEAR, n=266): **1.000** (dong thuan tho 1.000)
- So truong hop bat dong can trong tai: **3**

> Luu y khi viet bai: kappa cao ma so EXFIL rat nho thi kappa bi thoi phong boi lop da so. Nen bao cao kem phan bo nhan va so ca positive.

## Phan bo nhan

| Nhan | Nguoi 1 | Nguoi 2 |
|---|---|---|
| EXFIL | 1 | 1 |
| NO_EXFIL | 268 | 265 |
| UNCLEAR | 31 | 34 |

## Cac truong hop bat dong

| ID | Repo | File | Nguoi 1 | Nguoi 2 |
|---|---|---|---|---|
| A0043 | sl5net/SL5-aura-service | mac_setup.yml | NO_EXFIL | UNCLEAR |
| A0077 | nextcloud/health | release-appstore.yml | NO_EXFIL | UNCLEAR |
| A0285 | AnikaLegal/clerk | backup.yml | NO_EXFIL | UNCLEAR |

## Ground truth

Chua trong tai. Chay `src/09_build_adjudication_queue.py` roi `src/10_adjudicate.py`.
