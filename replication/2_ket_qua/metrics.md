# Metrics — Dataset A

- Tong mau: **300**
- Tap danh gia (bo UNCLEAR): **262**
- Positive (EXFIL): **0** | Negative (NO_EXFIL): **262**
- UNCLEAR bao cao rieng: **38**

> **Khong co positive trong Dataset A.** Recall, Precision va F1 khong dinh nghia duoc tren tap nay (mau so bang 0). Bang duoi bao cao FPR va so canh bao / 1000 workflow — hai dai luong tinh duoc va co y nghia. Recall lay tu Dataset B, bao cao o bang rieng.

## Ket qua tung cong cu

| Tool | TP | FP | TN | FN | FPR | Canh bao/1000 wf | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|---|
| exfilguard | 0 | 11 | 251 | 0 | 4.2% | 42.0 | n/a (0 positive trong ground truth) | n/a (khong co positive) | n/a |
| zizmor | 0 | 236 | 26 | 0 | 90.1% | 900.8 | n/a (0 positive trong ground truth) | n/a (khong co positive) | n/a |
| poutine | 0 | 126 | 136 | 0 | 48.1% | 480.9 | n/a (0 positive trong ground truth) | n/a (khong co positive) | n/a |
| gitleaks | 0 | 4 | 258 | 0 | 1.5% | 15.3 | n/a (0 positive trong ground truth) | n/a (khong co positive) | n/a |

## Canh bao roi vao nhom UNCLEAR

UNCLEAR bi loai khoi tap tinh metric, nen canh bao o day khong vao FPR. Bao cao rieng de khong bien mat khoi bai.

| Tool | So canh bao tren 38 ca UNCLEAR |
|---|---|
| exfilguard | 7 |
| zizmor | 36 |
| poutine | 25 |
| gitleaks | 0 |

## Phan bo loai duong di

| path_type | So ca |
|---|---|
| agreement-no-review | 232 |
| unresolved-repo-script | 18 |
| auth-to-owner | 17 |
| unresolved-action | 14 |
| excluded-sink | 8 |
| unresolved-endpoint-ownership | 4 |
| local-only | 2 |
| no-source | 2 |
| unresolved-runtime-value | 2 |
| co-occurrence-only | 1 |
