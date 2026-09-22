"""
Bước 6 — Cohen's kappa giữa hai người gán nhãn + danh sách bất đồng.

ĐÃ SỬA (v2): script này KHÔNG còn sinh data/ground_truth.csv nữa.
Ground truth do src/11_finalize_ground_truth.py sinh, sau khi trọng tài đã điền
bằng chứng G1/G2/G3. Trước đây 06 ghi đè ground_truth.csv mà không có
adjudication_note, làm mất bằng chứng.

Chạy:  python3 src/06_agreement.py
Ra:    data/agreement_report.md
"""
import csv
import os
import sys
from collections import Counter

SHEET = "data/review_sheet.csv"
LEGACY = "data/ground_truth.csv"


def read_csv(p):
    with open(p, encoding="utf-8-sig", errors="replace", newline="") as f:
        return list(csv.DictReader(f))


def kappa(a, b):
    labels = sorted(set(a) | set(b))
    n = len(a)
    if n == 0:
        return None, None
    po = sum(1 for x, y in zip(a, b) if x == y) / n
    ca, cb = Counter(a), Counter(b)
    pe = sum((ca[l] / n) * (cb[l] / n) for l in labels)
    if pe >= 1:
        return 1.0, po
    return (po - pe) / (1 - pe), po


def main():
    path = SHEET if os.path.exists(SHEET) else LEGACY
    if not os.path.exists(path):
        sys.exit(f"Khong tim thay {SHEET}.")
    rows = read_csv(path)

    both = [r for r in rows
            if (r.get("annotator1_label") or "").strip() and (r.get("annotator2_label") or "").strip()]
    if not both:
        print("Chua co dong nao duoc ca hai nguoi gan nhan. Chay src/08_merge_labels.py truoc.")
        return

    a = [r["annotator1_label"].strip().upper() for r in both]
    b = [r["annotator2_label"].strip().upper() for r in both]
    k, po = kappa(a, b)

    # kappa 2 lop tren cac ca ca hai deu quyet dinh duoc (bo UNCLEAR)
    dec = [(x, y) for x, y in zip(a, b) if x != "UNCLEAR" and y != "UNCLEAR"]
    k2, po2 = kappa([x for x, _ in dec], [y for _, y in dec]) if dec else (None, None)

    disagree = [r for r in both
                if r["annotator1_label"].strip().upper() != r["annotator2_label"].strip().upper()]

    L = ["# Bao cao do dong thuan — Dataset A", "",
         f"- So mau duoc ca hai nguoi gan nhan: **{len(both)}** / {len(rows)}",
         f"- Ti le dong thuan tho (3 lop): **{po:.3f}**",
         f"- Cohen's kappa (3 lop: EXFIL/NO_EXFIL/UNCLEAR): **{k:.3f}**"]
    if k2 is not None:
        L.append(f"- Cohen's kappa (2 lop, bo cac ca co UNCLEAR, n={len(dec)}): **{k2:.3f}** "
                 f"(dong thuan tho {po2:.3f})")
    L += [f"- So truong hop bat dong can trong tai: **{len(disagree)}**", "",
          "> Luu y khi viet bai: kappa cao ma so EXFIL rat nho thi kappa bi thoi phong boi lop da so. "
          "Nen bao cao kem phan bo nhan va so ca positive.", "",
          "## Phan bo nhan", "", "| Nhan | Nguoi 1 | Nguoi 2 |", "|---|---|---|"]
    ca, cb = Counter(a), Counter(b)
    for lbl in sorted(set(a) | set(b)):
        L.append(f"| {lbl} | {ca[lbl]} | {cb[lbl]} |")

    if disagree:
        L += ["", "## Cac truong hop bat dong", "",
              "| ID | Repo | File | Nguoi 1 | Nguoi 2 |", "|---|---|---|---|---|"]
        for r in disagree:
            L.append(f"| {r['review_id']} | {r['repo']} | {r['filename']} | "
                     f"{r['annotator1_label']} | {r['annotator2_label']} |")

    final = [r for r in rows if (r.get("final_label") or "").strip()]
    L += ["", "## Ground truth", ""]
    if final:
        cf = Counter(r["final_label"].strip().upper() for r in final)
        L += [f"Da co {len(final)} dong final_label. Phan bo: " +
              ", ".join(f"{k}={v}" for k, v in cf.most_common()),
              "", "Chi tiet va hash xem `data/GROUND_TRUTH_LOCK.md`."]
    else:
        L.append("Chua trong tai. Chay `src/09_build_adjudication_queue.py` roi `src/10_adjudicate.py`.")

    open("data/agreement_report.md", "w", encoding="utf-8").write("\n".join(L) + "\n")
    print("\n".join(L[:8]))
    print("\nDa ghi data/agreement_report.md (khong dung toi ground_truth.csv)")


if __name__ == "__main__":
    main()
