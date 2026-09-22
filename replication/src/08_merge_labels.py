"""
Bước 8 — Gộp nhãn của hai người vào data/review_sheet.csv.

ĐÃ SỬA (v2):
  - đọc được file có BOM (Excel trên Windows ghi ra BOM, bản cũ hỏng cột review_id)
  - tự di trú data/ground_truth.csv (dang review sheet) sang data/review_sheet.csv
  - bo sung cot adjudication_note neu thieu
  - KHONG dung toi final_label va adjudication_note da co

Chay:  python3 src/08_merge_labels.py
"""
import csv
import os
import shutil
import sys

SHEET = "data/review_sheet.csv"
LEGACY = "data/ground_truth.csv"
EXTRA_COLS = ["final_label", "adjudication_note"]


def read_csv(path):
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8-sig", errors="replace", newline="") as f:
        return list(csv.DictReader(f))


def load(path):
    rows = read_csv(path)
    if rows is None:
        print(f"  (chua co {path})")
        return {}
    d = {r["review_id"]: r for r in rows}
    print(f"  {path}: {len(d)} nhan")
    return d


def main():
    if not os.path.exists(SHEET):
        if os.path.exists(LEGACY) and "annotator1_label" in (read_csv(LEGACY) or [{}])[0]:
            shutil.copy(LEGACY, SHEET)
            print(f"  Da di tru {LEGACY} -> {SHEET}")
        else:
            sys.exit(f"Khong tim thay {SHEET}. Chay src/05_sample_review.py truoc.")

    a1 = load("data/labels_a1.csv")
    a2 = load("data/labels_a2.csv")
    if not a1 and not a2:
        sys.exit("Chua co file nhan nao. Chay src/07_label.py truoc.")

    rows = read_csv(SHEET)
    cols = list(rows[0].keys())
    for c in EXTRA_COLS:
        if c not in cols:
            cols.append(c)
    for r in rows:
        for c in cols:
            r.setdefault(c, "")

    shutil.copy(SHEET, SHEET + ".bak")

    n1 = n2 = 0
    for r in rows:
        rid = r["review_id"]
        if rid in a1:
            r["annotator1_label"] = a1[rid].get("label", "")
            r["annotator1_source"] = a1[rid].get("source", "")
            r["annotator1_sink"] = a1[rid].get("sink", "")
            r["annotator1_note"] = a1[rid].get("note", "")
            n1 += 1
        if rid in a2:
            r["annotator2_label"] = a2[rid].get("label", "")
            r["annotator2_source"] = a2[rid].get("source", "")
            r["annotator2_sink"] = a2[rid].get("sink", "")
            r["annotator2_note"] = a2[rid].get("note", "")
            n2 += 1

    with open(SHEET, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    both = sum(1 for r in rows
               if r["annotator1_label"].strip() and r["annotator2_label"].strip())
    print(f"\nDa ghi {SHEET} (ban sao luu: {SHEET}.bak)")
    print(f"  nguoi 1: {n1} | nguoi 2: {n2} | ca hai deu co nhan: {both}")
    print("\nTiep theo: python3 src/06_agreement.py")


if __name__ == "__main__":
    main()
