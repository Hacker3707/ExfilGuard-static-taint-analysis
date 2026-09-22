"""
Bước 9 — Dựng hàng đợi trọng tài (Bước 2 trong yêu cầu của thầy).

Chia 300 mẫu thành các nhóm và chỉ ra nhóm nào BẮT BUỘC rà thủ công theo
docs/ANNOTATION_GUIDELINE_v1.0.md.

Chạy:
    python3 src/09_build_adjudication_queue.py
    python3 src/09_build_adjudication_queue.py --spotcheck 30 --seed 20260908

Vào:  data/review_sheet.csv (tự di trú từ data/ground_truth.csv nếu chưa có)
      data/labels_a1.csv, data/labels_a2.csv
Ra:   data/adjudication_queue.csv
      data/adjudication_queue.md

Không gán nhãn, không gợi ý nhãn. Chỉ phân nhóm.
"""
import argparse
import csv
import os
import random
import shutil
import sys
from collections import Counter

SHEET = "data/review_sheet.csv"
LEGACY_SHEET = "data/ground_truth.csv"
QUEUE = "data/adjudication_queue.csv"
QUEUE_MD = "data/adjudication_queue.md"

SHEET_COLS = [
    "review_id", "repo", "filename", "stratum", "secret_names", "sink_families",
    "embedded_languages", "local_path", "snippet_file",
    "annotator1_label", "annotator1_source", "annotator1_sink", "annotator1_note",
    "annotator2_label", "annotator2_source", "annotator2_sink", "annotator2_note",
    "final_label", "adjudication_note",
]

QUEUE_COLS = [
    "review_id", "bucket", "reason", "priority", "stratum",
    "a1_label", "a2_label", "repo", "filename",
    "secret_names", "sink_families", "snippet_file", "local_path",
]


def read_csv(path):
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8-sig", errors="replace", newline="") as f:
        return list(csv.DictReader(f))


def ensure_sheet():
    """review_sheet.csv là file làm việc. Nếu chưa có, di trú từ ground_truth.csv cũ."""
    if not os.path.exists(SHEET):
        if not os.path.exists(LEGACY_SHEET):
            sys.exit(f"Khong tim thay {SHEET} lan {LEGACY_SHEET}. Chay src/05_sample_review.py truoc.")
        legacy = read_csv(LEGACY_SHEET)
        if "annotator1_label" not in (legacy[0].keys() if legacy else {}):
            sys.exit(f"{LEGACY_SHEET} khong phai review sheet (thieu cot annotator1_label).")
        shutil.copy(LEGACY_SHEET, SHEET)
        print(f"  Da di tru {LEGACY_SHEET} -> {SHEET}")
        print(f"  Tu gio {LEGACY_SHEET} se do src/11 sinh lai (ground truth that su).")

    rows = read_csv(SHEET)
    changed = False
    for c in SHEET_COLS:
        if c not in rows[0]:
            changed = True
            for r in rows:
                r.setdefault(c, "")
    if changed:
        for r in rows:
            for c in SHEET_COLS:
                r.setdefault(c, "")
        with open(SHEET, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=SHEET_COLS, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)
        print(f"  Da bo sung cot con thieu vao {SHEET}")
    return read_csv(SHEET)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--spotcheck", type=int, default=30,
                    help="so mau S1 dong thuan NO_EXFIL lay ra kiem tra (mac dinh 30)")
    ap.add_argument("--seed", type=int, default=20260908,
                    help="seed co dinh de nguoi khac tai lap duoc")
    args = ap.parse_args()

    rows = ensure_sheet()
    sheet = {r["review_id"]: r for r in rows}

    a1 = {r["review_id"]: r for r in (read_csv("data/labels_a1.csv") or [])}
    a2 = {r["review_id"]: r for r in (read_csv("data/labels_a2.csv") or [])}
    if not a1 or not a2:
        sys.exit("Thieu data/labels_a1.csv hoac labels_a2.csv.")

    def lab(d, rid):
        return (d.get(rid, {}).get("label") or "").strip().upper()

    queue = []
    auto = []
    for rid in sorted(sheet):
        l1, l2 = lab(a1, rid), lab(a2, rid)
        if not l1 or not l2:
            queue.append((rid, "B5_MISSING", f"thieu nhan: a1={l1 or '-'} a2={l2 or '-'}", 1))
        elif "EXFIL" in (l1, l2):
            queue.append((rid, "B1_EXFIL_CLAIM", f"co annotator gan EXFIL (a1={l1}, a2={l2})", 1))
        elif l1 != l2:
            queue.append((rid, "B2_DISAGREE", f"bat dong: a1={l1} vs a2={l2}", 1))
        elif "UNCLEAR" in (l1, l2):
            queue.append((rid, "B3_UNCLEAR", f"ca hai gan UNCLEAR", 2))
        else:
            auto.append(rid)

    # B4: spot-check nhom S1 dong thuan NO_EXFIL (cho de sot false negative nhat)
    s1_auto = [rid for rid in auto
               if sheet[rid]["stratum"] == "S1_secret_and_sink"
               and lab(a1, rid) == "NO_EXFIL"]
    rnd = random.Random(args.seed)
    picked = sorted(rnd.sample(s1_auto, min(args.spotcheck, len(s1_auto))))
    for rid in picked:
        queue.append((rid, "B4_SPOTCHECK",
                      f"kiem tra ngau nhien S1 dong thuan NO_EXFIL (seed={args.seed})", 3))
    picked_set = set(picked)

    queue.sort(key=lambda t: (t[3], t[0]))

    with open(QUEUE, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=QUEUE_COLS)
        w.writeheader()
        for rid, bucket, reason, prio in queue:
            r = sheet[rid]
            w.writerow({
                "review_id": rid, "bucket": bucket, "reason": reason, "priority": prio,
                "stratum": r["stratum"], "a1_label": lab(a1, rid), "a2_label": lab(a2, rid),
                "repo": r["repo"], "filename": r["filename"],
                "secret_names": r["secret_names"], "sink_families": r["sink_families"],
                "snippet_file": r["snippet_file"], "local_path": r["local_path"],
            })

    cnt = Counter(b for _, b, _, _ in queue)
    n_auto = len(auto) - len(picked_set)
    L = ["# Hang doi tro tai — Dataset A", "",
         f"- Tong mau: **{len(sheet)}**",
         f"- Can ra soat thu cong: **{len(queue)}**",
         f"- Lay nhan dong thuan tu dong: **{n_auto}**",
         f"- Seed spot-check: `{args.seed}` (tai lap duoc)", "",
         "| Nhom | So ca | Bat buoc? |", "|---|---|---|"]
    meaning = {
        "B1_EXFIL_CLAIM": "BAT BUOC — phai dien du G1/G2/G3",
        "B2_DISAGREE": "BAT BUOC — trong tai",
        "B3_UNCLEAR": "BAT BUOC — xac nhan ma U1-U5",
        "B4_SPOTCHECK": "Khuyen nghi manh — do sot false negative",
        "B5_MISSING": "BAT BUOC — thieu nhan goc",
    }
    for b in ["B1_EXFIL_CLAIM", "B2_DISAGREE", "B3_UNCLEAR", "B4_SPOTCHECK", "B5_MISSING"]:
        if cnt.get(b):
            L.append(f"| {b} | {cnt[b]} | {meaning[b]} |")

    L += ["", "## Danh sach", "", "| ID | Nhom | Tang | A1 | A2 | Repo / File |", "|---|---|---|---|---|---|"]
    for rid, bucket, _, _ in queue:
        r = sheet[rid]
        L.append(f"| {rid} | {bucket} | {r['stratum']} | {lab(a1, rid)} | {lab(a2, rid)} | "
                 f"{r['repo']} / {r['filename']} |")
    L += ["", "Tiep theo: `python3 src/10_adjudicate.py --arbiter <ten>`"]

    open(QUEUE_MD, "w", encoding="utf-8").write("\n".join(L) + "\n")

    print(f"\nDa ghi {QUEUE} ({len(queue)} ca) va {QUEUE_MD}")
    for b, c in sorted(cnt.items()):
        print(f"  {b:18s} {c}")
    print(f"  lay tu dong        {n_auto}")
    print(f"\nTiep theo: python3 src/10_adjudicate.py --arbiter <ten>")


if __name__ == "__main__":
    main()
