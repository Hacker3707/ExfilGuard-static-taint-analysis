"""
Bước 5 — Lấy mẫu phân tầng để gán nhãn tay.

Đây là phần tạo ra ground truth cho Dataset A. Không có bước này thì không tính
được Precision và Recall thật ở task #16, vì không có nhãn đúng để đối chiếu.

Cách làm: lấy toàn bộ (hoặc phần lớn) tầng S1 vì đó là nơi có khả năng tồn tại
đường source-to-sink thật, cộng thêm mẫu ngẫu nhiên từ ba tầng còn lại để đo được
cả false negative lẫn false positive. Hạt giống ngẫu nhiên cố định trong config.py
nên mẫu tái lập được y hệt.

Chạy:  python src/05_sample_review.py
Ra:    data/review_sheet.csv     (bảng để hai người gán nhãn độc lập)
       data/review_snippets/     (đoạn code liên quan của từng workflow, để đọc nhanh)
"""
import csv
import json
import os
import random
import re
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(__file__))
import config as C

FULL = "data/dataset_a_full.jsonl"
OUTCSV = "data/review_sheet.csv"
SNIPDIR = "data/review_snippets"


def snippet(path, secret_names, max_lines=60):
    """Trích các dòng liên quan để người gán nhãn không phải mở cả file dài."""
    try:
        lines = open(path, encoding="utf-8", errors="replace").read().split("\n")
    except OSError:
        return ""
    keys = ["secrets.", "secrets:", "env:", "run:", "curl", "wget", "nc ", "dig",
            "requests.", "fetch(", "axios", "Invoke-Web", "scp", "rsync", "$GITHUB_ENV"]
    keys += list(secret_names or [])
    keep = set()
    for i, l in enumerate(lines):
        if any(k in l for k in keys):
            for j in range(max(0, i - 2), min(len(lines), i + 6)):
                keep.add(j)
    idx = sorted(keep)[:max_lines]
    return "\n".join(f"{i+1:4d}| {lines[i]}" for i in idx)


def main():
    rows = [json.loads(l) for l in open(FULL, encoding="utf-8")]
    by = defaultdict(list)
    for r in rows:
        by[r["stratum"]].append(r)

    rnd = random.Random(C.RANDOM_SEED)
    sample = []
    for stratum, k in C.REVIEW_STRATA.items():
        pool = by.get(stratum, [])
        rnd.shuffle(pool)
        take = pool[:k]
        sample.extend(take)
        print(f"{stratum:22s} có {len(pool):6d} -> lấy {len(take)}")

    rnd.shuffle(sample)  # trộn để người gán nhãn không đoán được tầng

    os.makedirs(SNIPDIR, exist_ok=True)
    with open(OUTCSV, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "review_id", "repo", "filename", "stratum", "secret_names",
            "sink_families", "embedded_languages", "local_path", "snippet_file",
            # --- các cột người gán nhãn điền, để trống khi sinh ra
            "annotator1_label", "annotator1_source", "annotator1_sink", "annotator1_note",
            "annotator2_label", "annotator2_source", "annotator2_sink", "annotator2_note",
            "final_label", "adjudication_note",
        ])
        for i, r in enumerate(sample, 1):
            rid = f"A{i:04d}"
            snip = os.path.join(SNIPDIR, rid + ".txt")
            with open(snip, "w", encoding="utf-8") as sf:
                sf.write(f"# {r['repo']} / {r['filename']}\n")
                sf.write(f"# tầng: {r['stratum']}  secret: {r['secret_names']}  sink: {r['sink_families']}\n\n")
                sf.write(snippet(r["local_path"], r["secret_names"]))
            w.writerow([
                rid, r["repo"], r["filename"], r["stratum"],
                "|".join(r["secret_names"]), "|".join(r["sink_families"]),
                "|".join(r["embedded_languages"]), r["local_path"], snip,
                "", "", "", "", "", "", "", "", "", "",
            ])

    print(f"\nĐã sinh {len(sample)} mẫu -> {OUTCSV}")
    print("Đoạn trích đọc nhanh nằm trong", SNIPDIR)
    print("\nNhãn hợp lệ: EXFIL / NO_EXFIL / UNCLEAR  (xem docs/ANNOTATION_GUIDE.md)")


if __name__ == "__main__":
    main()
