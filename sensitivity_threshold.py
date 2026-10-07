#!/usr/bin/env python3
"""
Phan tich do nhay theo nguong muc rui ro (R1.5).

Chay tu THU MUC GOC cua repo:
    python3 sensitivity_threshold.py

Dung dung co may da tao ra so trong bai: YamlAnalyzer(DEFAULT_CONFIG),
giong main.py va run_ablation.py. Khong sua gi trong repo.

Ket qua ghi ra:
    replication/6_dataset_b_extended/threshold_sensitivity.md
    replication/6_dataset_b_extended/threshold_sensitivity.csv
"""
import csv
import os
import sys

ROOT = os.path.abspath(os.path.dirname(__file__))
os.chdir(ROOT)
sys.path.insert(0, ROOT)

from config import DEFAULT_CONFIG                      # noqa: E402
from analyzers.yaml_analyzer import YamlAnalyzer       # noqa: E402

GT_A = "replication/1_ground_truth/ground_truth.csv"
DIR_A = "replication/4_dataset_a_sample"
GT_B = "replication/3_dataset_b/ground_truth.csv"
DIR_B = "replication/3_dataset_b"
GT_X = "replication/6_dataset_b_extended/ground_truth.csv"
DIR_X = "replication/6_dataset_b_extended"

OUT_MD = "replication/6_dataset_b_extended/threshold_sensitivity.md"
OUT_CSV = "replication/6_dataset_b_extended/threshold_sensitivity.csv"

THRESHOLDS = [("LOW", 2.0), ("MEDIUM", 4.0), ("HIGH", 6.0), ("CRITICAL", 8.0)]

ANALYZER = YamlAnalyzer(DEFAULT_CONFIG)


def scan(path):
    """Diem cao nhat va danh sach muc cua mot workflow."""
    try:
        dets = ANALYZER.analyze(path) or []
    except Exception as e:                              # noqa: BLE001
        return 0.0, [f"ERROR:{type(e).__name__}"]
    scores, levels = [], []
    for d in dets:
        lv = d.get("Risk_Level")
        sc = d.get("Risk_Score")
        if lv:
            levels.append(lv)
        if sc is not None:
            try:
                scores.append(float(sc))
            except (TypeError, ValueError):
                pass
    return (max(scores) if scores else 0.0), levels


def read_csv(p):
    with open(p, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def collect_a():
    idx = {}
    for fn in os.listdir(DIR_A):
        if fn.endswith((".yml", ".yaml")):
            idx[fn.split("__", 1)[0]] = os.path.join(DIR_A, fn)
    rows, miss = [], []
    for r in read_csv(GT_A):
        rid = r["review_id"].strip()
        p = idx.get(rid)
        if not p:
            miss.append(rid)
            continue
        rows.append({"id": rid, "label": r["final_label"].strip().upper(), "path": p})
    return rows, miss


def collect_bx(gt, root):
    rows, miss = [], []
    for r in read_csv(gt):
        p = os.path.join(root, r["workflow_file"])
        if not os.path.exists(p):
            miss.append(r["case_id"])
            continue
        rows.append({"id": r["case_id"].strip(),
                     "label": r["label"].strip().lower(),
                     "path": p})
    return rows, miss


def run(rows, title):
    print(f"\n{title}: {len(rows)} file", flush=True)
    seen = {}
    for i, r in enumerate(rows, 1):
        r["score"], lv = scan(r["path"])
        for x in lv:
            seen[x] = seen.get(x, 0) + 1
        if i % 50 == 0 or i == len(rows):
            print(f"  {i}/{len(rows)}", flush=True)
    return seen


def main():
    a_rows, a_miss = collect_a()
    b_rows, b_miss = collect_bx(GT_B, DIR_B)
    x_rows, x_miss = collect_bx(GT_X, DIR_X)
    for nm, rws, ms in (("Dataset A", a_rows, a_miss), ("Dataset B", b_rows, b_miss),
                        ("Bo mo rong", x_rows, x_miss)):
        print(f"{nm:11s}: {len(rws)} file" + (f"  (thieu {len(ms)})" if ms else ""))

    lv_a = run(a_rows, "Dataset A")
    lv_b = run(b_rows, "Dataset B")
    lv_x = run(x_rows, "Bo mo rong")

    print("\nPhan bo muc rui ro:")
    for nm, d in (("Dataset A", lv_a), ("Dataset B", lv_b), ("Bo mo rong", lv_x)):
        print(f"  {nm:11s} {d if d else '{}'}")

    lines = ["# Threshold sensitivity for ExfilGuard", "",
             "Alerts recounted at each minimum risk level, using the same analyser "
             "configuration as the published results. The published numbers use MEDIUM.", ""]
    recs = []

    evalA = [r for r in a_rows if r["label"] in ("NO_EXFIL", "EXFIL")]
    lines += ["## Dataset A", "",
              f"Total {len(a_rows)} workflows, of which {len(evalA)} are adjudicated and "
              f"{len(a_rows) - len(evalA)} remain unclear. No positive instance, so only "
              "the false positive rate is defined.", "",
              "| Minimum risk level | Alerts | False positive rate | Alerts per 1000 |",
              "|---|---|---|---|"]
    for name, t in THRESHOLDS:
        n = sum(1 for r in evalA if r["score"] >= t)
        fpr = 100.0 * n / len(evalA) if evalA else 0.0
        lines.append(f"| {name} | {n} | {fpr:.1f} % | {1000.0 * n / len(evalA):.1f} |")
        recs.append(["dataset_a", name, t, n, len(evalA), f"{fpr:.1f}", "", "", "", ""])

    for title, rows, key in (("Dataset B", b_rows, "dataset_b"),
                             ("Extended boundary benchmark", x_rows, "extended")):
        pos = sum(1 for r in rows if r["label"] == "exploit")
        neg = len(rows) - pos
        lines += ["", f"## {title}", "",
                  f"{len(rows)} cases, {pos} exploit and {neg} benign.", "",
                  "| Minimum risk level | TP | FN | FP | TN | Recall | False positive rate |",
                  "|---|---|---|---|---|---|---|"]
        for name, t in THRESHOLDS:
            tp = fn = fp = tn = 0
            for r in rows:
                d, e = r["score"] >= t, r["label"] == "exploit"
                if e and d: tp += 1
                elif e: fn += 1
                elif d: fp += 1
                else: tn += 1
            rec = 100.0 * tp / pos if pos else 0.0
            fpr = 100.0 * fp / neg if neg else 0.0
            lines.append(f"| {name} | {tp} | {fn} | {fp} | {tn} | {rec:.1f} % | {fpr:.1f} % |")
            recs.append([key, name, t, "", "", f"{fpr:.1f}", tp, fn, fp, tn])

    with open(OUT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["dataset", "min_risk_level", "score_cutoff", "alerts", "n_eval",
                    "fpr_percent", "tp", "fn", "fp", "tn"])
        w.writerows(recs)

    print("\n" + "\n".join(lines))
    print(f"\nDa ghi {OUT_MD}\nDa ghi {OUT_CSV}")


if __name__ == "__main__":
    main()