#!/usr/bin/env python3
"""
Cham bo bien (boundary benchmark) bang dung co may da tao ra so trong bai.

Chay tu THU MUC GOC cua repo:
    python3 score_boundary.py

Ghi ra replication/6_dataset_b_extended/results.csv
"""
import csv
import os
import sys

ROOT = os.path.abspath(os.path.dirname(__file__))
os.chdir(ROOT)
sys.path.insert(0, ROOT)

from config import DEFAULT_CONFIG                      # noqa: E402
from analyzers.yaml_analyzer import YamlAnalyzer       # noqa: E402

ROOT_X = "replication/6_dataset_b_extended"
REPORTED = ("MEDIUM", "HIGH", "CRITICAL")   # nguong bao cao mac dinh, giong run_ablation.py

A = YamlAnalyzer(DEFAULT_CONFIG)
rows = list(csv.DictReader(open(f"{ROOT_X}/ground_truth.csv", encoding="utf-8-sig")))

out = [["case_id", "label", "detected", "verdict", "max_risk", "level", "sink", "path"]]
count = {"TP": 0, "FN": 0, "FP": 0, "TN": 0}

for r in rows:
    dets = A.analyze(os.path.join(ROOT_X, r["workflow_file"])) or []
    keep = [d for d in dets if d.get("Risk_Level") in REPORTED]
    best = max(keep, key=lambda d: float(d.get("Risk_Score") or 0), default=None)
    det = best is not None
    exploit = r["label"].strip().lower() == "exploit"
    v = "TP" if (exploit and det) else "FN" if exploit else "FP" if det else "TN"
    count[v] += 1
    out.append([r["case_id"], r["label"], "yes" if det else "no", v,
                (best or {}).get("Risk_Score", 0),
                (best or {}).get("Risk_Level", ""),
                (best or {}).get("Sink", ""),
                " > ".join((best or {}).get("Path", []) or [])])

with open(f"{ROOT_X}/results.csv", "w", newline="", encoding="utf-8") as f:
    csv.writer(f).writerows(out)

w = [max(len(str(r[i])) for r in out) for i in range(6)]
for r in out:
    print("  ".join(str(r[i]).ljust(w[i]) for i in range(6)))
print()
print("TP=%(TP)d  FN=%(FN)d  FP=%(FP)d  TN=%(TN)d" % count)
print(f"Da ghi {ROOT_X}/results.csv")
