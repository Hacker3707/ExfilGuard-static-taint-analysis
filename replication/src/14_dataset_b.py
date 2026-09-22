"""
Bước 14 — chạy detector trên Dataset B và tính metric.

Dataset B CO positive (18 exploit / 12 benign), nên Precision / Recall / F1
tinh duoc va co nghia — khac han Dataset A.

    python3 src/14_dataset_b.py --prepare ~/path/to/ExfilGuard_Dataset_B_v2
        Doc ground_truth.csv cua Dataset B, ghi data/dsb_index.csv

    python3 src/14_dataset_b.py --run gitleaks
    python3 src/14_dataset_b.py --run zizmor
    python3 src/14_dataset_b.py --run poutine
    python3 src/14_dataset_b.py --run exfilguard --cmd "<lenh cua Ha> {file}"

    python3 src/14_dataset_b.py --metrics
        Bang P/R/F1 tong the + tach theo scenario va difficulty.

Ra: out_dsb/<tool>.csv, out_dsb/<tool>_findings.jsonl, data/metrics_dsb.md
"""
import argparse
import csv
import json
import os
import sys
from collections import Counter, defaultdict

INDEX = "data/dsb_index.csv"
OUTDIR = "out_dsb"
METRICS = "data/metrics_dsb.md"

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from importlib import import_module
    _d = import_module("13_run_detectors")
    PRESETS, run_one, count_findings = _d.PRESETS, _d.run_one, _d.count_findings
except Exception:
    sys.exit("Khong import duoc src/13_run_detectors.py — dat hai file cung thu muc src/")


def read_csv(p):
    if not os.path.exists(p):
        return []
    with open(p, encoding="utf-8-sig", errors="replace", newline="") as f:
        return list(csv.DictReader(f))


def cmd_prepare(root):
    root = os.path.expanduser(root)
    gt = os.path.join(root, "ground_truth.csv")
    if not os.path.exists(gt):
        sys.exit(f"Khong thay {gt}")
    rows = read_csv(gt)
    out = []
    missing = []
    for r in rows:
        wf = os.path.join(root, r["workflow_file"])
        if not os.path.exists(wf):
            missing.append(r["case_id"])
        out.append({
            "case_id": r["case_id"],
            "label": r["label"].strip().lower(),      # exploit / benign
            "scenario": r["scenario"],
            "difficulty": r["difficulty"],
            "pattern": r["pattern"],
            "local_path": wf,
            "script_file": (os.path.join(root, r["script_file"])
                            if r.get("script_file") else ""),
        })
    os.makedirs("data", exist_ok=True)
    with open(INDEX, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(out[0].keys()))
        w.writeheader()
        w.writerows(out)

    c = Counter(r["label"] for r in out)
    print(f"Da ghi {INDEX}: {len(out)} ca")
    print(f"  exploit={c.get('exploit',0)}  benign={c.get('benign',0)}")
    print(f"  scenario: {len(set(r['scenario'] for r in out))}")
    n_script = sum(1 for r in out if r["script_file"])
    print(f"  ca co script rieng: {n_script}")
    if missing:
        print(f"  ⚠️  thieu file workflow: {', '.join(missing)}")


def cmd_run(tool, cmd, parse, only_rules, timeout):
    rows = read_csv(INDEX)
    if not rows:
        sys.exit(f"Khong co {INDEX}. Chay --prepare truoc.")

    if cmd:
        cmd_tpl, kind = cmd, parse
    elif tool in PRESETS:
        cmd_tpl, kind = PRESETS[tool]["cmd"], PRESETS[tool]["parse"]
    else:
        sys.exit(f"Khong co preset cho '{tool}'. Dung --cmd.")

    os.makedirs(OUTDIR, exist_ok=True)
    csv_path = os.path.join(OUTDIR, f"{tool}.csv")
    log_path = os.path.join(OUTDIR, f"{tool}_findings.jsonl")

    print(f"Tool  : {tool}\nLenh  : {cmd_tpl}\nSo ca : {len(rows)}\n")
    n_alert = 0
    with open(csv_path, "w", newline="", encoding="utf-8") as fc, \
         open(log_path, "w", encoding="utf-8") as fl:
        w = csv.writer(fc)
        w.writerow(["case_id", "result"])
        for r in rows:
            text, err = run_one(tool, cmd_tpl, r["local_path"], timeout)
            n, rules = count_findings(kind, text, only_rules)
            res = "EXFIL" if n > 0 else "NO_EXFIL"
            if res == "EXFIL":
                n_alert += 1
            w.writerow([r["case_id"], res])
            fl.write(json.dumps({"case_id": r["case_id"], "label": r["label"],
                                 "findings": n, "rules": rules[:20],
                                 "error": err}) + "\n")
            print(f"  {r['case_id']}  {r['label']:8s} {r['difficulty']:7s} "
                  f"-> {res}  ({n} finding)")

    print(f"\nDa ghi {csv_path}  ({n_alert}/{len(rows)} canh bao)")
    print(f"Da ghi {log_path}")


def prf(tp, fp, fn):
    p = tp / (tp + fp) if (tp + fp) else None
    r = tp / (tp + fn) if (tp + fn) else None
    f = 2 * p * r / (p + r) if (p and r) else None
    fmt = lambda x: f"{x*100:.1f}%" if x is not None else "n/a"
    return fmt(p), fmt(r), fmt(f)


def cmd_metrics():
    rows = read_csv(INDEX)
    if not rows:
        sys.exit(f"Khong co {INDEX}.")
    idx = {r["case_id"]: r for r in rows}

    tools = sorted(f[:-4] for f in os.listdir(OUTDIR)
                   if f.endswith(".csv")) if os.path.isdir(OUTDIR) else []
    if not tools:
        sys.exit(f"Chua co ket qua nao trong {OUTDIR}/. Chay --run truoc.")

    P = sum(1 for r in rows if r["label"] == "exploit")
    N = sum(1 for r in rows if r["label"] == "benign")
    L = ["# Metrics — Dataset B (controlled benchmark)", "",
         f"- Tong ca: **{len(rows)}** ({P} exploit, {N} benign)",
         f"- Scenario: **{len(set(r['scenario'] for r in rows))}**", "",
         "> Dataset B CO positive nen P/R/F1 tinh duoc. Dataset A khong. "
         "Hai bang phai de rieng, khong gop.", "",
         "## Tong the", "",
         "| Tool | TP | FP | TN | FN | Precision | Recall | F1 |", "|---|---|---|---|---|---|---|---|"]

    per_tool = {}
    for t in tools:
        res = {r["case_id"]: r["result"] for r in read_csv(os.path.join(OUTDIR, f"{t}.csv"))}
        cells = defaultdict(int)
        detail = []
        for cid, r in idx.items():
            got = res.get(cid)
            if not got:
                continue
            exp = r["label"] == "exploit"
            hit = got == "EXFIL"
            k = "TP" if (exp and hit) else "FN" if exp else "FP" if hit else "TN"
            cells[k] += 1
            detail.append((cid, r, k))
        per_tool[t] = detail
        p, rc, f1 = prf(cells["TP"], cells["FP"], cells["FN"])
        L.append(f"| {t} | {cells['TP']} | {cells['FP']} | {cells['TN']} | "
                 f"{cells['FN']} | {p} | {rc} | {f1} |")
        print(f"  {t:16s} TP={cells['TP']} FP={cells['FP']} TN={cells['TN']} "
              f"FN={cells['FN']}  P={p} R={rc} F1={f1}")

    for key, title in [("scenario", "Recall theo scenario"),
                       ("difficulty", "Recall theo difficulty")]:
        vals = sorted(set(r[key] for r in rows))
        L += ["", f"## {title}", "", "| Tool | " + " | ".join(vals) + " |",
              "|" + "---|" * (len(vals) + 1)]
        for t, detail in per_tool.items():
            cs = []
            for v in vals:
                tp = sum(1 for _, r, k in detail if r[key] == v and k == "TP")
                fn = sum(1 for _, r, k in detail if r[key] == v and k == "FN")
                cs.append(f"{tp}/{tp+fn}" if (tp + fn) else "—")
            L.append(f"| {t} | " + " | ".join(cs) + " |")

    L += ["", "## Ca sai — doc tung ca de viet error analysis", ""]
    for t, detail in per_tool.items():
        bad = [(c, r, k) for c, r, k in detail if k in ("FP", "FN")]
        if not bad:
            L.append(f"**{t}**: khong sai ca nao.")
            continue
        L.append(f"**{t}** ({len(bad)} ca sai)", )
        L.append("")
        L.append("| case | loai | difficulty | pattern |")
        L.append("|---|---|---|---|")
        for c, r, k in sorted(bad):
            L.append(f"| {c} | {k} | {r['difficulty']} | {r['pattern']} |")
        L.append("")

    open(METRICS, "w", encoding="utf-8").write("\n".join(L) + "\n")
    print(f"\nDa ghi {METRICS}")


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--prepare", metavar="DSB_DIR")
    g.add_argument("--run", metavar="TOOL")
    g.add_argument("--metrics", action="store_true")
    ap.add_argument("--cmd")
    ap.add_argument("--parse", default="json_array",
                    choices=["json_array", "sarif_or_list", "poutine"])
    ap.add_argument("--only-rules", nargs="*", default=[])
    ap.add_argument("--timeout", type=int, default=120)
    a = ap.parse_args()

    if a.prepare:
        cmd_prepare(a.prepare)
    elif a.run:
        cmd_run(a.run, a.cmd, a.parse, a.only_rules, a.timeout)
    else:
        cmd_metrics()


if __name__ == "__main__":
    main()
