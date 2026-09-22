"""
Bước 12 — master_results.csv (mục 15 trong nhận xét của thầy).

Một file duy nhất. Mọi Table, Figure, Abstract, Discussion, Conclusion đều lấy
số từ đây. Không ai gõ số vào Word.

    python3 src/12_build_master_results.py --init
        Tao master_results.csv tu ground_truth.csv + adjudication.csv.
        Cot ground truth da dien; 4 cot ket qua tool de trong.

    python3 src/12_build_master_results.py --merge exfilguard=out/eg.csv zizmor=out/zz.csv
        Do ket qua tool vao. Moi file la CSV 2 cot: sample_id,result
        (result = EXFIL hoac NO_EXFIL). Chay lai duoc nhieu lan.

    python3 src/12_build_master_results.py --metrics
        In bang confusion + FPR + so canh bao/1000 workflow cho tung tool,
        va ghi data/metrics.md. Bao cao dung cho truong hop 0 positive.

Chỉ dùng thư viện chuẩn Python 3.
"""
import argparse
import csv
import os
import sys
from collections import Counter

GT = "data/ground_truth.csv"
ADJ = "data/adjudication.csv"
EVAL = "data/ground_truth_eval.csv"
MASTER = "data/master_results.csv"
METRICS = "data/metrics.md"

TOOLS = ["exfilguard", "zizmor", "poutine", "gitleaks"]

COLS = (["sample_id", "final_label", "source", "sink", "path_type"]
        + [f"{t}_result" for t in TOOLS] + ["error_type"])

# Ma ly do -> loai duong di, de bang error analysis nhom duoc theo hinh dang
PATH_TYPE = {
    "E1": "payload-to-author-endpoint",
    "E2": "github-env-crossing",
    "E3": "encoded-then-sent",
    "E4": "third-party-endpoint",
    "N1": "no-source",
    "N2": "local-only",
    "N3": "excluded-sink",
    "N4": "auth-to-owner",
    "N5": "identifier-only",
    "N6": "co-occurrence-only",
    "N-AUTO": "agreement-no-review",
    "U1": "unresolved-repo-script",
    "U2": "unresolved-action",
    "U3": "unresolved-runtime-value",
    "U4": "unresolved-truncated",
    "U5": "unresolved-endpoint-ownership",
}


def read_csv(p):
    if not os.path.exists(p):
        return []
    with open(p, encoding="utf-8-sig", errors="replace", newline="") as f:
        return list(csv.DictReader(f))


def write_master(rows):
    with open(MASTER, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def cmd_init():
    gt = read_csv(GT)
    if not gt:
        sys.exit(f"Khong co {GT}. Chay src/11_finalize_ground_truth.py truoc.")
    adj = {r["review_id"]: r for r in read_csv(ADJ)}

    rows = []
    for r in gt:
        rid = r["review_id"]
        a = adj.get(rid, {})
        rule = r.get("adjudication_rule", "")
        row = {
            "sample_id": rid,
            "final_label": r["final_label"],
            "source": a.get("g1_source", "-"),
            "sink": a.get("g3_sink", "-"),
            "path_type": PATH_TYPE.get(rule, rule or "-"),
            "error_type": "",
        }
        for t in TOOLS:
            row[f"{t}_result"] = ""
        rows.append(row)

    write_master(rows)
    dist = Counter(r["final_label"] for r in rows)
    print(f"Da ghi {MASTER}: {len(rows)} dong")
    print(f"  phan bo nhan: {dict(dist)}")
    print(f"  cot ket qua tool de trong — do vao bang --merge sau khi chay tool")


def cmd_merge(pairs):
    rows = read_csv(MASTER)
    if not rows:
        sys.exit(f"Khong co {MASTER}. Chay --init truoc.")
    index = {r["sample_id"]: r for r in rows}

    for pair in pairs:
        if "=" not in pair:
            sys.exit(f"Sai dinh dang: {pair}. Dung: <tool>=<duong_dan.csv>")
        tool, path = pair.split("=", 1)
        if tool not in TOOLS:
            sys.exit(f"Ten tool khong hop le: {tool}. Chon trong: {', '.join(TOOLS)}")
        data = read_csv(path)
        if not data:
            sys.exit(f"Khong doc duoc {path}")
        key = "sample_id" if "sample_id" in data[0] else "review_id"
        n = miss = 0
        for d in data:
            rid = d[key].strip()
            val = (d.get("result") or d.get("label") or "").strip().upper()
            if val not in ("EXFIL", "NO_EXFIL"):
                sys.exit(f"{path}: gia tri khong hop le '{val}' o {rid} "
                         f"(chi chap nhan EXFIL hoac NO_EXFIL)")
            if rid in index:
                index[rid][f"{tool}_result"] = val
                n += 1
            else:
                miss += 1
        print(f"  {tool}: do {n} dong" + (f", {miss} sample_id khong khop" if miss else ""))

    # error_type: chi tinh tren tap eval (bo UNCLEAR), theo ExfilGuard
    for r in rows:
        gtl, eg = r["final_label"], r["exfilguard_result"]
        if gtl == "UNCLEAR":
            r["error_type"] = "excluded-unclear"
        elif not eg:
            r["error_type"] = ""
        elif gtl == "EXFIL" and eg == "EXFIL":
            r["error_type"] = "TP"
        elif gtl == "NO_EXFIL" and eg == "NO_EXFIL":
            r["error_type"] = "TN"
        elif gtl == "NO_EXFIL" and eg == "EXFIL":
            r["error_type"] = "FP"
        else:
            r["error_type"] = "FN"

    write_master(rows)
    print(f"Da cap nhat {MASTER}")


def cmd_metrics():
    rows = read_csv(MASTER)
    if not rows:
        sys.exit(f"Khong co {MASTER}. Chay --init truoc.")

    ev = [r for r in rows if r["final_label"] in ("EXFIL", "NO_EXFIL")]
    unclear = [r for r in rows if r["final_label"] == "UNCLEAR"]
    P = sum(1 for r in ev if r["final_label"] == "EXFIL")
    N = sum(1 for r in ev if r["final_label"] == "NO_EXFIL")

    L = ["# Metrics — Dataset A", "",
         f"- Tong mau: **{len(rows)}**",
         f"- Tap danh gia (bo UNCLEAR): **{len(ev)}**",
         f"- Positive (EXFIL): **{P}** | Negative (NO_EXFIL): **{N}**",
         f"- UNCLEAR bao cao rieng: **{len(unclear)}**", ""]

    if P == 0:
        L += ["> **Khong co positive trong Dataset A.** Recall, Precision va F1 "
              "khong dinh nghia duoc tren tap nay (mau so bang 0). Bang duoi bao cao "
              "FPR va so canh bao / 1000 workflow — hai dai luong tinh duoc va co y "
              "nghia. Recall lay tu Dataset B, bao cao o bang rieng.", ""]

    L += ["## Ket qua tung cong cu", "",
          "| Tool | TP | FP | TN | FN | FPR | Canh bao/1000 wf | Precision | Recall | F1 |",
          "|---|---|---|---|---|---|---|---|---|---|"]

    print(f"\nTap danh gia: {len(ev)} mau ({P} EXFIL, {N} NO_EXFIL), "
          f"{len(unclear)} UNCLEAR bao cao rieng\n")

    for t in TOOLS:
        col = f"{t}_result"
        got = [r for r in ev if r[col]]
        if not got:
            continue
        tp = sum(1 for r in got if r["final_label"] == "EXFIL" and r[col] == "EXFIL")
        fp = sum(1 for r in got if r["final_label"] == "NO_EXFIL" and r[col] == "EXFIL")
        tn = sum(1 for r in got if r["final_label"] == "NO_EXFIL" and r[col] == "NO_EXFIL")
        fn = sum(1 for r in got if r["final_label"] == "EXFIL" and r[col] == "NO_EXFIL")

        fpr = f"{fp/(fp+tn)*100:.1f}%" if (fp + tn) else "n/a"
        per1k = f"{(tp+fp)/len(got)*1000:.1f}" if got else "n/a"
        prec = ("n/a (0 positive trong ground truth)" if P == 0
                else (f"{tp/(tp+fp)*100:.1f}%" if (tp + fp) else "n/a (khong co canh bao)"))
        rec = f"{tp/(tp+fn)*100:.1f}%" if (tp + fn) else "n/a (khong co positive)"
        f1 = "n/a"
        if (tp + fp) and (tp + fn) and tp:
            p_, r_ = tp/(tp+fp), tp/(tp+fn)
            f1 = f"{2*p_*r_/(p_+r_)*100:.1f}%"

        L.append(f"| {t} | {tp} | {fp} | {tn} | {fn} | {fpr} | {per1k} | {prec} | {rec} | {f1} |")
        print(f"  {t:12s} TP={tp} FP={fp} TN={tn} FN={fn}  FPR={fpr}  canh bao/1000={per1k}")

    # Canh bao roi vao nhom UNCLEAR — phai bao cao rieng, khong duoc bo qua
    L += ["", "## Canh bao roi vao nhom UNCLEAR", "",
          "UNCLEAR bi loai khoi tap tinh metric, nen canh bao o day khong vao FPR. "
          "Bao cao rieng de khong bien mat khoi bai.", "",
          "| Tool | So canh bao tren " + str(len(unclear)) + " ca UNCLEAR |", "|---|---|"]
    for t in TOOLS:
        col = f"{t}_result"
        n = sum(1 for r in unclear if r[col] == "EXFIL")
        if any(r[col] for r in unclear):
            L.append(f"| {t} | {n} |")

    L += ["", "## Phan bo loai duong di", "", "| path_type | So ca |", "|---|---|"]
    for k, v in Counter(r["path_type"] for r in rows).most_common():
        L.append(f"| {k} | {v} |")

    open(METRICS, "w", encoding="utf-8").write("\n".join(L) + "\n")
    print(f"\nDa ghi {METRICS}")


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--init", action="store_true")
    g.add_argument("--merge", nargs="+", metavar="TOOL=FILE.csv")
    g.add_argument("--metrics", action="store_true")
    args = ap.parse_args()

    if args.init:
        cmd_init()
    elif args.merge:
        cmd_merge(args.merge)
    else:
        cmd_metrics()


if __name__ == "__main__":
    main()
