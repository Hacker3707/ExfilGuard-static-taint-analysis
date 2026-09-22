"""
Bước 13 — chạy detector trên ground truth ĐÃ KHÓA, xuất CSV cho --merge.

    python3 src/13_run_detectors.py --tool gitleaks
    python3 src/13_run_detectors.py --tool zizmor
    python3 src/13_run_detectors.py --tool poutine
    python3 src/13_run_detectors.py --tool exfilguard --cmd "python3 ../ExfilGuard/cli.py --json {file}"

Chạy trên CẢ 300 mẫu (265 eval + 35 UNCLEAR). Script 12 tách hai nhóm khi
tính metric, nên không cần chạy riêng.

Ra:
    out/<tool>.csv           sample_id,result   (EXFIL / NO_EXFIL)  -> dua vao --merge
    out/<tool>_findings.jsonl mot dong moi mau: so finding + noi dung tho

⛔ Chạy `python3 src/11_finalize_ground_truth.py --verify` TRƯỚC và SAU mỗi lần
chạy script này, và lưu output. Đó là bằng chứng ground truth không đổi.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import csv

GT = "data/ground_truth.csv"
OUTDIR = "out"

# Moi preset: lenh chay, cach dem finding, va GHI CHU ve quy tac quy doi.
#
# ⚠️ Quy doi "co finding -> EXFIL" la mot QUYET DINH THIET KE, khong phai su that
# hien nhien. Ba baseline khong giai cung bai toan voi ExfilGuard (nhan xet muc 8
# cua thay), nen quy tac quy doi phai duoc ghi ro trong bai:
#   - gitleaks tim SECRET LITERAL. Mot finding = "co secret hardcode", KHONG phai
#     "co exfiltration". Quy doi thang se cho FPR rat cao va do la ket qua dung —
#     no do coverage gap, khong phai do gitleaks kem.
#   - zizmor/poutine tim RUI RO CAU HINH workflow. Nhieu rule cua chung khong lien
#     quan gi toi exfiltration (vd pin action, permissions rong).
#   - Vi vay script ho tro --only-rules de loc ve nhung rule THUC SU noi ve
#     secret roi ra ngoai, va bai nen bao cao CA HAI: quy doi tho va quy doi loc.
PRESETS = {
    "gitleaks": {
        "cmd": "gitleaks detect --no-git --source {file} --report-format json "
               "--report-path {out} --exit-code 0 --redact",
        "reads": "file",
        "parse": "json_array",
        "note": "moi finding = mot secret literal phat hien duoc",
    },
    "zizmor": {
        "cmd": "zizmor --format json --no-progress {file}",
        "reads": "stdout",
        "parse": "sarif_or_list",
        "note": "moi finding = mot canh bao cau hinh workflow",
    },
    "poutine": {
        "cmd": "poutine analyze_local {repo} --format json",
        "reads": "stdout",
        "parse": "poutine",
        "note": "poutine doc CA REPO, nen moi file duoc dung tam thanh mot repo gia",
    },
}


def read_csv(p):
    if not os.path.exists(p):
        return []
    with open(p, encoding="utf-8-sig", errors="replace", newline="") as f:
        return list(csv.DictReader(f))


def count_findings(kind, text, only_rules):
    """Tra ve (so_finding, danh_sach_rule_id). Tolerant: output rac -> 0."""
    if not text or not text.strip():
        return 0, []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Vai tool in log lan vao stdout; lay khoi JSON dau tien
        s = text.find("[") if "[" in text else text.find("{")
        if s < 0:
            return 0, []
        try:
            data = json.loads(text[s:])
        except json.JSONDecodeError:
            return 0, []

    items = []
    if kind == "json_array":
        items = data if isinstance(data, list) else data.get("findings", [])
    elif kind == "sarif_or_list":
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            runs = data.get("runs")
            if runs:
                for run in runs:
                    items.extend(run.get("results", []))
            else:
                items = data.get("findings", []) or data.get("results", [])
    elif kind == "poutine":
        if isinstance(data, dict):
            items = data.get("findings", []) or data.get("results", [])
        elif isinstance(data, list):
            items = data

    rules = []
    for it in items:
        if not isinstance(it, dict):
            rules.append("?")
            continue
        rid = (it.get("RuleID") or it.get("ruleId") or it.get("rule_id")
               or it.get("ident") or it.get("rule") or it.get("Description") or "?")
        rules.append(str(rid))

    if only_rules:
        keep = [r for r in rules if any(k.lower() in r.lower() for k in only_rules)]
        return len(keep), keep
    return len(rules), rules


def run_one(preset, cmd_tpl, path, timeout):
    """Chay tool tren mot file. Tra ve (stdout_text, loi_neu_co)."""
    tmpdir = None
    out_file = None
    try:
        fmt = {"file": path}
        if "{repo}" in cmd_tpl:
            tmpdir = tempfile.mkdtemp(prefix="det-repo-")
            wf = os.path.join(tmpdir, ".github", "workflows")
            os.makedirs(wf, exist_ok=True)
            shutil.copy(path, os.path.join(wf, os.path.basename(path)))
            fmt["repo"] = tmpdir
        if "{out}" in cmd_tpl:
            fd, out_file = tempfile.mkstemp(suffix=".json")
            os.close(fd)
            fmt["out"] = out_file

        cmd = cmd_tpl.format(**fmt)
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=timeout)
        if out_file:
            with open(out_file, encoding="utf-8", errors="replace") as f:
                return f.read(), None
        return p.stdout, (p.stderr.strip()[:200] if p.returncode not in (0, 1) else None)
    except subprocess.TimeoutExpired:
        return "", f"timeout sau {timeout}s"
    except Exception as e:
        return "", str(e)[:200]
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)
        if out_file and os.path.exists(out_file):
            os.remove(out_file)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tool", required=True,
                    help="gitleaks | zizmor | poutine | <ten tuy y voi --cmd>")
    ap.add_argument("--cmd", help="Lenh tuy chinh. Dung {file} cho duong dan workflow, "
                                  "{repo} neu tool doc ca thu muc, {out} neu tool ghi ra file.")
    ap.add_argument("--parse", default="json_array",
                    choices=["json_array", "sarif_or_list", "poutine"],
                    help="Cach doc output khi dung --cmd")
    ap.add_argument("--only-rules", nargs="*", default=[],
                    help="Chi dem finding co rule id chua mot trong cac chuoi nay")
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--limit", type=int, help="Chay thu N mau dau")
    args = ap.parse_args()

    gt = read_csv(GT)
    if not gt:
        sys.exit(f"Khong co {GT}. Chay src/11_finalize_ground_truth.py truoc.")

    if args.cmd:
        cmd_tpl, parse, note = args.cmd, args.parse, "lenh tuy chinh"
    elif args.tool in PRESETS:
        p = PRESETS[args.tool]
        cmd_tpl, parse, note = p["cmd"], p["parse"], p["note"]
    else:
        sys.exit(f"Khong co preset cho '{args.tool}'. Dung --cmd de tu khai bao lenh.")

    rows = gt[:args.limit] if args.limit else gt
    os.makedirs(OUTDIR, exist_ok=True)
    csv_path = os.path.join(OUTDIR, f"{args.tool}.csv")
    log_path = os.path.join(OUTDIR, f"{args.tool}_findings.jsonl")

    print(f"Tool     : {args.tool}")
    print(f"Lenh     : {cmd_tpl}")
    print(f"Quy doi  : {note}")
    if args.only_rules:
        print(f"Loc rule : {', '.join(args.only_rules)}")
    print(f"So mau   : {len(rows)}\n")

    n_exfil = n_err = 0
    with open(csv_path, "w", newline="", encoding="utf-8") as fc, \
         open(log_path, "w", encoding="utf-8") as fl:
        w = csv.writer(fc)
        w.writerow(["sample_id", "result"])
        for i, r in enumerate(rows, 1):
            rid, path = r["review_id"], r["local_path"]
            if not os.path.exists(path):
                w.writerow([rid, "NO_EXFIL"])
                fl.write(json.dumps({"sample_id": rid, "error": "file khong ton tai"}) + "\n")
                n_err += 1
                continue

            text, err = run_one(args.tool, cmd_tpl, path, args.timeout)
            n, rules = count_findings(parse, text, args.only_rules)
            result = "EXFIL" if n > 0 else "NO_EXFIL"
            if result == "EXFIL":
                n_exfil += 1
            if err:
                n_err += 1

            w.writerow([rid, result])
            fl.write(json.dumps({"sample_id": rid, "findings": n,
                                 "rules": rules[:20], "error": err}) + "\n")

            if i % 25 == 0 or i == len(rows):
                print(f"  {i}/{len(rows)}  canh bao: {n_exfil}  loi: {n_err}")

    print(f"\nDa ghi {csv_path}  ({n_exfil}/{len(rows)} canh bao)")
    print(f"Da ghi {log_path}")
    if n_err:
        print(f"⚠️  {n_err} mau bao loi — doc {log_path} truoc khi dung ket qua")
    print(f"\nTiep theo: python3 src/12_build_master_results.py --merge {args.tool}={csv_path}")


if __name__ == "__main__":
    main()
