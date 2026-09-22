"""
Bước 11 — Chốt final_label + adjudication_note, kiểm tra tính hợp lệ, khóa bằng SHA256.

Đây là bước 4 trong yêu cầu của thầy: ground truth phải được khóa TRƯỚC khi chạy
ExfilGuard và baseline, và phải chứng minh được là không đổi sau đó.

Chạy:
    python3 src/11_finalize_ground_truth.py            # chot + khoa
    python3 src/11_finalize_ground_truth.py --verify   # kiem tra chua bi sua (chay truoc/sau moi thi nghiem)

Ra:
    data/review_sheet.csv        (dien final_label + adjudication_note)
    data/ground_truth.csv        (ground truth day du, ke ca UNCLEAR)
    data/ground_truth_eval.csv   (chi EXFIL/NO_EXFIL — tap dung tinh P/R/F1/FPR)
    data/GROUND_TRUTH_LOCK.md    (SHA256 + thoi diem khoa + phan bo nhan)
"""
import argparse
import csv
import datetime
import hashlib
import os
import shutil
import sys
from collections import Counter

SHEET = "data/review_sheet.csv"
QUEUE = "data/adjudication_queue.csv"
ADJ = "data/adjudication.csv"
GT = "data/ground_truth.csv"
GT_EVAL = "data/ground_truth_eval.csv"
LOCK = "data/GROUND_TRUTH_LOCK.md"
GUIDE = "docs/ANNOTATION_GUIDELINE_v1.0.md"

GT_COLS = ["review_id", "repo", "filename", "stratum", "local_path",
           "final_label", "adjudication_rule", "adjudication_basis", "adjudication_note"]

VALID = {"EXFIL", "NO_EXFIL", "UNCLEAR"}
PREFIX = {"EXFIL": "E", "NO_EXFIL": "N", "UNCLEAR": "U"}


def read_csv(p):
    if not os.path.exists(p):
        return []
    with open(p, encoding="utf-8-sig", errors="replace", newline="") as f:
        return list(csv.DictReader(f))


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def note_of(a):
    return (f"[{a['rule']}] src={a['g1_source'] or '-'} | path={a['g2_path'] or '-'} | "
            f"sink={a['g3_sink'] or '-'} | why={a['why']} | "
            f"basis=arbiter:{a['arbiter']} | rev={a['guideline_rev']}")


def verify():
    if not os.path.exists(LOCK):
        sys.exit(f"[LOI] Chua co {LOCK}. Chua khoa ground truth thi chua duoc chay detector.")
    recorded = {}
    for line in open(LOCK, encoding="utf-8"):
        if line.startswith("- `") and "` : `" in line:
            f, h = line.strip()[3:].split("` : `")
            recorded[f] = h.rstrip("`")
    ok = True
    for f, h in recorded.items():
        if not os.path.exists(f):
            print(f"[LOI] thieu file {f}")
            ok = False
        elif sha256(f) != h:
            print(f"[LOI] {f} DA BI SUA sau khi khoa")
            ok = False
        else:
            print(f"[OK] {f}")
    if ok:
        print("\n[OK] ground truth khong doi so voi thoi diem khoa.")
    else:
        print("\n[LOI] Ground truth da thay doi. Ket qua danh gia khong con hop le.")
        sys.exit(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--allow-missing", action="store_true",
                    help="cho phep chot khi hang doi con ca chua tro tai (KHONG dung cho ban cuoi)")
    args = ap.parse_args()

    if args.verify:
        verify()
        return

    rows = read_csv(SHEET)
    if not rows:
        sys.exit(f"Khong co {SHEET}. Chay src/09_build_adjudication_queue.py truoc.")
    queue = {r["review_id"]: r for r in read_csv(QUEUE)}
    adj = {r["review_id"]: r for r in read_csv(ADJ)}

    errors, warns = [], []

    # 1. Hang doi phai xong het
    missing = [rid for rid in queue if rid not in adj]
    if missing:
        msg = f"{len(missing)} ca trong hang doi chua tro tai: {', '.join(missing[:15])}"
        (warns if args.allow_missing else errors).append(msg)

    # 2. Kiem tra tung ban ghi tro tai
    for rid, a in adj.items():
        lbl = (a["final_label"] or "").strip().upper()
        if lbl not in VALID:
            errors.append(f"{rid}: nhan khong hop le '{lbl}'")
            continue
        if not a["rule"].startswith(PREFIX[lbl]):
            errors.append(f"{rid}: nhan {lbl} nhung ma ly do '{a['rule']}' khong khop")
        if lbl == "EXFIL":
            for f, name in (("g1_source", "G1 source"), ("g2_path", "G2 path"), ("g3_sink", "G3 sink")):
                if not (a[f] or "").strip() or (a[f] or "").strip() == "-":
                    errors.append(f"{rid}: gan EXFIL nhung thieu {name} — vi pham guideline muc 1")
        if lbl == "UNCLEAR" and not (a["why"] or "").strip():
            errors.append(f"{rid}: UNCLEAR nhung khong ghi thieu du lieu gi")

    if errors:
        print("KHONG CHOT DUOC. Sua cac loi sau roi chay lai:\n")
        for e in errors:
            print("  [LOI] " + e)
        print("\n  (sua bang: python3 src/10_adjudicate.py --arbiter <ten> --id <ID> --redo)")
        sys.exit(1)
    for w in warns:
        print("  [CANH BAO] " + w)

    # 3. Dien final_label + note
    n_arb = n_auto = n_blank = 0
    for r in rows:
        rid = r["review_id"]
        l1 = (r.get("annotator1_label") or "").strip().upper()
        l2 = (r.get("annotator2_label") or "").strip().upper()
        if rid in adj:
            a = adj[rid]
            r["final_label"] = a["final_label"].strip().upper()
            r["adjudication_note"] = note_of(a)
            r["_rule"] = a["rule"]
            r["_basis"] = f"arbiter:{a['arbiter']}"
            n_arb += 1
        elif l1 and l1 == l2:
            r["final_label"] = l1
            r["_rule"] = "N-AUTO" if l1 == "NO_EXFIL" else f"{PREFIX[l1]}-AUTO"
            r["_basis"] = "agreement"
            r["adjudication_note"] = (
                f"[{r['_rule']}] src=- | path=- | sink=- | "
                f"why=hai annotator dong thuan {l1}, khong thuoc dien ra soat | "
                f"basis=agreement | rev=v1.0")
            n_auto += 1
        else:
            r["final_label"] = ""
            r["adjudication_note"] = ""
            r["_rule"] = ""
            r["_basis"] = ""
            n_blank += 1

    cols = [c for c in rows[0] if not c.startswith("_")]
    if "adjudication_note" not in cols:
        cols.append("adjudication_note")
    if os.path.exists(SHEET):
        shutil.copy(SHEET, SHEET + ".bak")
    with open(SHEET, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    final_rows = [r for r in rows if r["final_label"]]
    with open(GT, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=GT_COLS)
        w.writeheader()
        for r in final_rows:
            w.writerow({
                "review_id": r["review_id"], "repo": r["repo"], "filename": r["filename"],
                "stratum": r["stratum"], "local_path": r["local_path"],
                "final_label": r["final_label"], "adjudication_rule": r["_rule"],
                "adjudication_basis": r["_basis"], "adjudication_note": r["adjudication_note"],
            })

    eval_rows = [r for r in final_rows if r["final_label"] in ("EXFIL", "NO_EXFIL")]
    with open(GT_EVAL, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["review_id", "local_path", "stratum", "label"])
        for r in eval_rows:
            w.writerow([r["review_id"], r["local_path"], r["stratum"], r["final_label"]])

    dist = Counter(r["final_label"] for r in final_rows)
    rules = Counter(r["_rule"] for r in final_rows)
    basis = Counter(r["_basis"] for r in final_rows)
    by_stratum = Counter((r["stratum"], r["final_label"]) for r in final_rows)
    strata = sorted({s for s, _ in by_stratum})
    ts = datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")

    files = [GT, GT_EVAL, GUIDE]
    L = ["# GROUND TRUTH LOCK — Dataset A", "",
         f"- Thoi diem khoa: **{ts}**",
         f"- Guideline: `ANNOTATION_GUIDELINE_v1.0` (khoa)",
         f"- Tong mau co nhan cuoi: **{len(final_rows)}** / {len(rows)}",
         f"- Tap dung danh gia (loai UNCLEAR): **{len(eval_rows)}**",
         f"- Ca do trong tai quyet dinh: **{n_arb}** | lay tu dong thuan: **{n_auto}**", ""]
    if n_blank:
        L.append(f"> CANH BAO: con {n_blank} dong chua co final_label.\n")
    L += ["## Hash (dung de chung minh ground truth doc lap voi detector)", ""]
    for f in files:
        if os.path.exists(f):
            L.append(f"- `{f}` : `{sha256(f)}`")
    L += ["", "Kiem tra lai bat ky luc nao:", "", "```bash",
          "python3 src/11_finalize_ground_truth.py --verify", "```", "",
          "Chay lenh nay **truoc va sau** moi lan chay ExfilGuard/baseline va dan ket qua vao log thi nghiem.",
          "", "## Phan bo nhan cuoi", "", "| Nhan | So luong | Ti le |", "|---|---|---|"]
    for lbl, c in dist.most_common():
        L.append(f"| {lbl} | {c} | {c/len(final_rows)*100:.1f}% |")

    L += ["", "## Phan bo theo tang", "", "| Tang | " + " | ".join(sorted(dist)) + " |",
          "|" + "---|" * (len(dist) + 1)]
    for s in strata:
        L.append(f"| {s} | " + " | ".join(str(by_stratum.get((s, l), 0)) for l in sorted(dist)) + " |")

    L += ["", "## Ma ly do", "", "| Ma | So luong |", "|---|---|"]
    for k, c in rules.most_common():
        L.append(f"| {k} | {c} |")

    L += ["", "## Nguon quyet dinh", "", "| Nguon | So luong |", "|---|---|"]
    for k, c in basis.most_common():
        L.append(f"| {k} | {c} |")

    n_exfil = dist.get("EXFIL", 0)
    L += ["", "## Ghi chu bat buoc dua vao Limitations", ""]
    if n_exfil < 10:
        L += [f"- Chi co **{n_exfil}** ca EXFIL trong {len(eval_rows)} mau danh gia. "
              "So positive nay **khong du de uoc luong Recall co y nghia thong ke** tren Dataset A.",
              "- Dataset A dung de bao cao: **FPR**, **so canh bao / 1000 workflow**, va **case study** "
              "tren cac ca positive. **Recall lay tu Dataset B** va bao cao tach bang rieng.",
              f"- Neu bao cao Recall tren {n_exfil} positive, khoang tin cay se rong toi muc vo nghia — "
              "phan bien se hoi ngay diem nay."]
    else:
        L.append(f"- {n_exfil} ca EXFIL — du de bao cao Recall kem khoang tin cay.")
    L += ["- UNCLEAR duoc bao cao rieng, loai khoi tap tinh P/R/F1/FPR (`ground_truth_eval.csv`), "
          "khong ep ve EXFIL hay NO_EXFIL."]

    open(LOCK, "w", encoding="utf-8").write("\n".join(L) + "\n")

    print(f"\nDa ghi:")
    print(f"  {SHEET}   (ban sao luu {SHEET}.bak)")
    print(f"  {GT}          {len(final_rows)} dong")
    print(f"  {GT_EVAL}     {len(eval_rows)} dong (loai UNCLEAR)")
    print(f"  {LOCK}")
    print(f"\nPhan bo nhan cuoi: {dict(dist)}")
    print(f"SHA256 ground_truth.csv: {sha256(GT)}")
    print("\nGIO MOI duoc chay ExfilGuard va baseline.")


if __name__ == "__main__":
    main()
