"""
Bước 10 — Công cụ trọng tài: điền final_label + bằng chứng G1/G2/G3.

Áp dụng docs/ANNOTATION_GUIDELINE_v1.0.md. Công cụ KHÔNG gợi ý nhãn và KHÔNG
đọc output của ExfilGuard hay baseline nào.

Chạy:
    python3 src/10_adjudicate.py --arbiter nhi
    python3 src/10_adjudicate.py --arbiter nhi --bucket B1_EXFIL_CLAIM
    python3 src/10_adjudicate.py --arbiter nhi --id A0299
    python3 src/10_adjudicate.py --arbiter nhi --redo        # lam lai ca da xong

Ghi ngay sau mỗi ca vào data/adjudication.csv nên tắt giữa chừng không mất gì.

Phím ở màn hình nhãn:
    e EXFIL   n NO_EXFIL   u UNCLEAR
    p  bang bang chung (dong co secret / lenh mang)
    f  xem toan bo file goc
    g  tom tat guideline
    b  quay lai ca truoc      s  bo qua      q  thoat
"""
import argparse
import csv
import os
import re
import sys

QUEUE = "data/adjudication_queue.csv"
SHEET = "data/review_sheet.csv"
OUT = "data/adjudication.csv"

FIELDS = ["review_id", "bucket", "final_label", "rule",
          "g1_source", "g2_path", "g3_sink", "why", "arbiter", "guideline_rev"]

REV = "v1.0"

RULES = {
    "EXFIL": {
        "E1": "secret nam trong payload gui toi endpoint do tac gia chon",
        "E2": "secret di qua $GITHUB_ENV/$GITHUB_OUTPUT roi ra mang o step sau",
        "E3": "secret duoc encode/nen roi moi gui ra ngoai",
        "E4": "secret gui toi ben thu ba khong so huu secret do",
    },
    "NO_EXFIL": {
        "N1": "khong co source (G1 fail)",
        "N2": "khong co thao tac mang; chi ghi file/log tren runner",
        "N3": "sink thuoc ha tang co dinh bi loai tru (muc 2.2)",
        "N4": "secret xac thuc voi dung dich vu so huu no",
        "N5": "secret chi la dich den/dinh danh, khong phai du lieu gui di",
        "N6": "dong hien dien secret + lenh mang nhung khong co duong noi (G2 fail)",
    },
    "UNCLEAR": {
        "U1": "duong di nam trong script cua repo khong co trong Dataset A",
        "U2": "duong di nam ben trong third-party/composite action",
        "U3": "dich den hoac payload phu thuoc gia tri runtime khong giai duoc tinh",
        "U4": "doan trich bi cat, khong co file goc de doi chieu",
        "U5": "khong xac dinh duoc quyen so huu secret cua endpoint (ranh gioi N4/E4)",
    },
}

SOURCE_RE = re.compile(r"secrets\s*\.\s*[A-Za-z0-9_-]+|secrets\s*:\s*inherit|GITHUB_TOKEN", re.I)
SINK_RE = re.compile(
    r"\bcurl\b|\bwget\b|\bnc\b|\bncat\b|\bnetcat\b|\bdig\b|\bnslookup\b|\bscp\b|\brsync\b|"
    r"\bssh\b|\bssh-keyscan\b|\btelnet\b|\bftp\b|requests\.(post|get|put|patch)|urllib|"
    r"http\.client|fetch\s*\(|axios|Invoke-WebRequest|Invoke-RestMethod|Net\.WebClient|"
    r"socket\.|aws s3 (cp|sync)|gh api|\bgcloud\b|\baz \b", re.I)
EXCLUDED_RE = re.compile(
    r"actions/checkout|actions/cache|actions/(upload|download)-artifact|actions/setup-|"
    r"docker/login-action|docker/build-push-action|docker (pull|push)|npm (ci|install)|"
    r"yarn install|pnpm install|pip install|poetry install|apt-get|apk add|brew install|"
    r"go mod download|cargo fetch|codecov", re.I)
PROP_RE = re.compile(r"GITHUB_ENV|GITHUB_OUTPUT|base64|gzip|openssl enc|xxd|tee\b|jq -n", re.I)


def read_csv(p):
    if not os.path.exists(p):
        return []
    with open(p, encoding="utf-8-sig", errors="replace", newline="") as f:
        return list(csv.DictReader(f))


def save(rows):
    with open(OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for rid in sorted(rows):
            w.writerow(rows[rid])


def clear():
    os.system("clear" if os.name != "nt" else "cls")


def read_source_file(row):
    for key in ("local_path", "snippet_file"):
        p = row.get(key) or ""
        if p and os.path.exists(p):
            with open(p, encoding="utf-8", errors="replace") as f:
                return p, f.read()
    return None, None


def evidence_panel(row):
    clear()
    path, text = read_source_file(row)
    print("=" * 78)
    print(f"  BANG BANG CHUNG — {row['review_id']}   nguon: {path or '(khong doc duoc)'}")
    print("  Cong cu chi loc dong theo tu khoa. KHONG phai ket luan. Tu doc va quyet dinh.")
    print("=" * 78)
    if not text:
        input("\n[Enter] ")
        return
    hits = []
    for i, line in enumerate(text.splitlines(), 1):
        tags = []
        if SOURCE_RE.search(line):
            tags.append("G1?")
        if SINK_RE.search(line):
            tags.append("EXCL" if EXCLUDED_RE.search(line) else "G3?")
        elif EXCLUDED_RE.search(line):
            tags.append("EXCL")
        if PROP_RE.search(line):
            tags.append("G2?")
        if tags:
            hits.append((i, ",".join(tags), line.rstrip()[:120]))
    if not hits:
        print("\n  (khong co dong nao khop tu khoa)")
    for i, tag, line in hits:
        print(f"  {i:5d} [{tag:9s}] {line}")
    print("-" * 78)
    print("  G1?=co ve la source   G3?=co ve la sink   EXCL=sink loai tru (muc 2.2)   G2?=buoc lan truyen")
    print("  Luu y: so dong lay theo file dang doc. Neu doc tu snippet, so dong da co san trong snippet.")
    input("\n[Enter de quay lai] ")


def show_guideline():
    clear()
    print("=" * 78)
    print("  TOM TAT ANNOTATION GUIDELINE v1.0")
    print("=" * 78)
    print("""
  EXFIL <=> G1 (source@dong) + G2 (chuoi lan truyen tuong minh) + G3 (sink ngoai)
  Thieu 1 trong 3 -> KHONG duoc gan EXFIL.
  CAM: gan EXFIL vi "co secret + co lenh mang".
  CAM: xem output ExfilGuard/baseline trong luc tro tai.

  Thu tu hoi:
    Q1 co source?              khong -> NO_EXFIL (N1)
    Q2 co network op hop le?   khong -> NO_EXFIL (N2/N3)
    Q3 co duong noi?           khong -> NO_EXFIL (N6) | doc khong duoc -> UNCLEAR (U1-U4)
    Q4 dich co so huu secret?  co -> N4 | khong ro -> U5 | khong -> EXFIL (E1-E4)

  Sink loai tru: checkout, cache, artifact, setup-*, npm/pip/apt/go/cargo,
                 docker login/build-push/pull, codecov.
  Khong phai sink: ghi file tren runner, echo ra log, build-arg, env.
  N5: secret la dia chi dich / username, khong phai du lieu gui di.
""")
    for lbl, d in RULES.items():
        print(f"  {lbl}:")
        for k, v in d.items():
            print(f"    {k}  {v}")
    input("\n[Enter de quay lai] ")


def show_case(row, sheet_row, idx, total, done):
    clear()
    print("=" * 78)
    print(f"  {row['review_id']}   [{row['bucket']}]   ca {idx}/{total}   da xong: {done}")
    print("=" * 78)
    print(f"  Ly do vao hang doi : {row['reason']}")
    print(f"  Repo / File        : {row['repo']} / {row['filename']}")
    print(f"  Tang               : {row['stratum']}")
    print(f"  Secret gap         : {(row['secret_names'] or '(khong co)')[:200]}")
    print(f"  Sink gap           : {row['sink_families'] or '(khong co)'}")
    n1 = (sheet_row or {}).get("annotator1_note", "") or "-"
    n2 = (sheet_row or {}).get("annotator2_note", "") or "-"
    print(f"  A1 = {row['a1_label']:9s} note: {n1[:60]}")
    print(f"  A2 = {row['a2_label']:9s} note: {n2[:60]}")
    print("-" * 78)
    p = row.get("snippet_file") or ""
    if p and os.path.exists(p):
        print(open(p, encoding="utf-8", errors="replace").read())
    else:
        print("(khong doc duoc file trich doan)")
    print("-" * 78)


def show_full(row):
    clear()
    p = row.get("local_path") or ""
    if p and os.path.exists(p):
        text = open(p, encoding="utf-8", errors="replace").read()
        for i, line in enumerate(text.splitlines(), 1):
            print(f"{i:5d}| {line}")
    else:
        print(f"(khong doc duoc file goc: {p})")
        print("Neu thieu thu muc data/raw/, dung 'p' de xem bang bang chung tu snippet,")
        print("va cong nhan U4 neu doan trich khong du de ket luan.")
    input("\n[Enter de quay lai] ")


def ask_rule(label):
    d = RULES[label]
    while True:
        print(f"\n  Ma ly do cho {label}:")
        for k, v in d.items():
            print(f"    {k}  {v}")
        v = input("  Ma > ").strip().upper()
        if v in d:
            return v
        print("  Ma khong hop le.")


def ask(prompt, required=True, default=""):
    while True:
        v = input(prompt).strip()
        if not v and default:
            return default
        if v or not required:
            return v
        print("  Bat buoc dien.")


def collect(label, row):
    print("-" * 78)
    rule = ask_rule(label)
    if label == "EXFIL":
        print("\n  Bat buoc dien du ca ba. Ghi kem so dong.")
        g1 = ask("  G1 source (vd SLACK_TOKEN@31)          > ")
        g2 = ask("  G2 path   (vd secrets.X@31 -> env@31 -> $X@44 -> --data@44) > ")
        g3 = ask("  G3 sink   (vd curl@44 -> https://...)  > ")
    elif label == "UNCLEAR":
        print("\n  Ghi ro thieu du lieu gi.")
        g1 = ask("  G1 source (hoac '-')                   > ", required=False, default="-")
        g2 = ask("  G2 path den cho bi dut                 > ")
        g3 = ask("  G3 sink   (thuong la 'khong xac dinh duoc') > ", required=False,
                 default="khong xac dinh duoc")
    else:
        g1 = ask("  G1 source (hoac '-')                   > ", required=False, default="-")
        g2 = ask("  G2 path   (hoac '-')                   > ", required=False, default="-")
        g3 = ask("  G3 sink   (hoac '-')                   > ", required=False, default="-")
    why = ask("  why  (1 dong, khong dau)               > ")
    return rule, g1, g2, g3, why


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arbiter", required=True, help="ten nguoi tro tai, vd nhi")
    ap.add_argument("--bucket", help="chi lam mot nhom, vd B1_EXFIL_CLAIM")
    ap.add_argument("--id", help="chi lam mot ca, vd A0299")
    ap.add_argument("--redo", action="store_true", help="lam lai ca da xong")
    args = ap.parse_args()

    queue = read_csv(QUEUE)
    if not queue:
        sys.exit(f"Khong co {QUEUE}. Chay src/09_build_adjudication_queue.py truoc.")
    sheet = {r["review_id"]: r for r in read_csv(SHEET)}
    done = {r["review_id"]: r for r in read_csv(OUT)}

    todo = queue
    if args.bucket:
        todo = [r for r in todo if r["bucket"] == args.bucket]
    if args.id:
        todo = [r for r in todo if r["review_id"] == args.id]
    if not args.redo:
        todo = [r for r in todo if r["review_id"] not in done]

    if not todo:
        print("Khong con ca nao trong hang doi. Chay: python3 src/11_finalize_ground_truth.py")
        return

    i = 0
    while 0 <= i < len(todo):
        row = todo[i]
        rid = row["review_id"]
        show_case(row, sheet.get(rid), i + 1, len(todo), len(done))
        if rid in done:
            d = done[rid]
            print(f"  DA XONG truoc do: {d['final_label']} [{d['rule']}] — gan lai se ghi de.")
        k = input("  [e]xfil [n]o [u]nclear | [p]bang chung [f]ile [g]uideline [b]ack [s]kip [q]uit > ").strip().lower()
        if k == "q":
            break
        if k == "s":
            i += 1
            continue
        if k == "b":
            i = max(0, i - 1)
            continue
        if k == "p":
            evidence_panel(row)
            continue
        if k == "f":
            show_full(row)
            continue
        if k == "g":
            show_guideline()
            continue
        label = {"e": "EXFIL", "n": "NO_EXFIL", "u": "UNCLEAR"}.get(k)
        if not label:
            continue
        rule, g1, g2, g3, why = collect(label, row)
        done[rid] = {
            "review_id": rid, "bucket": row["bucket"], "final_label": label, "rule": rule,
            "g1_source": g1, "g2_path": g2, "g3_sink": g3, "why": why,
            "arbiter": args.arbiter, "guideline_rev": REV,
        }
        save(done)
        i += 1

    save(done)
    remaining = [r["review_id"] for r in queue if r["review_id"] not in done]
    print(f"\nDa luu {OUT}: {len(done)} ca.")
    if remaining:
        print(f"Con {len(remaining)} ca chua xong: {', '.join(remaining[:10])}"
              + (" ..." if len(remaining) > 10 else ""))
    else:
        print("Het hang doi. Tiep theo: python3 src/11_finalize_ground_truth.py")


if __name__ == "__main__":
    main()
