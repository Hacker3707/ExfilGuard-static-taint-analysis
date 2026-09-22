"""
Kiểm tra tính hợp lệ của Dataset B trước khi phát hành.

    python3 validate_dsb.py /duong/dan/ExfilGuard_Dataset_B_v2

Kiểm 6 thứ:
  1. Mọi file workflow parse được bằng YAML (GitHub Actions từ chối file lỗi)
  2. Cấu trúc GitHub Actions tối thiểu: on / jobs / steps
  3. Mọi đường dẫn trong ground_truth.csv đều tồn tại
  4. Mọi script_file khai báo đều được workflow gọi thật
  5. Nhãn chỉ nhận exploit / benign; difficulty chỉ nhận easy / medium / hard
  6. Ca exploit phải tham chiếu ${{ secrets.* }} ở đâu đó

Thoát mã 1 nếu có lỗi — dùng được trong CI.
"""
import csv
import os
import re
import sys

try:
    import yaml
except ImportError:
    sys.exit("Can pyyaml: pip install pyyaml")

VALID_LABEL = {"exploit", "benign"}
VALID_DIFF = {"easy", "medium", "hard"}
SECRET_RE = re.compile(r"\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}")


def main():
    if len(sys.argv) < 2:
        sys.exit("Usage: python3 validate_dsb.py <thu_muc_dataset_B>")
    root = os.path.abspath(os.path.expanduser(sys.argv[1]))
    gt = os.path.join(root, "ground_truth.csv")
    if not os.path.exists(gt):
        sys.exit(f"Cannot find {gt}")

    with open(gt, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))

    errors, warns = [], []
    n_exploit = n_benign = 0

    for r in rows:
        cid = r["case_id"]
        wf = os.path.join(root, r["workflow_file"])

        label = (r.get("label") or "").strip().lower()
        if label not in VALID_LABEL:
            errors.append(f"{cid}: label khong hop le '{label}'")
        n_exploit += label == "exploit"
        n_benign += label == "benign"

        diff = (r.get("difficulty") or "").strip().lower()
        if diff not in VALID_DIFF:
            warns.append(f"{cid}: difficulty la '{diff}'")

        if not os.path.exists(wf):
            errors.append(f"{cid}: thieu file {r['workflow_file']}")
            continue

        raw = open(wf, encoding="utf-8", errors="replace").read()

        # 1. YAML hop le
        try:
            doc = yaml.safe_load(raw)
        except yaml.YAMLError as e:
            line = getattr(getattr(e, "problem_mark", None), "line", None)
            where = f" (dong {line + 1})" if line is not None else ""
            errors.append(f"{cid}: YAML KHONG HOP LE{where} — "
                          f"{str(e).splitlines()[0][:60]}")
            continue

        # 2. Cau truc toi thieu
        if not isinstance(doc, dict):
            errors.append(f"{cid}: khong phai mapping o cap cao nhat")
            continue
        if "jobs" not in doc:
            errors.append(f"{cid}: thieu 'jobs'")
            continue
        if not (doc.get("on") or doc.get(True)):   # YAML doc 'on' thanh True
            warns.append(f"{cid}: thieu 'on'")

        steps = []
        for jname, job in (doc.get("jobs") or {}).items():
            if not isinstance(job, dict):
                errors.append(f"{cid}: job '{jname}' khong hop le")
                continue
            steps.extend(job.get("steps") or [])
        if not steps:
            errors.append(f"{cid}: khong co step nao")
            continue

        run_text = "\n".join(s.get("run", "") for s in steps if isinstance(s, dict))

        # 4. script_file phai duoc goi that
        sf = (r.get("script_file") or "").strip()
        if sf:
            sp = os.path.join(root, sf)
            if not os.path.exists(sp):
                errors.append(f"{cid}: thieu script {sf}")
            elif os.path.basename(sf) not in run_text:
                errors.append(f"{cid}: khai bao script {sf} nhung khong step nao goi")

        # 6. exploit phai co secret
        if label == "exploit" and not SECRET_RE.search(raw):
            errors.append(f"{cid}: la exploit nhung khong tham chieu secrets.*")

    print(f"Dataset: {root}")
    print(f"So ca  : {len(rows)}  ({n_exploit} exploit / {n_benign} benign)\n")

    for w in warns:
        print(f"  [canh bao] {w}")
    for e in errors:
        print(f"  [LOI] {e}")

    if errors:
        print(f"\nKHONG DAT: {len(errors)} loi. Sua roi phat hanh lai.")
        sys.exit(1)
    print(f"\nDAT{'  (' + str(len(warns)) + ' canh bao)' if warns else ''}. "
          f"Moi file parse duoc va co cau truc GitHub Actions hop le.")


if __name__ == "__main__":
    main()
