"""
Bước 7 — Công cụ gán nhãn trên terminal.

Thay cho việc mở từng file bằng tay. Hiển thị đoạn trích liên quan, hỏi nhãn,
ghi ngay sau mỗi mẫu nên tắt giữa chừng không mất gì.

Mỗi người chạy với số của mình:
    python src/07_label.py --annotator 1
    python src/07_label.py --annotator 2

Ghi ra file riêng (data/labels_a1.csv, data/labels_a2.csv) để hai người không
đụng file của nhau. Gộp lại bằng src/08_merge_labels.py.

Phím:
    e  EXFIL       có đường đi hoàn chỉnh từ secret tới sink mạng
    n  NO_EXFIL    không có đường nào nối được
    u  UNCLEAR     phụ thuộc mã ngoài file, không kết luận được
    f  xem toàn bộ file workflow
    b  quay lại mẫu trước
    s  bỏ qua, quay lại sau
    q  thoát (đã lưu hết phần làm rồi)
"""
import argparse
import csv
import os
import sys

SHEET = "data/review_sheet.csv"
FIELDS = ["review_id", "label", "source", "sink", "note"]


def load_done(path):
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8", errors="replace") as f:
        return {r["review_id"]: r for r in csv.DictReader(f)}


def save(path, rows):
    with open(path, "w", newline="", encoding="utf-8", errors="replace") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for rid in sorted(rows):
            w.writerow(rows[rid])


def show(row, idx, total, done_count):
    os.system("clear" if os.name != "nt" else "cls")
    print("=" * 78)
    print(f"  {row['review_id']}      mau {idx}/{total}      da gan: {done_count}")
    print("=" * 78)
    print(f"  Repo : {row['repo']}")
    print(f"  File : {row['filename']}")
    print(f"  Secret gap: {row['secret_names'] or '(khong co)'}")
    print(f"  Sink gap  : {row['sink_families'] or '(khong co)'}")
    print("-" * 78)
    try:
        print(open(row["snippet_file"], encoding="utf-8", errors="replace").read())
    except OSError:
        print("(khong doc duoc file trich doan)")
    print("-" * 78)


def show_full(row):
    os.system("clear" if os.name != "nt" else "cls")
    try:
        print(open(row["local_path"], encoding="utf-8", errors="replace").read())
    except OSError:
        print("(khong doc duoc file goc)")
    input("\n[Enter de quay lai] ")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--annotator", required=True, choices=["1", "2"])
    ap.add_argument("--sheet", default=SHEET)
    args = ap.parse_args()

    out = f"data/labels_a{args.annotator}.csv"
    rows = list(csv.DictReader(open(args.sheet, encoding="utf-8", errors="replace")))
    done = load_done(out)

    print(f"Nguoi gan nhan {args.annotator} | {len(rows)} mau | da lam {len(done)}")
    input("[Enter de bat dau] ")

    i = 0
    while i < len(rows):
        row = rows[i]
        rid = row["review_id"]
        if rid in done:
            i += 1
            continue

        show(row, i + 1, len(rows), len(done))
        print("  [e] EXFIL   [n] NO_EXFIL   [u] UNCLEAR   [f] xem ca file"
              "   [b] lui   [s] bo qua   [q] thoat")
        k = input("  > ").strip().lower()

        if k == "q":
            break
        if k == "f":
            show_full(row)
            continue
        if k == "s":
            i += 1
            continue
        if k == "b":
            i = max(0, i - 1)
            done.pop(rows[i]["review_id"], None)
            continue
        if k not in ("e", "n", "u"):
            continue

        label = {"e": "EXFIL", "n": "NO_EXFIL", "u": "UNCLEAR"}[k]
        src = sink = ""
        if label == "EXFIL":
            src = input("  Source (ten secret la diem dau): ").strip()
            sink = input("  Sink (lenh hoac ham la diem cuoi): ").strip()
        note = input("  Ghi chu (bat buoc neu UNCLEAR, Enter de bo qua): ").strip()
        if label == "UNCLEAR" and not note:
            note = "(khong ghi ly do)"

        done[rid] = {"review_id": rid, "label": label, "source": src,
                     "sink": sink, "note": note}
        save(out, done)          # ghi ngay sau moi mau
        i += 1

    save(out, done)
    print(f"\nDa luu {len(done)}/{len(rows)} nhan vao {out}")
    if len(done) < len(rows):
        print("Chay lai lenh cu de tiep tuc tu cho dang do.")


if __name__ == "__main__":
    main()
