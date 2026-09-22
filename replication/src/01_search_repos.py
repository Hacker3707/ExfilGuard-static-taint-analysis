"""
Bước 1 — Tìm repository ứng viên bằng GitHub Search API, có phân tầng.

BẢN SỬA (v2). Bản cũ duyệt theo thứ tự `for lang: for stars:`, nghĩa là phải
vét cạn toàn bộ dải sao của Python rồi mới sang JavaScript. Mỗi ô lại lấy tới
1000 kết quả (trần cứng của Search API), nên chỉ hai ô đầu đã ăn hết ngân sách
và tập dữ liệu chỉ còn đúng một ngôn ngữ.

Bản này sửa hai điểm:
  1. Duyệt các ô theo vòng tròn: mỗi lượt đi qua tất cả ngôn ngữ, hết lượt mới
     sang dải sao tiếp theo. Dừng lúc nào cũng có phân bố tương đối đều.
  2. Giới hạn số repo lấy từ MỖI ô bằng MAX_PER_CELL, thay vì để một ô ăn 1000.

Chạy:  python src/01_search_repos.py
Ra:    data/repos.jsonl

Script chạy lại được: đọc file cũ, bỏ qua repo đã có, và biết ô nào đã đủ.
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
import config as C
import gh

OUT = "data/repos.jsonl"
PER_PAGE = 100


def search_cell(lang, lo, hi, want):
    """Một ô phân tầng: ngôn ngữ x dải sao. Lấy tối đa `want` repo."""
    star = f"{lo}..{hi}" if hi < 1000000 else f">={lo}"
    q = (f"language:{lang} stars:{star} pushed:>={C.PUSHED_AFTER} "
         f"is:public archived:false fork:false")
    found = []
    pages = (want + PER_PAGE - 1) // PER_PAGE
    for page in range(1, min(pages, 10) + 1):
        resp = gh.get("/search/repositories", params={
            "q": q, "sort": "updated", "order": "desc",
            "per_page": PER_PAGE, "page": page,
        })
        if resp is None:
            break
        items = resp.json().get("items", [])
        if not items:
            break
        found.extend(items)
        if len(items) < PER_PAGE or len(found) >= want:
            break
        time.sleep(2.2)   # Search API: 30 request/phut khi co token
    return found[:want]


def cell_order():
    """Vong tron: het mot luot ngon ngu moi sang dai sao tiep theo."""
    for lo, hi in C.STAR_BANDS:
        for lang in C.LANGUAGES:
            yield lang, lo, hi


def main():
    os.makedirs("data", exist_ok=True)

    seen = set()
    per_cell_done = {}
    if os.path.exists(OUT):
        with open(OUT, encoding="utf-8") as f:
            for line in f:
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                seen.add(rec["full_name"])
                key = (rec.get("stratum_lang"), rec.get("stratum_stars"))
                per_cell_done[key] = per_cell_done.get(key, 0) + 1
        print(f"Da co san {len(seen)} repo trong {OUT}.")
        if per_cell_done:
            print("Phan bo hien tai theo o:")
            for k, v in sorted(per_cell_done.items(), key=lambda x: -x[1]):
                print(f"  {str(k[0]):12s} sao {str(k[1]):<10} {v}")

    cap = getattr(C, "MAX_PER_CELL", 150)
    total = len(seen)

    with open(OUT, "a", encoding="utf-8") as out:
        for lang, lo, hi in cell_order():
            if total >= C.TARGET_CANDIDATE_REPOS:
                print("\nDa du chi tieu, dung.")
                break

            key = (lang, f"{lo}-{hi}")
            already = per_cell_done.get(key, 0)
            want = cap - already
            if want <= 0:
                print(f"{lang:12s} sao {lo}-{hi:<8} bo qua (da co {already})")
                continue

            items = search_cell(lang, lo, hi, want)
            added = 0
            for it in items:
                if it["full_name"] in seen:
                    continue
                seen.add(it["full_name"])
                out.write(json.dumps({
                    "full_name":      it["full_name"],
                    "html_url":       it["html_url"],
                    "stars":          it["stargazers_count"],
                    "language":       it.get("language"),
                    "size_kb":        it.get("size"),
                    "created_at":     it.get("created_at"),
                    "pushed_at":      it.get("pushed_at"),
                    "default_branch": it.get("default_branch", "main"),
                    "stratum_lang":   lang,
                    "stratum_stars":  f"{lo}-{hi}",
                }, ensure_ascii=False) + "\n")
                added += 1
                total += 1
            out.flush()
            print(f"{lang:12s} sao {lo}-{hi:<8} +{added:4d}  (tong {total})", flush=True)

    print(f"\nXong. {total} repository ung vien trong {OUT}")
    print("Quota con lai:", gh.quota())


if __name__ == "__main__":
    main()
