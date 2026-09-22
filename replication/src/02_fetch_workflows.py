"""
Bước 2 — Tải file YAML trong .github/workflows/ của từng repository.

Mỗi repo tốn 1 request để liệt kê thư mục, cộng thêm 1 request cho mỗi file tải về.
Với token, giới hạn là 5000 request/giờ, nên khoảng 1500-2000 repo mỗi giờ.
Script có thể dừng giữa chừng và chạy lại: nó đọc lại phần đã tải và bỏ qua.

Chạy:  python src/02_fetch_workflows.py
Ra:    data/raw/<owner>__<repo>__<file>.yml   (nội dung workflow)
       data/workflow_index.jsonl               (siêu dữ liệu mỗi file)
       data/repos_no_workflow.txt              (repo bị loại vì không có workflow)
"""
import json
import os
import sys
import hashlib

sys.path.insert(0, os.path.dirname(__file__))
import config as C
import gh

REPOS = "data/repos.jsonl"
RAWDIR = "data/raw"
INDEX = "data/workflow_index.jsonl"
NOWF = "data/repos_no_workflow.txt"


def safe_name(full_name, filename):
    return full_name.replace("/", "__") + "__" + filename.replace("/", "_")


def main():
    os.makedirs(RAWDIR, exist_ok=True)
    done = set()
    if os.path.exists(INDEX):
        with open(INDEX, encoding="utf-8") as f:
            for line in f:
                try:
                    done.add(json.loads(line)["repo"])
                except Exception:
                    pass
    if os.path.exists(NOWF):
        done |= {l.strip() for l in open(NOWF, encoding="utf-8") if l.strip()}
    print(f"Đã xử lý trước đó: {len(done)} repo")

    repos = [json.loads(l) for l in open(REPOS, encoding="utf-8")]
    n_wf = 0
    with open(INDEX, "a", encoding="utf-8") as idx, open(NOWF, "a", encoding="utf-8") as nowf:
        for i, r in enumerate(repos, 1):
            fn = r["full_name"]
            if fn in done:
                continue
            resp = gh.get(f"/repos/{fn}/contents/.github/workflows")
            if resp is None:
                nowf.write(fn + "\n"); nowf.flush()
                continue
            listing = resp.json()
            if not isinstance(listing, list):
                nowf.write(fn + "\n"); nowf.flush()
                continue

            files = [x for x in listing
                     if x.get("type") == "file"
                     and x["name"].lower().endswith((".yml", ".yaml"))
                     and x.get("size", 0) <= C.MAX_WORKFLOW_BYTES]
            files = files[:C.MAX_WORKFLOWS_PER_REPO]
            if not files:
                nowf.write(fn + "\n"); nowf.flush()
                continue

            for fmeta in files:
                text = gh.get_raw(fmeta["download_url"])
                if text is None:
                    continue
                local = os.path.join(RAWDIR, safe_name(fn, fmeta["name"]))
                with open(local, "w", encoding="utf-8") as fh:
                    fh.write(text)
                idx.write(json.dumps({
                    "repo": fn,
                    "stars": r["stars"],
                    "repo_language": r.get("language"),
                    "stratum_lang": r.get("stratum_lang"),
                    "stratum_stars": r.get("stratum_stars"),
                    "filename": fmeta["name"],
                    "path": ".github/workflows/" + fmeta["name"],
                    "size_bytes": fmeta.get("size"),
                    "blob_sha": fmeta.get("sha"),
                    "content_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                    "local_path": local,
                }, ensure_ascii=False) + "\n")
                n_wf += 1
            idx.flush()

            if i % 50 == 0:
                print(f"  {i}/{len(repos)} repo | {n_wf} workflow đã tải | quota {gh.quota()}",
                      flush=True)

    print(f"\nXong. Đã tải thêm {n_wf} file workflow vào {RAWDIR}")


if __name__ == "__main__":
    main()
