"""
Bước 4 — Áp bộ lọc cuối, khử trùng lặp, xuất Dataset A và bảng thống kê.

KHỬ TRÙNG LẶP LÀ BẮT BUỘC. Workflow bị sao chép giữa các repo rất nhiều; nếu để
nguyên, một template phổ biến sẽ bị đếm hàng trăm lần và mọi tỉ lệ phần trăm trong
mục 4.1 đều sai lệch. Script giữ bản xuất hiện đầu tiên và ghi lại số bản trùng.

Chạy:  python src/04_build_dataset.py
Ra:    data/dataset_a.csv        (tập cuối cùng, mỗi dòng một workflow)
       data/dataset_a_full.jsonl (giữ đủ trường, dùng cho phân tích sâu)
       data/stats_4_1.md         (bảng thống kê dán thẳng vào mục 4.1)
       data/filter_log.md        (số lượng bị loại ở từng bước - dùng cho sơ đồ PRISMA)
"""
import csv
import json
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(__file__))
import config as C

FEAT = "data/features.jsonl"


def main():
    rows = [json.loads(l) for l in open(FEAT, encoding="utf-8")]
    log = [("Số file YAML tải về từ .github/workflows/", len(rows))]

    # (1) chỉ giữ file thực sự là workflow
    wf = [r for r in rows if r["is_workflow"]]
    log.append(("Loại: không phân tích được YAML hoặc thiếu on:/jobs:", len(rows) - len(wf)))

    # (2) khử trùng lặp theo nội dung
    seen, dedup = {}, []
    dup_count = Counter()
    for r in wf:
        h = r["content_sha256"]
        if h in seen:
            dup_count[h] += 1
            continue
        seen[h] = r
        dedup.append(r)
    n_dup = len(wf) - len(dedup)
    log.append(("Loại: trùng lặp nội dung y hệt (giữ bản đầu tiên)", n_dup))
    for r in dedup:
        r["duplicate_copies"] = dup_count.get(r["content_sha256"], 0)

    log.append(("DATASET A cuối cùng (số workflow duy nhất)", len(dedup)))

    os.makedirs("data", exist_ok=True)
    with open("data/dataset_a_full.jsonl", "w", encoding="utf-8") as f:
        for r in dedup:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    cols = ["repo", "stars", "repo_language", "filename", "lines", "n_steps",
            "n_run_steps", "run_chars", "embedded_languages", "uses_secrets",
            "n_secret_refs", "secrets_inherit", "has_network_sink", "sink_families",
            "triggers", "risky_trigger", "stratum", "duplicate_copies",
            "content_sha256", "local_path"]
    with open("data/dataset_a.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for r in dedup:
            w.writerow(["|".join(r[c]) if isinstance(r.get(c), list) else r.get(c, "")
                        for c in cols])

    # ---------------- thống kê cho mục 4.1
    repos = {r["repo"] for r in dedup}
    langs = Counter()
    for r in dedup:
        for l in r["embedded_languages"]:
            langs[l] += 1
    strata = Counter(r["stratum"] for r in dedup)
    sinks = Counter()
    for r in dedup:
        for s in r["sink_families"]:
            sinks[s] += 1
    repo_lang = Counter(r["repo_language"] or "unknown" for r in dedup)
    star_band = Counter(r.get("stratum_stars", "?") for r in dedup)

    n = len(dedup)
    pct = lambda x: f"{100.0 * x / n:.1f}%" if n else "0%"

    L = []
    L.append("# Dataset A — thống kê cho mục 4.1\n")
    L.append("_Sinh tự động bởi `04_build_dataset.py`. Không sửa tay; chạy lại script nếu dữ liệu đổi._\n")

    L.append("\n## Bảng 1. Quy mô Dataset A\n")
    L.append("| Đại lượng | Giá trị |")
    L.append("|---|---|")
    L.append(f"| Số repository | {len(repos)} |")
    L.append(f"| Số workflow (duy nhất sau khử trùng lặp) | {n} |")
    L.append(f"| Số file YAML tải về ban đầu | {len(rows)} |")
    L.append(f"| Số bản trùng lặp bị loại | {n_dup} |")
    L.append(f"| Tổng số step | {sum(r['n_steps'] for r in dedup)} |")
    L.append(f"| Số step có khối run: | {sum(r['n_run_steps'] for r in dedup)} |")
    L.append(f"| Tổng ký tự script nhúng | {sum(r['run_chars'] for r in dedup):,} |")

    L.append("\n## Bảng 2. Ngôn ngữ script nhúng\n")
    L.append("| Ngôn ngữ | Số workflow | Tỉ lệ |")
    L.append("|---|---|---|")
    for k, v in langs.most_common():
        L.append(f"| {k} | {v} | {pct(v)} |")

    L.append("\n## Bảng 3. Secret và ứng viên sink mạng\n")
    L.append("| Đặc điểm | Số workflow | Tỉ lệ |")
    L.append("|---|---|---|")
    us = sum(1 for r in dedup if r["uses_secrets"])
    hs = sum(1 for r in dedup if r["has_network_sink"])
    inh = sum(1 for r in dedup if r["secrets_inherit"])
    rt = sum(1 for r in dedup if r["risky_trigger"])
    L.append(f"| Có tham chiếu secret | {us} | {pct(us)} |")
    L.append(f"| Dùng secrets: inherit | {inh} | {pct(inh)} |")
    L.append(f"| Có ứng viên sink mạng trong khối run: | {hs} | {pct(hs)} |")
    L.append(f"| Có trigger rủi ro (pull_request_target, workflow_run, issue_comment) | {rt} | {pct(rt)} |")

    L.append("\n## Bảng 4. Phân tầng dùng để lấy mẫu gán nhãn\n")
    L.append("| Tầng | Ý nghĩa | Số workflow | Tỉ lệ |")
    L.append("|---|---|---|---|")
    mean = {"S1_secret_and_sink": "Có cả secret lẫn ứng viên sink — tầng quan trọng nhất",
            "S2_secret_only": "Có secret, không có ứng viên sink",
            "S3_sink_only": "Có ứng viên sink, không có secret",
            "S4_neither": "Không có cả hai"}
    for k in ["S1_secret_and_sink", "S2_secret_only", "S3_sink_only", "S4_neither"]:
        L.append(f"| {k} | {mean[k]} | {strata.get(k,0)} | {pct(strata.get(k,0))} |")

    L.append("\n## Bảng 5. Họ sink xuất hiện\n")
    L.append("| Họ sink | Số workflow |")
    L.append("|---|---|")
    for k, v in sinks.most_common():
        L.append(f"| {k} | {v} |")

    L.append("\n## Bảng 6. Phân bố theo ngôn ngữ chính của repository\n")
    L.append("| Ngôn ngữ repo | Số workflow |")
    L.append("|---|---|")
    for k, v in repo_lang.most_common():
        L.append(f"| {k} | {v} |")

    L.append("\n## Bảng 7. Phân bố theo dải sao\n")
    L.append("| Dải sao | Số workflow |")
    L.append("|---|---|")
    for k, v in sorted(star_band.items()):
        L.append(f"| {k} | {v} |")

    L.append("\n## Tiêu chí lựa chọn đã áp dụng\n")
    L.append(f"- Repository công khai, không phải fork, không bị lưu trữ (archived)")
    L.append(f"- Số sao tối thiểu: {C.MIN_STARS}")
    L.append(f"- Có commit sau ngày: {C.PUSHED_AFTER}")
    L.append(f"- Phân tầng theo ngôn ngữ chính: {', '.join(C.LANGUAGES)}")
    L.append(f"- Phân tầng theo dải sao: {', '.join(f'{a}-{b}' for a,b in C.STAR_BANDS)}")
    L.append(f"- Có ít nhất một file .yml hoặc .yaml trong .github/workflows/")
    L.append(f"- Kích thước file tối đa: {C.MAX_WORKFLOW_BYTES // 1024} KB")
    L.append(f"- Số workflow tối đa lấy từ một repository: {C.MAX_WORKFLOWS_PER_REPO}")
    L.append(f"- File phải phân tích được YAML và có cả khoá on: lẫn jobs:")
    L.append(f"- Khử trùng lặp theo băm SHA-256 của nội dung")

    open("data/stats_4_1.md", "w", encoding="utf-8").write("\n".join(L) + "\n")

    F = ["# Nhật ký lọc — dùng để vẽ sơ đồ luồng dữ liệu trong mục 4.1\n",
         "| Bước | Số lượng |", "|---|---|"]
    for k, v in log:
        F.append(f"| {k} | {v} |")
    open("data/filter_log.md", "w", encoding="utf-8").write("\n".join(F) + "\n")

    print("\n".join(f"{v:>8}  {k}" for k, v in log))
    print("\nĐã ghi: data/dataset_a.csv, data/dataset_a_full.jsonl, data/stats_4_1.md, data/filter_log.md")


if __name__ == "__main__":
    main()
