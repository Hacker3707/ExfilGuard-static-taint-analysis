"""
Bước 3 — Phân tích từng file YAML và trích đặc trưng.

Đặc trưng trích ra phục vụ hai việc: (a) dựng bảng thống kê cho mục 4.1, và
(b) phân tầng khi lấy mẫu gán nhãn tay ở bước 5.

QUAN TRỌNG: các heuristic ở đây (secret có mặt, có ứng viên sink mạng) KHÔNG phải
là bộ phát hiện của ExfilGuard. Chúng chỉ dùng để chia tầng lấy mẫu. Nếu dùng chính
công cụ của nhóm để sinh ground truth thì đánh giá ở task #16 sẽ mất giá trị vì
lập luận vòng tròn. Điều này phải được nói rõ trong mục 4.1.

Chạy:  python src/03_extract_features.py
Ra:    data/features.jsonl
"""
import json
import os
import re
import sys

import yaml

sys.path.insert(0, os.path.dirname(__file__))
import config as C

INDEX = "data/workflow_index.jsonl"
OUT = "data/features.jsonl"

SECRET_RES = [re.compile(p) for p in C.SECRET_PATTERNS]
INHERIT_RE = re.compile(C.SECRETS_INHERIT_PATTERN)
SINK_RES = {k: [re.compile(p, re.I) for p in v] for k, v in C.NETWORK_SINKS.items()}
PY_RES = [re.compile(p, re.M) for p in C.PYTHON_HINTS]
NODE_RES = [re.compile(p, re.M) for p in C.NODE_HINTS]


def normalize_on_key(d):
    """PyYAML đọc `on:` thành khoá boolean True. Đổi lại thành chuỗi 'on'."""
    if not isinstance(d, dict):
        return d
    out = {}
    for k, v in d.items():
        out["on" if k is True else k] = v
    return out


def collect_run_steps(doc):
    """Trả về danh sách (job_id, step_index, run_text, shell_value, uses_value)."""
    steps = []
    jobs = doc.get("jobs") if isinstance(doc, dict) else None
    if not isinstance(jobs, dict):
        return steps
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        job_shell = None
        defaults = job.get("defaults")
        if isinstance(defaults, dict) and isinstance(defaults.get("run"), dict):
            job_shell = defaults["run"].get("shell")
        for i, st in enumerate(job.get("steps") or []):
            if not isinstance(st, dict):
                continue
            run = st.get("run") if isinstance(st.get("run"), str) else ""
            uses = st.get("uses") if isinstance(st.get("uses"), str) else ""
            # actions/github-script nhúng JavaScript qua with.script — đây cũng là
            # script nhúng theo đúng nghĩa của bài, phải tính vào phân tích.
            if not run and C.GITHUB_SCRIPT_ACTION in uses:
                with_ = st.get("with")
                if isinstance(with_, dict) and isinstance(with_.get("script"), str):
                    run = with_["script"]
            steps.append((str(job_id), i, run, st.get("shell") or job_shell, uses))
    return steps


def detect_language(run_text, shell_value, uses_value):
    if shell_value:
        base = str(shell_value).strip().split()[0].lower()
        if base in C.SHELL_KEY_MAP:
            return C.SHELL_KEY_MAP[base]
    if uses_value and C.GITHUB_SCRIPT_ACTION in uses_value:
        return "javascript"
    if run_text:
        if any(r.search(run_text) for r in PY_RES):
            return "python"
        if any(r.search(run_text) for r in NODE_RES):
            return "javascript"
        return "bash"   # mặc định của GitHub Actions trên runner Linux
    return None


def find_sinks(text):
    hits = {}
    for family, regs in SINK_RES.items():
        m = [r.pattern for r in regs if r.search(text)]
        if m:
            hits[family] = m
    return hits


def extract(text, meta):
    f = dict(meta)
    f["lines"] = text.count("\n") + 1

    # --- phân tích YAML, có đường lui bằng regex nếu file hỏng
    parsed_ok = True
    doc = None
    try:
        doc = yaml.safe_load(text)
        doc = normalize_on_key(doc)
        if not isinstance(doc, dict):
            parsed_ok = False
    except Exception:
        parsed_ok = False
    f["yaml_parse_ok"] = parsed_ok

    # Một file .yml trong .github/workflows chỉ được tính là WORKFLOW nếu có
    # cả `on:` lẫn `jobs:`. Đây là lý do số YAML file và số workflow khác nhau.
    f["is_workflow"] = bool(parsed_ok and doc.get("on") is not None and isinstance(doc.get("jobs"), dict))

    triggers = []
    if f["is_workflow"]:
        on = doc.get("on")
        if isinstance(on, str):
            triggers = [on]
        elif isinstance(on, list):
            triggers = [str(x) for x in on]
        elif isinstance(on, dict):
            triggers = [str(k) for k in on]
    f["triggers"] = sorted(triggers)
    f["risky_trigger"] = any(t in ("pull_request_target", "workflow_run", "issue_comment")
                             for t in triggers)

    # --- secret
    names = set()
    for r in SECRET_RES:
        names |= set(r.findall(text))
    f["secret_names"] = sorted(names)
    f["n_secret_refs"] = len(names)
    f["secrets_inherit"] = bool(INHERIT_RE.search(text))
    f["token_like_env"] = sorted({t for t in C.TOKEN_LIKE_ENV if t in text})
    f["uses_secrets"] = bool(names or f["secrets_inherit"] or f["token_like_env"])

    # --- script nhúng
    steps = collect_run_steps(doc) if f["is_workflow"] else []
    langs, run_chars, n_run = set(), 0, 0
    for _job, _i, run, shell, uses in steps:
        lang = detect_language(run, shell, uses)
        if run:
            n_run += 1
            run_chars += len(run)
        if lang:
            langs.add(lang)
    f["n_steps"] = len(steps)
    f["n_run_steps"] = n_run
    f["run_chars"] = run_chars
    f["embedded_languages"] = sorted(langs)
    f["has_embedded_script"] = n_run > 0

    # --- ứng viên sink mạng: chỉ tìm bên trong khối run, không tìm cả file,
    #     để tránh khớp nhầm với URL trong comment hay tên action.
    run_blob = "\n".join(s[2] for s in steps if s[2])
    sinks = find_sinks(run_blob)
    f["sink_families"] = sorted(sinks)
    f["has_network_sink"] = bool(sinks)

    # --- tầng lấy mẫu
    if f["uses_secrets"] and f["has_network_sink"]:
        f["stratum"] = "S1_secret_and_sink"
    elif f["uses_secrets"]:
        f["stratum"] = "S2_secret_only"
    elif f["has_network_sink"]:
        f["stratum"] = "S3_sink_only"
    else:
        f["stratum"] = "S4_neither"
    return f


def main():
    rows = [json.loads(l) for l in open(INDEX, encoding="utf-8")]
    n_ok = 0
    with open(OUT, "w", encoding="utf-8") as out:
        for i, meta in enumerate(rows, 1):
            try:
                text = open(meta["local_path"], encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            out.write(json.dumps(extract(text, meta), ensure_ascii=False) + "\n")
            n_ok += 1
            if i % 2000 == 0:
                print(f"  {i}/{len(rows)}", flush=True)
    print(f"Xong. {n_ok} file đã trích đặc trưng -> {OUT}")


if __name__ == "__main__":
    main()
