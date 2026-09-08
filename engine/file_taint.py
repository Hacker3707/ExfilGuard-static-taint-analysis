"""
engine/file_taint.py

Taint cap FILE.

Ly do ton tai: bien khong phai kenh duy nhat. Duong ro that su trong
proxy-sorter di qua file, khong qua argv:

    CONTENT=$(curl -s "$SECRET_URL")      # bien mang taint
    echo "$CONTENT" > input/proxies.txt   # taint chuyen sang FILE
    git add .                             # file vao staging
    git push                              # file len repo cong khai

Khong co buoc giua thi ca ba analyzer hien tai deu bao BENIGN, vi khong co
secret nao xuat hien tren dong `git push`.

File taint song o pham vi JOB, khong phai STEP: file ton tai xuyen suot cac
step trong cung mot job.
"""

import re

WILDCARD_PATTERNS = {".", "-A", "--all", "*", "./", "-u", "--update"}


def normalize_path(path_str):
    """Chuan hoa duong dan de so khop.

    Chu y: KHONG dung lstrip("./") - no an ca dau cham cua `git add .`
    va bien pattern thanh chuoi rong.
    """
    cleaned = str(path_str).strip().strip("'\"")
    if cleaned in WILDCARD_PATTERNS:
        return cleaned
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned.rstrip("/") or cleaned


class FileTaintState:
    """Trang thai file tainted va vung staging cua git trong mot job."""

    def __init__(self):
        self.files = {}    # path -> {"Source": str, "Path": [str]}
        self.staged = {}   # path -> info

    def taint(self, path_str, source, trail):
        key = normalize_path(path_str)
        if not key:
            return
        self.files[key] = {"Source": source, "Path": list(trail)}

    def match(self, pattern):
        """Tra ve list (path, info) TAT DINH cho mot pattern git add / artifact."""
        pattern = normalize_path(pattern)
        hits = []
        for path in sorted(self.files):
            if pattern in WILDCARD_PATTERNS:
                hits.append((path, self.files[path]))
            elif pattern.endswith("*") and path.startswith(pattern[:-1]):
                hits.append((path, self.files[path]))
            elif path == pattern or path.startswith(pattern + "/"):
                hits.append((path, self.files[path]))
        return hits

    def stage(self, pattern):
        for path, info in self.match(pattern):
            self.staged[path] = info

    def stage_all(self):
        for path, info in sorted(self.files.items()):
            self.staged[path] = info

    def take_staged(self):
        """Lay danh sach staged roi xoa - `git push` chi day mot lan."""
        items = sorted(self.staged.items())
        self.staged = {}
        return items


# ==============================================================================
# GHI VAO FILE
# ==============================================================================

def apply_write_redirects(line, var_tainted, file_state, redirect_pattern,
                          tee_pattern, find_secret, find_tainted_ref):
    """
    Tim `> file`, `>> file`, `| tee file` va chuyen taint tu ve trai sang file.

    Bo qua $GITHUB_ENV / $GITHUB_OUTPUT - do la kenh truyen bien giua cac step,
    khong phai file du lieu.
    """
    for pattern in (redirect_pattern, tee_pattern):
        for match in pattern.finditer(line):
            target = match.group(1)
            if "GITHUB_ENV" in target or "GITHUB_OUTPUT" in target:
                continue

            left = line[: match.start()]

            secret = find_secret(left)
            if secret:
                file_state.taint(target, secret, [secret, "file:" + target])
                continue

            ref = find_tainted_ref(left, var_tainted)
            if ref:
                info = var_tainted[ref]
                file_state.taint(
                    target, info["Source"], info["Path"] + ["file:" + target]
                )


# ==============================================================================
# TRACE TOOL
# ==============================================================================

TRACE_TOOL_PATTERN = re.compile(r"playwright\s+test\b(?=.*--trace(?![= ]off))")
TRACE_OUTPUT_PATTERN = re.compile(r"--output[= ]([^\s;&|]+)")


def apply_trace_tools(line, var_tainted, file_state):
    """
    Cong cu ghi trace mang (playwright --trace) dump toan bo request URL,
    header va response vao thu muc output. Neu step co bien tainted trong env
    thi thu muc do mang taint.

    Day la case staging: BASE_URL la secret, --trace=on, roi upload-artifact.
    """
    if not TRACE_TOOL_PATTERN.search(line):
        return
    if not var_tainted:
        return

    name = sorted(var_tainted)[0]
    info = var_tainted[name]

    out_match = TRACE_OUTPUT_PATTERN.search(line)
    out_dir = out_match.group(1) if out_match else "test-results"
    file_state.taint(out_dir, info["Source"], info["Path"] + ["trace:" + out_dir])