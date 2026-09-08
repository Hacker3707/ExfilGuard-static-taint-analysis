import re

from catalogs import ALLOWLISTED_DOMAINS, CREDENTIAL_LEXICAL_PATTERN

# ==============================================================================
# Weight matrices (Section 3.4 / 3.6)
# ==============================================================================
SOURCE_WEIGHTS = {
    "S_ctx": 3.0, "S_dyn": 3.0, "S_prog": 2.0, "S_env": 2.0, "S_inp": 1.0
}
SINK_WEIGHTS = {
    "K_cli": 3.0, "K_raw": 3.0, "K_dns": 3.0, "K_lib": 2.5,
    "K_scm": 1.5,
    # K_artifact: upload artifact. Dat ngang K_scm vi cung la kenh publish
    # gian tiep qua file, khong phai egress mang truc tiep.
    "K_artifact": 1.5,
    # K_file: scp/rsync/gsutil/azcopy/curl -T. Ngang K_cli vi day la egress
    # mang truc tiep, chi khac o cho payload di qua file.
    "K_file": 3.0,
}
DESTINATION_MULTIPLIERS = {
    "untrusted_external": 1.2, "external": 1.0, "allowlisted": 0.4
}

# ==============================================================================
# CANH BAO VE BAO HOA DIEM
# ==============================================================================
# Mo hinh nhan hien tai bi tran o dau tren:
#
#   S_ctx(3.0) x K_cli(3.0) x untrusted(1.2) = 10.8  -> cap ve 10.0
#   S_ctx(3.0) x K_dns(3.0) x untrusted(1.2) = 10.8  -> cap ve 10.0
#   S_ctx(3.0) x K_raw(3.0) x untrusted(1.2) = 10.8  -> cap ve 10.0
#   S_dyn x {K_cli, K_dns, K_raw} x untrusted        -> cap ve 10.0
#
# Sau 6 to hop khac nhau ve ban chat deu hien thi giong het nhau, nen diem
# khong con phan biet duoc muc do nghiem trong o vung CRITICAL.
#
# NORMALIZE_SCORE=True chuan hoa ve thang [0, 10] thay vi cat cut, giu nguyen
# thu tu xep hang giua cac path. Mac dinh False de tai lap dung so lieu da
# cong bo; bat len neu can do phan giai o vung diem cao.
NORMALIZE_SCORE = False

_MAX_RAW = max(SOURCE_WEIGHTS.values()) * max(SINK_WEIGHTS.values()) * max(
    DESTINATION_MULTIPLIERS.values()
)

# Nguong phan loai. Them INFO de khop voi FINDING_TYPE_SCORE_CAP trong
# engine/models.py (finding INFO bi cap ve 1.5).
LEVEL_THRESHOLDS = (
    (8.0, "CRITICAL"),
    (6.0, "HIGH"),
    (4.0, "MEDIUM"),
    (2.0, "LOW"),
)


def level_for_score(score: float) -> str:
    for threshold, level in LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    return "INFO"


# ==============================================================================
# SOURCE
# ==============================================================================

def classify_source(source_str: str) -> str:
    if not isinstance(source_str, str):
        return "S_env"

    # SRC-01 / SRC-02: platform secret va runner token.
    if source_str.startswith("${{ secrets.") or source_str == "${{ github.token }}":
        return "S_ctx"

    # SRC-07 / SRC-08: credential dong tu IMDS hoac secret-store CLI.
    # bash_analyzer gan tien to "dynamic:" khi seed loai nguon nay.
    if source_str.startswith("dynamic:"):
        return "S_dyn"

    if any(
        source_str.startswith(prefix)
        for prefix in ("os.getenv", "os.environ", "process.env")
    ):
        return "S_prog"

    if source_str.startswith("${{ inputs.") or source_str.startswith(
        "${{ github.event.inputs."
    ):
        return "S_inp"

    return "S_env"


def is_credential_lexical(name: str) -> bool:
    """SRC-03: ten bien khop lexical qualifier (TOKEN/SECRET/KEY/PASS/...).

    Tach rieng thanh ham de goi co chon loc. KHONG bat mac dinh: coi moi bien
    ten *KEY* la nhay cam se tao FP tren nhung thu nhu CACHE_KEY, SORT_KEY,
    PRIMARY_KEY. Bat qua ExfilGuardConfig.enable_lexical_source neu can dung
    dung dac ta SRC-03.
    """
    return bool(name and CREDENTIAL_LEXICAL_PATTERN.search(name))


# ==============================================================================
# SINK
# ==============================================================================

def classify_sink(sink_cmd: str) -> str:
    if sink_cmd in ["curl", "wget", "scp", "rsync"]:
        return "K_cli"
    # SNK raw socket: tach khoi K_cli. nc/socat khong noi HTTP, chung mo
    # TCP/UDP tho nen thuoc pham tru khac.
    if sink_cmd in ["nc", "ncat", "socat", "telnet", "socket.socket"]:
        return "K_raw"
    if sink_cmd in ["dig", "nslookup", "host", "socket.gethostbyname"]:
        return "K_dns"
    if isinstance(sink_cmd, str) and sink_cmd.startswith("git "):
        return "K_scm"
    if isinstance(sink_cmd, str) and "upload-artifact" in sink_cmd:
        return "K_artifact"
    if isinstance(sink_cmd, str) and sink_cmd.split()[0] in (
        "scp", "rsync", "gsutil", "azcopy", "aws", "gh",
    ):
        return "K_file"
    return "K_lib"


# ==============================================================================
# DESTINATION
# ==============================================================================

def classify_destination(text: str) -> str:
    """
    Ba tang, dung nhu Section 3.6 mo ta.

    Ban truoc chi tra ve 2 gia tri: khong co URL literal -> untrusted_external.
    Nghia la tang "external" (nhan 1.0) khong bao gio duoc dung, va moi lenh
    co URL nam trong bien deu an nhan cao nhat. Do la nguon FP he thong.
    """
    if not isinstance(text, str):
        return "untrusted_external"

    urls = re.findall(r"https?://([^/\s\"']+)", text)
    if not urls:
        # Dich den khong trich xuat duoc tinh (nam trong bien / secret).
        # Giu untrusted_external vi khong the chung minh la an toan, NHUNG
        # arg_roles da loc truoc: neu secret chi o vi tri dich den va payload
        # sach thi finding la INFO, khong phai EXFIL.
        return "untrusted_external"

    hostname = urls[0].lower().split("@")[-1].split(":")[0]

    for domain in ALLOWLISTED_DOMAINS:
        if hostname == domain or hostname.endswith("." + domain):
            return "allowlisted"

    # Host literal, phan giai duoc, khong nam trong allowlist.
    # Day la tang "external" (1.0) ma dac ta mo ta.
    if re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", hostname):
        return "external"

    # IP tho hoac host khong hop le -> khong xac minh duoc.
    return "untrusted_external"


# ==============================================================================
# RISK
# ==============================================================================

def calculate_risk(src_cat: str, snk_cat: str, dst_type: str):
    w_src = SOURCE_WEIGHTS.get(src_cat, 1.0)
    w_snk = SINK_WEIGHTS.get(snk_cat, 1.0)
    m_dst = DESTINATION_MULTIPLIERS.get(dst_type, 1.0)

    raw = (w_src * w_snk) * m_dst

    if NORMALIZE_SCORE:
        score = round(10.0 * raw / _MAX_RAW, 1)
    else:
        score = round(min(10.0, raw), 1)

    return score, level_for_score(score)