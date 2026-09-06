import re
from catalogs import ALLOWLISTED_DOMAINS

# Weight matrices (Section 3.4)
SOURCE_WEIGHTS = {
    "S_ctx": 3.0, "S_dyn": 3.0, "S_prog": 2.0, "S_env": 2.0, "S_inp": 1.0
}
SINK_WEIGHTS = {
    "K_cli": 3.0, "K_raw": 3.0, "K_dns": 3.0, "K_lib": 2.5, "K_scm": 1.5
}
DESTINATION_MULTIPLIERS = {
    "untrusted_external": 1.2, "external": 1.0, "allowlisted": 0.4
}

def classify_source(source_str: str) -> str:
    if source_str.startswith("${{ secrets.") or source_str == "${{ github.token }}":
        return "S_ctx"
    if any(source_str.startswith(k) for k in ["os.getenv", "os.environ", "process.env"]):
        return "S_prog"
    if source_str.startswith("${{ inputs."):
        return "S_inp"
    return "S_env"

def classify_sink(sink_cmd: str) -> str:
    if sink_cmd in ["curl", "wget", "nc", "ncat", "socat", "scp", "rsync"]:
        return "K_cli"
    if sink_cmd in ["dig", "nslookup", "host", "socket.gethostbyname"]:
        return "K_dns"
    return "K_lib"

def classify_destination(text: str) -> str:
    urls = re.findall(r"https?://([^/\s\"']+)", text)
    if not urls:
        return "untrusted_external"
    hostname = urls[0].lower().split(":")[0]
    for domain in ALLOWLISTED_DOMAINS:
        if hostname == domain or hostname.endswith("." + domain):
            return "allowlisted"
    return "untrusted_external"

def calculate_risk(src_cat: str, snk_cat: str, dst_type: str):
    w_src = SOURCE_WEIGHTS.get(src_cat, 1.0)
    w_snk = SINK_WEIGHTS.get(snk_cat, 1.0)
    m_dst = DESTINATION_MULTIPLIERS.get(dst_type, 1.0)
    score = round(min(10.0, (w_src * w_snk) * m_dst), 1)

    if score >= 8.0:
        level = "CRITICAL"
    elif score >= 6.0:
        level = "HIGH"
    elif score >= 4.0:
        level = "MEDIUM"
    else:
        level = "LOW"
    return score, level