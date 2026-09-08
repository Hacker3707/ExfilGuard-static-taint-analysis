import re

# ==============================================================================
# SOURCE IDENTIFIERS & REGEX
# ==============================================================================
# S_ctx: Context secrets (GitHub secrets, tokens)
SECRET_PATTERN = re.compile(
    r"\$\{\{\s*(?:secrets\.[A-Za-z0-9_-]+|github\.token)\s*\}\}"
)

# S_inp: Workflow inputs
INPUT_PATTERN = re.compile(
    r"\$\{\{\s*inputs\.[A-Za-z0-9_]+\s*\}\}"
)

# S_inp: du lieu do NGUOI NGOAI kiem soat (PR title/body, branch name).
# Khac INPUT_PATTERN: inputs.* do nguoi chay workflow dat, con cai nay den tu
# ben ngoai va la nguon script injection.
UNTRUSTED_EVENT_PATTERN = re.compile(
    r"\$\{\{\s*github\.(?:event\.[A-Za-z0-9_.\[\]]*|head_ref)\s*\}\}"
)

# S_prog: Programmatic environment access patterns
PYTHON_ENV_PATTERNS = [
    re.compile(r"""\bos\.getenv\s*\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*\)"""),
    re.compile(r"""\bos\.environ\.get\s*\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*\)"""),
    re.compile(r"""\bos\.environ\s*\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*\]"""),
]

NODEJS_ENV_PATTERNS = [
    re.compile(r"""\bprocess\.env\.([A-Za-z_][A-Za-z0-9_]*)"""),
    re.compile(r"""\bprocess\.env\[["']([A-Za-z_][A-Za-z0-9_]*)["']\]"""),
]

# S_dyn: credential lay tu Instance Metadata Service.
# Day la duong lay credential kinh dien tren CI co IAM role gan vao runner:
# container chay --network=host goi thang IMDS la co token cua role do.
IMDS_ENDPOINT_PATTERN = re.compile(
    r"169\.254\.169\.254"                    # AWS / Azure IMDS
    r"|169\.254\.170\.2"                     # ECS task metadata
    r"|metadata\.google\.internal"            # GCP
    r"|metadata\.azure\.com"
)

# Lenh CLI tra ve credential ngan han.
DYNAMIC_CRED_PATTERN = re.compile(
    r"\baws\s+ecr\s+get-login-password\b"
    r"|\baws\s+sts\s+(?:assume-role|get-session-token)\b"
    r"|\bgcloud\s+auth\s+print-(?:access|identity)-token\b"
    r"|\baz\s+account\s+get-access-token\b"
    r"|\bvault\s+(?:read|kv\s+get)\b"
    r"|\baws\s+secretsmanager\s+get-secret-value\b"
    r"|\baz\s+keyvault\s+secret\s+show\b"
)

# SRC-03: lexical credential qualifier. Dung boi common.is_credential_lexical.
# KHONG bat mac dinh: coi moi bien ten *KEY* la nhay cam se tao FP tren
# CACHE_KEY, SORT_KEY, PRIMARY_KEY...
CREDENTIAL_LEXICAL_PATTERN = re.compile(
    r"(?:TOKEN|SECRET|KEY|PASS|PWD|AUTH|CRED)", re.IGNORECASE
)

VAR_REF_PATTERN = re.compile(
    r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*|\d+)\}|([A-Za-z_][A-Za-z0-9_]*|\d+))"
)

# ==============================================================================
# SINK CATALOGS
# ==============================================================================
# K_cli: CLI command execution transfer
# Dung (?<![\w/-]) thay \b de "nc" khong khop trong duong dan hay ten co gach.
CLI_SINK_PATTERN = re.compile(
    r"(?<![\w/-])(curl|wget|nc|ncat|socat|scp|rsync)(?![\w-])"
)

# K_raw: raw socket egress (tap con cua CLI_SINK_PATTERN, dung de phan loai)
RAW_SOCKET_CMDS = {"nc", "ncat", "socat", "telnet"}

# ---------------------------------------------------------------------------
# Ho FILE TRANSFER: payload cua chung la DUONG DAN FILE, khong phai chuoi
# trong argv. Phai doi chieu voi FileTaintState chu khong tim bien.
# ---------------------------------------------------------------------------
FILE_TRANSFER_PATTERN = re.compile(
    r"(?<![\w/-])(scp|rsync|azcopy)(?![\w-])"
    r"|(aws\s+s3\s+(?:cp|sync|mv))"
    r"|(gsutil\s+(?:cp|rsync|mv))"
    r"|(gh\s+release\s+upload)"
    r"|(?<![\w/-])(curl)(?=[^;&|]*\s(?:-T|--upload-file)\s)"
)

# Token o vi tri DICH DEN cua lenh file-transfer (khong phai file nguon).
REMOTE_TARGET_PATTERN = re.compile(
    r"://|^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+:|^s3://|^gs://"
)

# K_scm: publish du lieu ra ngoai runner qua source control / object store.
# Khac K_cli o cho du lieu di qua FILE chu khong qua argv.
# SNK-05 chi gom SCM that su. aws s3 / gh release / gsutil / azcopy la
# chuyen file tu xa -> thuoc SNK-07 (K_file), khong phai SCM.
SCM_SINK_PATTERN = re.compile(r"(git\s+push)")

GIT_ADD_PATTERN = re.compile(r"\bgit\s+add\s+([^;&|]+)")
GIT_COMMIT_ALL_PATTERN = re.compile(r"\bgit\s+commit\b[^;&|]*?\s-{1,2}[a-z]*a[a-z]*\b")

# T_3 mo rong: ghi vao kenh truyen taint giua cac step.
GITHUB_CHANNEL_WRITE_PATTERN = re.compile(
    r"""echo\s+["']?([A-Za-z_][A-Za-z0-9_-]*)=(.*?)["']?\s*>>\s*"?\$\{?GITHUB_(ENV|OUTPUT)\}?"?"""
)

# Ghi du lieu xuong file -> file mang taint.
REDIRECT_PATTERN = re.compile(r"(?:^|\s)\d?>{1,2}\s*([^\s;&|<>]+)")
TEE_PATTERN = re.compile(r"\|\s*tee\s+(?:-a\s+)?([^\s;&|]+)")

# K_artifact: upload artifact cua CI. Artifact KHONG duoc GitHub mask, nen
# secret nam trong file se lo nguyen van.
ARTIFACT_ACTIONS = ("actions/upload-artifact",)

# K_dns: DNS query exfiltration
# `host` phai di kem doi so giong hostname, neu khong \bhost\b se khop moi tu
# "host" trong cau lenh binh thuong (vd: "--host", "the host is down").
DNS_SINK_PATTERN = re.compile(
    r"(?<![\w/-])(dig|nslookup)(?![\w-])"
    r"|(?<![\w/-])(host)(?![\w-])(?=\s+[\w.$-]+\.)"
)

# K_lib / K_dns (Python)
PYTHON_SINK_PATTERN = re.compile(
    r"\b(requests\.(?:post|get|put|patch|delete|request)|urllib\.request|http\.client|httpx\.(?:post|get|put|patch|delete|request)|aiohttp|socket\.gethostbyname)\b"
)

# K_lib (Node.js)
NODEJS_SINK_PATTERN = re.compile(
    r"\b(axios\.(?:post|get|put|request)|fetch|http\.request|https\.request|got\.(?:post|get)|needle\.(?:post|get))\b"
)

# ==============================================================================
# ALLOWLIST DOMAINS
# ==============================================================================
ALLOWLISTED_DOMAINS = {
    "api.github.com", "uploads.github.com", "github.com",
    "pypi.org", "files.pythonhosted.org", "registry.npmjs.org",
    "ghcr.io", "localhost", "127.0.0.1", "vault.internal", "company.com"
}

# ==============================================================================
# RULE ID CATALOG MAPPINGS
# ==============================================================================

SOURCE_RULE_IDS = {
    "S_ctx": "RULE-SRC-01 (Context Secrets / GitHub Token)",
    "S_dyn": "RULE-SRC-02 (Dynamic / Cloud IMDS Credentials)",
    "S_prog": "RULE-SRC-03 (Programmatic Env Variable Access)",
    "S_env": "RULE-SRC-04 (Workflow Environment Binding)",
    "S_inp": "RULE-SRC-05 (Untrusted Workflow Trigger Inputs)",
}

SINK_RULE_IDS = {
    "K_cli": "RULE-SNK-01 (CLI Network Transfer Utility)",
    "K_dns": "RULE-SNK-02 (DNS Exfiltration Channel)",
    "K_lib": "RULE-SNK-03 (HTTP/Socket Client Library)",
    "K_raw": "RULE-SNK-04 (Raw Network Socket Egress)",
    "K_scm": "RULE-SNK-05 (SCM Push / Insecure Commit)",
    "K_artifact": "RULE-SNK-06 (CI Artifact Upload)",
    "K_file": "RULE-SNK-07 (Remote File Transfer)",
}


def get_source_rule_id(category: str) -> str:
  return SOURCE_RULE_IDS.get(category, "RULE-SRC-UNKNOWN")


def get_sink_rule_id(category: str) -> str:
  return SINK_RULE_IDS.get(category, "RULE-SNK-UNKNOWN")