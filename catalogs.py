import re

# ==============================================================================
# SOURCE IDENTIFIERS & REGEX
# ==============================================================================
# S_ctx: Context secrets (GitHub secrets, tokens)
SECRET_PATTERN = re.compile(
    r"\$\{\{\s*(?:secrets\.[A-Za-z0-9_]+|github\.token)\s*\}\}"
)

# S_inp: Workflow inputs
INPUT_PATTERN = re.compile(
    r"\$\{\{\s*inputs\.[A-Za-z0-9_]+\s*\}\}"
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

VAR_REF_PATTERN = re.compile(
    r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*|\d+)\}|([A-Za-z_][A-Za-z0-9_]*|\d+))"
)

# ==============================================================================
# SINK CATALOGS
# ==============================================================================
# K_cli: CLI command execution transfer
CLI_SINK_PATTERN = re.compile(r"\b(curl|wget|nc|ncat|socat|scp|rsync)\b")

# K_dns: DNS query exfiltration
DNS_SINK_PATTERN = re.compile(r"\b(dig|nslookup|host)\b")

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
}


def get_source_rule_id(category: str) -> str:
  return SOURCE_RULE_IDS.get(category, "RULE-SRC-UNKNOWN")


def get_sink_rule_id(category: str) -> str:
  return SINK_RULE_IDS.get(category, "RULE-SNK-UNKNOWN")