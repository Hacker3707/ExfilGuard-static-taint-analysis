from dataclasses import dataclass


# =========================
# Source Sensitivity
# =========================

SOURCE_WEIGHTS = {
    "S_ctx": 3.0,    # ${{ secrets.* }}
    "S_dyn": 3.0,    # IMDS / dynamic cloud credentials
    "S_env": 2.0,    # environment credentials
    "S_lang": 2.0,   # programmatic environment keys
    "S_inp": 1.0,    # workflow inputs
}


# =========================
# Sink Capability
# =========================

SINK_WEIGHTS = {
    "K_cli": 3.0,    # curl, nc, etc.
    "K_raw": 3.0,    # raw sockets
    "K_dns": 3.0,    # DNS exfiltration
    "K_lib": 2.5,    # requests, urllib, httpx, ...
    "K_scm": 1.5,    # SCM push
}


# =========================
# Destination
# =========================

DESTINATION_MULTIPLIERS = {
    "untrusted_external": 1.2,
    "external": 1.0,
    "allowlisted": 0.4,
}


@dataclass
class RiskResult:
    score: float
    level: str
    source_weight: float
    sink_weight: float
    destination_multiplier: float


def calculate_risk(
    source_category: str,
    sink_category: str,
    destination_type: str
) -> RiskResult:

    # Get weights
    w_src = SOURCE_WEIGHTS.get(source_category, 1.0)
    w_snk = SINK_WEIGHTS.get(sink_category, 1.0)
    m_dst = DESTINATION_MULTIPLIERS.get(
        destination_type,
        1.0
    )

    # R(P) = min(10, (Wsrc × Wsnk) × Mdst)
    score = min(
        10.0,
        (w_src * w_snk) * m_dst
    )

    # Risk classification
    if score >= 8.0:
        level = "CRITICAL"
    elif score >= 6.0:
        level = "HIGH"
    elif score >= 4.0:
        level = "MEDIUM"
    else:
        level = "LOW"

    return RiskResult(
        score=round(score, 1),
        level=level,
        source_weight=w_src,
        sink_weight=w_snk,
        destination_multiplier=m_dst,
    )