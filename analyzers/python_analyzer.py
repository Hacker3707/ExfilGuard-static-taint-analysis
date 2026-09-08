import re
from catalogs import PYTHON_SINK_PATTERN, PYTHON_ENV_PATTERNS, SECRET_PATTERN
from engine.common import classify_source, classify_sink, classify_destination, calculate_risk
from engine.common import is_credential_lexical
from engine.models import DetectionResult
from engine.arg_roles import (
    split_statements,
    call_payload_blob,
    split_call_args,
    classify_destination_roles,
    PY_PAYLOAD_KWARGS,
)

class PythonAnalyzer:
    def __init__(self, lexical_env_source=False):
        """lexical_env_source: bat SRC-04 (khop ten bien voi
        TOKEN/SECRET/KEY/PASS/...). Tat mac dinh vi bat len se coi
        CACHE_KEY, SORT_KEY, PRIMARY_KEY la nhay cam."""
        self.lexical_env_source = lexical_env_source

    def analyze(self, lines, tainted_env, context_name="python"):
        tainted = tainted_env.copy()
        detections = []

        # Tách logical statements qua dấu chấm phẩy
        statements = []
        for l in lines:
            statements.extend(split_statements(l))

        for stmt in statements:
            # 1. Assignment tracking
            assign = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)", stmt)
            if assign:
                var, expr = assign.group(1), assign.group(2)
                sec_match = SECRET_PATTERN.search(expr)
                env_match = None
                for pat in PYTHON_ENV_PATTERNS:
                    m = pat.search(expr)
                    if m:
                        env_match = m.group(1)
                        break

                if sec_match:
                    tainted[var] = {"Source": sec_match.group(), "Path": [sec_match.group(), f"{context_name}.{var}"]}
                elif env_match and env_match in tainted:
                    # RULE T_3: bien env DA tainted tu YAML -> ke thua nguyen
                    # Source goc (S_ctx), khong tao nguon moi.
                    #
                    # Truoc day nhanh nay tao thang "os.getenv(X)" -> S_prog,
                    # gay HAI loi cung luc:
                    #   - under-classify: secret that bi cham 2.0 thay vi 3.0
                    #   - over-taint: os.getenv("HOME") cung thanh nguon
                    info = tainted[env_match]
                    tainted[var] = {
                        "Source": info["Source"],
                        "Path": info["Path"] + [f"{context_name}.{var}"],
                    }
                elif env_match and self.lexical_env_source and is_credential_lexical(env_match):
                    # SRC-04: ten bien khop lexical qualifier (TOKEN/KEY/PASS...).
                    # Tat mac dinh - xem ExfilGuardConfig.enable_lexical_source.
                    src = f"os.getenv({env_match})"
                    tainted[var] = {"Source": src, "Path": [src, f"{context_name}.{var}"]}
                else:
                    for ident in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", expr):
                        if ident in tainted:
                            tainted[var] = {"Source": tainted[ident]["Source"], "Path": tainted[ident]["Path"] + [f"{context_name}.{var}"]}
                            break

            # 2. Sink check
            sink_match = PYTHON_SINK_PATTERN.search(stmt)
            if sink_match:
                sink_cmd = sink_match.group(1)

                # Chi xet phan MANG DU LIEU cua loi goi. Ban cu quet ca stmt
                # nen bien tainted o vi tri URL cung bi tinh la exfil.
                call_text = stmt[sink_match.start():]
                payload_blob = call_payload_blob(call_text, PY_PAYLOAD_KWARGS)
                if "socket." in sink_cmd:
                    payload_blob = call_text

                direct_sec = SECRET_PATTERN.search(payload_blob)
                culprit_ref = None
                for ident in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", payload_blob):
                    if ident in tainted:
                        culprit_ref = ident
                        break

                if culprit_ref or direct_sec:
                    if culprit_ref:
                        full_path = tainted[culprit_ref]["Path"] + [sink_cmd]
                        src_val = tainted[culprit_ref]["Source"]
                    else:
                        full_path = [direct_sec.group(), sink_cmd]
                        src_val = direct_sec.group()

                    s_cat = classify_source(src_val)
                    k_cat = "K_dns" if "socket." in sink_cmd else "K_lib"
                    positional, _ = split_call_args(call_text)
                    d_type = classify_destination_roles(positional[:1], tainted)
                    score, level = calculate_risk(s_cat, k_cat, d_type)

                    detections.append(DetectionResult(
                        source=src_val, source_category=s_cat, sink=sink_cmd,
                        sink_category=k_cat, destination_type=d_type, risk_score=score,
                        risk_level=level, command=stmt, context=context_name, path=full_path
                    ))

        return tainted, detections