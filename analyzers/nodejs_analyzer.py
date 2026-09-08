import re
from catalogs import NODEJS_SINK_PATTERN, NODEJS_ENV_PATTERNS, SECRET_PATTERN
from engine.common import classify_source, classify_destination, calculate_risk
from engine.common import is_credential_lexical
from engine.models import DetectionResult
from engine.arg_roles import (
    split_statements,
    call_payload_blob,
    split_call_args,
    classify_destination_roles,
    JS_PAYLOAD_KEYS,
)

class NodejsAnalyzer:
    def __init__(self, lexical_env_source=False):
        """lexical_env_source: bat SRC-04/SRC-05 (khop ten bien voi
        TOKEN/SECRET/KEY/PASS/...). Tat mac dinh vi no coi CACHE_KEY,
        SORT_KEY, PRIMARY_KEY la nhay cam."""
        self.lexical_env_source = lexical_env_source

    def analyze(self, lines, tainted_env, context_name="nodejs"):
        tainted = tainted_env.copy()
        detections = []

        statements = []
        for l in lines:
            statements.extend(split_statements(l))

        for stmt in statements:
            # 1. Assignment: const/let/var x = ...
            assign = re.match(r"^(?:const|let|var)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)", stmt)
            if assign:
                var, expr = assign.group(1), assign.group(2)
                sec_match = SECRET_PATTERN.search(expr)
                env_match = None
                for pat in NODEJS_ENV_PATTERNS:
                    m = pat.search(expr)
                    if m:
                        env_match = m.group(1)
                        break

                if sec_match:
                    tainted[var] = {"Source": sec_match.group(), "Path": [sec_match.group(), f"{context_name}.{var}"]}
                elif env_match and env_match in tainted:
                    # RULE T_3: ke thua taint tu bien env da tainted o YAML.
                    info = tainted[env_match]
                    tainted[var] = {
                        "Source": info["Source"],
                        "Path": info["Path"] + [f"{context_name}.{var}"],
                    }
                elif env_match and self.lexical_env_source and is_credential_lexical(env_match):
                    # SRC-05: ten bien khop lexical qualifier. Tat mac dinh.
                    src = f"process.env.{env_match}"
                    tainted[var] = {"Source": src, "Path": [src, f"{context_name}.{var}"]}
                else:
                    for ident in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", expr):
                        if ident in tainted:
                            tainted[var] = {"Source": tainted[ident]["Source"], "Path": tainted[ident]["Path"] + [f"{context_name}.{var}"]}
                            break

            # 2. Sink check: axios, fetch, http...
            sink_match = NODEJS_SINK_PATTERN.search(stmt)
            if sink_match:
                sink_cmd = sink_match.group(1)

                call_text = stmt[sink_match.start():]
                payload_blob = call_payload_blob(call_text, JS_PAYLOAD_KEYS)

                direct_sec = SECRET_PATTERN.search(payload_blob)
                culprit_ref = None
                for ident in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", payload_blob):
                    if ident in tainted:
                        culprit_ref = ident
                        break

                if culprit_ref or direct_sec:
                    full_path = tainted[culprit_ref]["Path"] + [sink_cmd] if culprit_ref else [direct_sec.group(), sink_cmd]
                    src_val = tainted[culprit_ref]["Source"] if culprit_ref else direct_sec.group()
                    s_cat = classify_source(src_val)
                    k_cat = "K_lib"
                    positional, _ = split_call_args(call_text)
                    d_type = classify_destination_roles(positional[:1], tainted)
                    score, level = calculate_risk(s_cat, k_cat, d_type)

                    detections.append(DetectionResult(
                        source=src_val, source_category=s_cat, sink=sink_cmd,
                        sink_category=k_cat, destination_type=d_type, risk_score=score,
                        risk_level=level, command=stmt, context=context_name, path=full_path
                    ))

        return tainted, detections