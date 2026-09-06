import re
from catalogs import NODEJS_SINK_PATTERN, NODEJS_ENV_PATTERNS, SECRET_PATTERN
from engine.common import classify_source, classify_destination, calculate_risk
from engine.models import DetectionResult

class NodejsAnalyzer:
    def analyze(self, lines, tainted_env, context_name="nodejs"):
        tainted = tainted_env.copy()
        detections = []

        statements = []
        for l in lines:
            statements.extend([s.strip() for s in re.split(r";(?=(?:[^'\"]|'[^']*'|\"[^\"]*\")*$)", l) if s.strip()])

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
                elif env_match:
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
                direct_sec = SECRET_PATTERN.search(stmt)
                culprit_ref = None
                for ident in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", stmt):
                    if ident in tainted:
                        culprit_ref = ident
                        break

                if culprit_ref or direct_sec:
                    full_path = tainted[culprit_ref]["Path"] + [sink_cmd] if culprit_ref else [direct_sec.group(), sink_cmd]
                    src_val = tainted[culprit_ref]["Source"] if culprit_ref else direct_sec.group()
                    s_cat = classify_source(src_val)
                    k_cat = "K_lib"
                    d_type = classify_destination(stmt)
                    score, level = calculate_risk(s_cat, k_cat, d_type)

                    detections.append(DetectionResult(
                        source=src_val, source_category=s_cat, sink=sink_cmd,
                        sink_category=k_cat, destination_type=d_type, risk_score=score,
                        risk_level=level, command=stmt, context=context_name, path=full_path
                    ))

        return tainted, detections