import re
from catalogs import CLI_SINK_PATTERN, DNS_SINK_PATTERN, VAR_REF_PATTERN, SECRET_PATTERN
from engine.common import classify_source, classify_sink, classify_destination, calculate_risk
from engine.models import DetectionResult

class BashAnalyzer:
    def analyze(self, lines, tainted_env, context_name="bash"):
        tainted = tainted_env.copy()
        detections = []

        for line in lines:
            line_str = line.strip()
            # 1. Variable Assignment tracking: VAR=...
            assignment = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)", line_str)
            if assignment:
                var, expr = assignment.group(1), assignment.group(2)
                sec_match = SECRET_PATTERN.search(expr)
                if sec_match:
                    tainted[var] = {"Source": sec_match.group(), "Path": [sec_match.group(), f"{context_name}.{var}"]}
                else:
                    for ref in VAR_REF_PATTERN.findall(expr):
                        r = ref[0] or ref[1]
                        if r in tainted:
                            tainted[var] = {"Source": tainted[r]["Source"], "Path": tainted[r]["Path"] + [f"{context_name}.{var}"]}
                            break

            # 2. Sink check: curl, wget, nc, dig...
            sink_match = CLI_SINK_PATTERN.search(line_str) or DNS_SINK_PATTERN.search(line_str)
            if sink_match:
                sink_cmd = sink_match.group(1)
                direct_sec = SECRET_PATTERN.search(line_str)
                culprit_ref = None
                for ref in VAR_REF_PATTERN.findall(line_str):
                    r = ref[0] or ref[1]
                    if r in tainted:
                        culprit_ref = r
                        break

                if culprit_ref or direct_sec:
                    is_egress = bool(
                        re.search(r"(-d|--data|--data-raw|-F|--form|-H|--header|-u|--user)\s+", line_str)
                        or re.search(r"https?://", line_str) or sink_cmd in ["dig", "nslookup", "nc"]
                    )
                    if not is_egress:
                        continue

                    if culprit_ref:
                        full_path = tainted[culprit_ref]["Path"] + [sink_cmd]
                        src_val = tainted[culprit_ref]["Source"]
                    else:
                        full_path = [direct_sec.group(), sink_cmd]
                        src_val = direct_sec.group()

                    s_cat = classify_source(src_val)
                    k_cat = classify_sink(sink_cmd)
                    d_type = classify_destination(line_str)
                    score, level = calculate_risk(s_cat, k_cat, d_type)

                    detections.append(DetectionResult(
                        source=src_val, source_category=s_cat, sink=sink_cmd,
                        sink_category=k_cat, destination_type=d_type, risk_score=score,
                        risk_level=level, command=line_str, context=context_name, path=full_path
                    ))

        return tainted, detections