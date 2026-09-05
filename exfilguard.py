import yaml
import sys
import os
import re
from risk_scoring import calculate_risk

# ==============================================================================
# PATTERNS & CATALOG DEFINITIONS (Section 3.3, 3.4)
# ==============================================================================
SECRET_PATTERN = re.compile(r"\$\{\{\s*(?:secrets\.[A-Za-z0-9_]+|github\.token)\s*\}\}")
# Mở rộng regex để bắt cả positional argument $1, $2 trong bash script
VAR_REF_PATTERN = re.compile(r"\$(?:\{([A-Za-z0-9_]+)\}|([A-Za-z0-9_]+))")
CLI_SINK_PATTERN = re.compile(r"\b(curl|wget|nc|ncat|socat|dig|nslookup)\b")

ALLOWLISTED_DOMAINS = {
    "api.github.com",
    "uploads.github.com",
    "github.com",

    # Package / artifact services
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",

    # Common CI/CD services
    "ghcr.io",

    # Local / internal destinations
    "localhost",
    "127.0.0.1",
    "vault.internal",
    "company.com",
}

def get_source_category(source):
    if source.startswith("${{ secrets."):
        return "S_ctx"

    if source == "${{ github.token }}":
        return "S_ctx"

    return "S_inp"


def get_sink_category(sink):
    if sink in ["curl", "wget", "nc", "ncat", "socat"]:
        return "K_cli"

    if sink in ["dig", "nslookup"]:
        return "K_dns"

    return "K_cli"


def get_destination_type(line):
    urls = re.findall(
        r"https?://([^/\s\"']+)",
        line
    )

    if not urls:
        return "untrusted_external"

    hostname = urls[0].lower()

    # Remove optional port
    hostname = hostname.split(":")[0]

    for domain in ALLOWLISTED_DOMAINS:
        domain = domain.lower()

        # Exact match
        if hostname == domain:
            return "allowlisted"

        # Valid subdomain
        if hostname.endswith("." + domain):
            return "allowlisted"

    return "untrusted_external"


def get_secret_source(value):
    if not isinstance(value, str):
        return None
    match = SECRET_PATTERN.search(value)
    return match.group() if match else None

def find_variable_references(text):
    matches = VAR_REF_PATTERN.findall(text)
    refs = set()
    for m in matches:
        var = m[0] or m[1]
        if var:
            refs.add(var)
    return refs

def get_logical_lines(script_content):
    lines = script_content.splitlines()
    logical_lines = []
    current_line = ""

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if current_line:
            current_line += " " + line
        else:
            current_line = line

        if current_line.endswith("\\"):
            current_line = current_line[:-1].strip()
        else:
            logical_lines.append(current_line)
            current_line = ""

    if current_line:
        logical_lines.append(current_line)
    return logical_lines

# ==============================================================================
# CORE PROPAGATION ENGINE (YAML & BASH SCRIPTS)
# ==============================================================================
def analyze_shell_commands(lines, tainted_env, context_name="inline"):
    """
    Theo dõi lan truyền biến trong các dòng lệnh Shell (hỗ trợ cả inline run và file .sh ngoài)
    """
    tainted = tainted_env.copy()
    detections = []

    for line in lines:
        # 1. Lan truyền qua gán biến (Rule T_1, T_2): var=expr hoặc var=$(echo $sec | base64)
        assignment = re.match(r"([A-Za-z_][A-Za-z0-9_]*)=(.*)", line)
        if assignment:
            variable = assignment.group(1)
            expression = assignment.group(2)
            refs = find_variable_references(expression)

            # Kiểm tra nếu vế phải nhận trực tiếp secret ${{ secrets.* }}
            direct_sec = get_secret_source(expression)
            if direct_sec:
                tainted[variable] = {
                    "Source": direct_sec,
                    "Path": [direct_sec, f"{context_name}.{variable}"]
                }
            else:
                for ref in refs:
                    if ref in tainted:
                        tainted[variable] = {
                            "Source": tainted[ref]["Source"],
                            "Path": tainted[ref]["Path"] + [f"{context_name}.{variable}"]
                        }
                        break

        # 2. Kiểm tra Dangerous Sink (Rule T_4: CLI Sink Invocation)
        sink_match = CLI_SINK_PATTERN.search(line)
        if sink_match:
            sink_cmd = sink_match.group(1)
            refs = find_variable_references(line)
            direct_sec = get_secret_source(line)

            culprit_ref = None
            for ref in refs:
                if ref in tainted:
                    culprit_ref = ref
                    break

            if culprit_ref or direct_sec:
                # Kiểm tra cờ egress payload (-d, -H, URL)
                is_egress = bool(
                    re.search(r"(-d|--data|--data-raw|--data-binary|-F|--form|-H|--header|-u|--user)\s+", line)
                    or re.search(r"https?://", line)
                    or sink_cmd in ["dig", "nslookup"]
                )

                if is_egress:

                    if culprit_ref:
                        full_path = tainted[culprit_ref]["Path"] + [sink_cmd]
                        src_val = tainted[culprit_ref]["Source"]
                    elif direct_sec:
                        full_path = [direct_sec, sink_cmd]
                        src_val = direct_sec
                    else:
                        # Không có source hợp lệ thì bỏ qua
                        continue

                    # ==========================================================
                    # RISK SCORING
                    # ==========================================================

                    source_category = get_source_category(src_val)
                    sink_category = get_sink_category(sink_cmd)
                    destination_type = get_destination_type(line)

                    risk = calculate_risk(
                        source_category=source_category,
                        sink_category=sink_category,
                        destination_type=destination_type
                    )

                    detections.append({
                        "Sink": sink_cmd,
                        "Command": line,
                        "Source": src_val,
                        "Path": full_path,
                        "Context": context_name,

                        "Source_Category": source_category,
                        "Sink_Category": sink_category,
                        "Destination_Type": destination_type,

                        "Risk_Score": risk.score,
                        "Risk_Level": risk.level
                    })

    return tainted, detections

# ==============================================================================
# DISPATCHER: WORKFLOW & EXTERNAL SCRIPT EXTRACTION (Rule T_3, T_5)
# ==============================================================================
def analyze_workflow(file_path):
    if not os.path.exists(file_path):
        return []

    with open(file_path, "r", encoding="utf-8") as f:
        try:
            workflow = yaml.safe_load(f)
        except Exception:
            return []

    jobs = workflow.get("jobs", {}) if isinstance(workflow, dict) else {}
    all_detections = []

    for job_name, job in jobs.items():
        job_tainted = {}
        # Rule T_3: Job-level Env
        for var, val in job.get("env", {}).items():
            src = get_secret_source(str(val))
            if src:
                job_tainted[var] = {"Source": src, "Path": [src, f"job.env.{var}"]}

        for step_idx, step in enumerate(job.get("steps", []), start=1):
            if not isinstance(step, dict):
                print(
                    f"[WARNING] Invalid step format "
                    f"in job '{job_name}', step {step_idx}"
                )
                continue

            step_tainted = job_tainted.copy()
            # Rule T_3: Step-level Env
            for var, val in step.get("env", {}).items():
                src = get_secret_source(str(val))
                if src:
                    step_tainted[var] = {"Source": src, "Path": [src, f"step.{step_idx}.env.{var}"]}

            run_script = step.get("run")
            if not run_script:
                continue

            lines = get_logical_lines(run_script)

            # Phân tích lệnh shell inline
            step_tainted, step_detections = analyze_shell_commands(
                lines, step_tainted, context_name=f"step_{step_idx}"
            )
            all_detections.extend(step_detections)

            # MỐC 1: Bắt lệnh gọi external Bash script (ví dụ: bash scripts/s03_01.sh "$API_KEY")
            for line in lines:
                script_call_match = re.search(r"(?:bash|sh|\./)\s*([^\s;&|]+\.sh)(.*)", line)
                if script_call_match:
                    sh_file = script_call_match.group(1).strip()
                    sh_args = script_call_match.group(2).strip()

                    # Chuẩn hóa đường dẫn file .sh
                    target_sh_path = sh_file if os.path.exists(sh_file) else os.path.join("scripts", os.path.basename(sh_file))

                    if os.path.exists(target_sh_path):
                        with open(target_sh_path, "r", encoding="utf-8", errors="ignore") as sf:
                            sh_lines = get_logical_lines(sf.read())

                        sh_tainted = step_tainted.copy()

                        # Rule T_5: Handoff đối số CLI vào biến $1, $2... trong script ngoài
                        passed_refs = find_variable_references(sh_args)
                        for ref in passed_refs:
                            if ref in step_tainted:
                                sh_tainted["1"] = {
                                    "Source": step_tainted[ref]["Source"],
                                    "Path": step_tainted[ref]["Path"] + [f"{os.path.basename(target_sh_path)}.$1"]
                                }
                                break

                        _, sh_detections = analyze_shell_commands(
                            sh_lines, sh_tainted, context_name=os.path.basename(target_sh_path)
                        )
                        all_detections.extend(sh_detections)

    return all_detections

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python exfilguard.py <path_to_workflow.yml>")
        sys.exit(1)

    results = analyze_workflow(sys.argv[1])
    if results:
        print("\n[ALERT] Potential Secret Exfiltration Detected!")
        print("=" * 60)

        for d in results:
            print(f"Context              : {d['Context']}")
            print(f"Source               : {d['Source']}")
            print(f"Source Category      : {d['Source_Category']}")
            print(f"Sink                 : {d['Sink']}")
            print(f"Sink Category        : {d['Sink_Category']}")
            print(f"Destination Type     : {d['Destination_Type']}")
            print(f"Risk Score           : {d['Risk_Score']} / 10")
            print(f"Risk Level           : {d['Risk_Level']}")
            print(f"Command              : {d['Command']}")
            print(f"Path                 : {' -> '.join(d['Path'])}")
            print("-" * 60)
    else:
        print("\n[PASS] No secret exfiltration flow detected (BENIGN).")