import yaml
import sys
import os
import re
from risk_scoring import calculate_risk

# ==============================================================================
# PATTERNS & CATALOG DEFINITIONS (Section 3.3, 3.4)
# ==============================================================================

SECRET_PATTERN = re.compile(
    r"\$\{\{\s*(?:secrets\.[A-Za-z0-9_]+|github\.token)\s*\}\}"
)

# Bash variable references: $VAR, ${VAR}, $1, $2, ...
VAR_REF_PATTERN = re.compile(
    r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*|\d+)\}|([A-Za-z_][A-Za-z0-9_]*|\d+))"
)

CLI_SINK_PATTERN = re.compile(
    r"\b(curl|wget|nc|ncat|socat|dig|nslookup)\b"
)

PYTHON_GETENV_PATTERN = re.compile(
    r"""\bos\.getenv\s*\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*\)"""
)

PYTHON_ENVIRON_GET_PATTERN = re.compile(
    r"""\bos\.environ\.get\s*\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*\)"""
)

PYTHON_ENVIRON_INDEX_PATTERN = re.compile(
    r"""\bos\.environ\s*\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*\]"""
)

# ==============================================================================
# PYTHON SINK CATALOG
# ==============================================================================

PYTHON_SINK_PATTERN = re.compile(
     r"""
    \b(
        requests\.(?:post|get|put|patch|delete|request)
        |
        urllib\.request
        |
        http\.client
        |
        httpx\.(?:post|get|put|patch|delete|request)
        |
        aiohttp
        |
        socket\.gethostbyname
    )
    """,
    re.VERBOSE
)

PYTHON_IMPORT_PATTERN = re.compile(
    r"^\s*(?:import|from)\s+"
)


# ==============================================================================
# ALLOWLIST
# ==============================================================================

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

def get_python_env_name(expression):

    patterns = [
        PYTHON_GETENV_PATTERN,
        PYTHON_ENVIRON_GET_PATTERN,
        PYTHON_ENVIRON_INDEX_PATTERN
    ]

    for pattern in patterns:

        match = pattern.search(expression)

        if match:
            return match.group(1)

    return None


# ==============================================================================
# SOURCE / SINK / DESTINATION CLASSIFICATION
# ==============================================================================

def get_source_category(source):

    if source.startswith("${{ secrets."):
        return "S_ctx"

    if source == "${{ github.token }}":
        return "S_ctx"

    if source.startswith("os.getenv("):
        return "S_prog"

    if source.startswith("os.environ"):
        return "S_prog"

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


# ==============================================================================
# SECRET DETECTION
# ==============================================================================

def get_secret_source(value):
    if not isinstance(value, str):
        return None

    match = SECRET_PATTERN.search(value)

    return match.group() if match else None


# ==============================================================================
# PYTHON STATEMENT SPLITTING
# ==============================================================================

def split_python_statements(line):
    """
    Split simple Python -c statements separated by ';'.

    Example:

        key = secret; data = key; requests.post(...)

    becomes:

        [
            "key = secret",
            "data = key",
            "requests.post(...)"
        ]

    This MVP splitter is intended for simple python -c benchmark cases.
    """

    statements = re.split(
        r";(?=(?:[^'\"]|'[^']*'|\"[^\"]*\")*$)",
        line
    )

    return [
        statement.strip()
        for statement in statements
        if statement.strip()
    ]


# ==============================================================================
# BASH VARIABLE REFERENCES
# ==============================================================================

def find_variable_references(text):
    matches = VAR_REF_PATTERN.findall(text)

    refs = set()

    for m in matches:
        var = m[0] or m[1]

        if var:
            refs.add(var)

    return refs


# ==============================================================================
# PYTHON VARIABLE REFERENCES
# ==============================================================================

def find_python_variable_references(text):
    """
    Find Python identifiers appearing in an expression / statement.

    Example:

        data = key

    returns:

        {"data", "key"}

    Example:

        requests.post(url, data=data)

    returns identifiers such as:

        {"requests", "post", "url", "data"}
    """

    matches = re.findall(
        r"\b[A-Za-z_][A-Za-z0-9_]*\b",
        text
    )

    return set(matches)


# ==============================================================================
# YAML / SHELL LOGICAL LINES
# ==============================================================================

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
# CORE PROPAGATION ENGINE
# BASH / SHELL ANALYSIS
# ==============================================================================

def analyze_shell_commands(lines, tainted_env, context_name="inline"):
    """
    Theo dõi lan truyền biến trong các dòng lệnh Shell.

    Supports:
    - Inline run
    - External .sh
    - Variable assignment
    - CLI sinks
    - Positional arguments
    """

    tainted = tainted_env.copy()

    detections = []

    for line in lines:

        # ==============================================================
        # 1. Variable assignment
        # ==============================================================

        assignment = re.match(
            r"([A-Za-z_][A-Za-z0-9_]*)=(.*)",
            line
        )

        if assignment:

            variable = assignment.group(1)

            expression = assignment.group(2)

            refs = find_variable_references(expression)

            direct_sec = get_secret_source(expression)

            # Direct secret assignment
            if direct_sec:

                tainted[variable] = {
                    "Source": direct_sec,
                    "Path": [
                        direct_sec,
                        f"{context_name}.{variable}"
                    ]
                }

            # Propagation from another tainted variable
            else:

                for ref in refs:

                    if ref in tainted:

                        tainted[variable] = {
                            "Source": tainted[ref]["Source"],
                            "Path": (
                                tainted[ref]["Path"]
                                + [f"{context_name}.{variable}"]
                            )
                        }

                        break

        # ==============================================================
        # 2. Dangerous CLI sink
        # ==============================================================

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

                # ======================================================
                # Determine whether this is an egress operation
                # ======================================================

                is_egress = bool(
                    re.search(
                        r"(-d|--data|--data-raw|--data-binary|-F|--form|-H|--header|-u|--user)\s+",
                        line
                    )
                    or re.search(
                        r"https?://",
                        line
                    )
                    or sink_cmd in ["dig", "nslookup"]
                )

                if is_egress:

                    # ==================================================
                    # Build explainable path
                    # ==================================================

                    if culprit_ref:

                        full_path = (
                            tainted[culprit_ref]["Path"]
                            + [sink_cmd]
                        )

                        src_val = tainted[culprit_ref]["Source"]

                    elif direct_sec:

                        full_path = [
                            direct_sec,
                            sink_cmd
                        ]

                        src_val = direct_sec

                    else:
                        continue

                    # ==================================================
                    # Risk scoring
                    # ==================================================

                    source_category = get_source_category(
                        src_val
                    )

                    sink_category = get_sink_category(
                        sink_cmd
                    )

                    destination_type = get_destination_type(
                        line
                    )

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
# PYTHON ANALYSIS
# ==============================================================================

def analyze_python_commands(
    lines,
    tainted_env,
    context_name="python"
):
    """
    Python analysis following:

        Source
           ↓
        Variable
           ↓
        Variable
           ↓
        Python HTTP Sink

    MVP supports:
    - python -c
    - simple assignments
    - propagation through variables
    - requests.*
    - urllib.request
    - http.client
    - httpx.*
    - aiohttp
    - semicolon-separated statements
    """

    tainted = tainted_env.copy()

    detections = []

    for raw_line in lines:

        # ==============================================================
        # Split multiple statements
        #
        # Example:
        #
        # import requests;
        # key = secret;
        # data = key;
        # requests.post(...)
        #
        # ==============================================================

        statements = split_python_statements(
            raw_line
        )

        # ==============================================================
        # IMPORTANT:
        # Process every statement sequentially.
        #
        # This is required for propagation:
        #
        # secret -> key -> data -> requests.post
        # ==============================================================

        for line in statements:

            if not line:
                continue

            # ==========================================================
            # 1. Variable assignment
            # ==========================================================

            assignment = re.match(
                r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)",
                line
            )

            if assignment:

                variable = assignment.group(1)

                expression = assignment.group(2)

                # ------------------------------------------------------
                # Direct secret
                #
                # key = "${{ secrets.API_KEY }}"
                # ------------------------------------------------------

                direct_sec = get_secret_source(
                    expression
                )

                env_name = get_python_env_name(
                    expression
                )

                if direct_sec:

                    tainted[variable] = {
                        "Source": direct_sec,
                        "Path": [
                            direct_sec,
                            f"{context_name}.{variable}"
                        ]
                    }

                elif env_name:

                    source = f"os.getenv({env_name})"

                    tainted[variable] = {
                        "Source": source,
                        "Path": [
                            source,
                            f"{context_name}.{variable}"
                        ]
                    }

                else:

                    refs = find_python_variable_references(
                        expression
                    )

                    for ref in refs:

                        if ref in tainted:
                            tainted[variable] = {
                                "Source": (
                                    tainted[ref]["Source"]
                                ),
                                "Path": (
                                        tainted[ref]["Path"]
                                        + [
                                            f"{context_name}.{variable}"
                                        ]
                                )
                            }

                            break

            # ==========================================================
            # 2. Python HTTP sink
            # ==========================================================

            sink_match = PYTHON_SINK_PATTERN.search(
                line
            )

            if not sink_match:
                continue

            sink = sink_match.group(1)

            # ----------------------------------------------------------
            # Find Python identifiers
            # ----------------------------------------------------------

            refs = find_python_variable_references(
                line
            )

            # ----------------------------------------------------------
            # Direct secret appearing in sink
            # ----------------------------------------------------------

            direct_sec = get_secret_source(
                line
            )

            culprit_ref = None

            for ref in refs:

                if ref in tainted:

                    culprit_ref = ref

                    break

            # No tainted source
            if not culprit_ref and not direct_sec:
                continue

            # ==========================================================
            # 3. Determine whether sink carries data
            # ==========================================================

            is_egress = bool(
                direct_sec
                or culprit_ref
                or re.search(
                    r"\b(?:data|json|headers|params|auth|content|body)\s*=",
                    line
                )
            )

            if not is_egress:
                continue

            # ==========================================================
            # 4. Build explainable path
            # ==========================================================

            if culprit_ref:

                full_path = (
                    tainted[culprit_ref]["Path"]
                    + [sink]
                )

                src_val = tainted[culprit_ref]["Source"]

            else:

                full_path = [
                    direct_sec,
                    sink
                ]

                src_val = direct_sec

            # ==========================================================
            # 5. Risk scoring
            # ==========================================================

            source_category = get_source_category(
                src_val
            )

            if sink.startswith("socket."):
                sink_category = "K_dns"
            else:
                sink_category = "K_lib"

            destination_type = get_destination_type(
                line
            )

            risk = calculate_risk(
                source_category=source_category,
                sink_category=sink_category,
                destination_type=destination_type
            )

            # ==========================================================
            # 6. Detection result
            # ==========================================================

            detections.append({

                "Sink": sink,

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
# PYTHON FILE RESOLUTION
# ==============================================================================

def resolve_python_file(script_path, workflow_path):
    """
    Resolve Python file referenced by a GitHub Actions run command.

    Supported:
    - python script.py
    - python3 script.py
    - python ./script.py
    - python scripts/script.py

    The file is resolved relative to the workflow directory.
    """

    workflow_dir = os.path.dirname(
        os.path.abspath(workflow_path)
    )

    # Remove surrounding quotes if present
    script_path = script_path.strip().strip("'\"")

    # Resolve relative to workflow directory
    target_path = os.path.join(
        workflow_dir,
        script_path
    )

    if os.path.isfile(target_path):
        return target_path

    # Fallback: current working directory
    if os.path.isfile(script_path):
        return os.path.abspath(script_path)

    return None

# ==============================================================================
# DISPATCHER
# WORKFLOW & EXTERNAL SCRIPT EXTRACTION
# ==============================================================================

def analyze_workflow(file_path):

    if not os.path.exists(file_path):
        return []

    with open(
        file_path,
        "r",
        encoding="utf-8"
    ) as f:

        try:
            workflow = yaml.safe_load(f)

        except Exception:
            return []

    jobs = (
        workflow.get("jobs", {})
        if isinstance(workflow, dict)
        else {}
    )

    all_detections = []

    # ==========================================================================
    # JOB
    # ==========================================================================

    for job_name, job in jobs.items():

        job_tainted = {}

        # ======================================================================
        # Job-level environment
        # ======================================================================

        for var, val in job.get("env", {}).items():

            src = get_secret_source(
                str(val)
            )

            if src:

                job_tainted[var] = {

                    "Source": src,

                    "Path": [
                        src,
                        f"job.env.{var}"
                    ]
                }

        # ======================================================================
        # STEPS
        # ======================================================================

        for step_idx, step in enumerate(
            job.get("steps", []),
            start=1
        ):

            if not isinstance(step, dict):

                print(
                    f"[WARNING] Invalid step format "
                    f"in job '{job_name}', step {step_idx}"
                )

                continue

            # ------------------------------------------------------------------
            # Start with job-level taint
            # ------------------------------------------------------------------

            step_tainted = job_tainted.copy()

            # ------------------------------------------------------------------
            # Step-level environment
            # ------------------------------------------------------------------

            for var, val in step.get(
                "env",
                {}
            ).items():

                src = get_secret_source(
                    str(val)
                )

                if src:

                    step_tainted[var] = {

                        "Source": src,

                        "Path": [
                            src,
                            f"step.{step_idx}.env.{var}"
                        ]
                    }

            # ------------------------------------------------------------------
            # run block
            # ------------------------------------------------------------------

            run_script = step.get("run")

            if not run_script:
                continue

            lines = get_logical_lines(
                run_script
            )

            # ==================================================================
            # BASH / SHELL ANALYSIS
            # ==================================================================

            step_tainted, step_detections = (
                analyze_shell_commands(
                    lines,
                    step_tainted,
                    context_name=f"step_{step_idx}"
                )
            )

            all_detections.extend(
                step_detections
            )

            # ==========================================================
            # PYTHON ANALYSIS
            # ==========================================================

            python_lines = []

            i = 0

            while i < len(lines):

                stripped = lines[i].strip()

                # ------------------------------------------------------
                # Detect python -c '...'
                # or python3 -c '...'
                # ------------------------------------------------------

                python_match = re.match(
                    r"\bpython(?:3)?\s+-c\s+(['\"])(.*)$",
                    stripped
                )

                if python_match:

                    quote = python_match.group(1)

                    python_code = python_match.group(2)

                    # --------------------------------------------------
                    # Python -c may span multiple YAML lines.
                    #
                    # Example:
                    #
                    # python -c 'import requests; key = secret;
                    # requests.post(..., data=key)'
                    #
                    # --------------------------------------------------

                    while not python_code.endswith(quote):

                        i += 1

                        if i >= len(lines):
                            break

                        python_code += " " + lines[i].strip()

                    # --------------------------------------------------
                    # Remove closing quote
                    # --------------------------------------------------

                    if python_code.endswith(quote):
                        python_code = python_code[:-1]

                    # --------------------------------------------------
                    # Split Python statements
                    # --------------------------------------------------

                    python_lines.extend(
                        split_python_statements(
                            python_code
                        )
                    )


                else:

                    # --------------------------------------------------

                    # Detect:

                    #

                    # python script.py

                    # python3 script.py

                    #

                    # --------------------------------------------------

                    python_match = re.match(

                        r"\bpython(?:3)?\s+([^\s;&|]+\.py)(.*)",

                        stripped

                    )

                    if python_match:

                        script_path = (

                            python_match.group(1)

                        )

                        python_file = resolve_python_file(

                            script_path,

                            file_path

                        )

                        if python_file:

                            try:

                                with open(

                                        python_file,

                                        "r",

                                        encoding="utf-8",

                                        errors="ignore"

                                ) as pf:

                                    python_source = pf.read()

                                # --------------------------------------------------

                                # Analyze the Python file using the same

                                # propagation engine used for python -c.

                                # --------------------------------------------------

                                _, file_detections = (

                                    analyze_python_commands(

                                        python_source.splitlines(),

                                        step_tainted,

                                        context_name=(

                                            f"step_{step_idx}."

                                            f"{os.path.basename(python_file)}"

                                        )

                                    )

                                )

                                all_detections.extend(

                                    file_detections

                                )


                            except OSError:

                                pass

                i += 1

            # ------------------------------------------------------------------
            # Run Python propagation engine
            # ------------------------------------------------------------------

            _, python_detections = (
                analyze_python_commands(
                    python_lines,
                    step_tainted,
                    context_name=f"step_{step_idx}.python"
                )
            )

            all_detections.extend(
                python_detections
            )

            # ==================================================================
            # EXTERNAL BASH SCRIPT
            # ==================================================================

            for line in lines:

                script_call_match = re.search(
                    r"(?:bash|sh|\./)\s*([^\s;&|]+\.sh)(.*)",
                    line
                )

                if script_call_match:

                    sh_file = (
                        script_call_match.group(1).strip()
                    )

                    sh_args = (
                        script_call_match.group(2).strip()
                    )

                    # ----------------------------------------------------------
                    # Normalize .sh path
                    # ----------------------------------------------------------

                    target_sh_path = (
                        sh_file
                        if os.path.exists(sh_file)
                        else os.path.join(
                            "scripts",
                            os.path.basename(sh_file)
                        )
                    )

                    if os.path.exists(
                        target_sh_path
                    ):

                        with open(
                            target_sh_path,
                            "r",
                            encoding="utf-8",
                            errors="ignore"
                        ) as sf:

                            sh_lines = get_logical_lines(
                                sf.read()
                            )

                        sh_tainted = (
                            step_tainted.copy()
                        )

                        # ------------------------------------------------------
                        # Rule T_5:
                        #
                        # CLI argument -> $1
                        # ------------------------------------------------------

                        passed_refs = (
                            find_variable_references(
                                sh_args
                            )
                        )

                        for ref in passed_refs:

                            if ref in step_tainted:

                                sh_tainted["1"] = {

                                    "Source": (
                                        step_tainted[ref]["Source"]
                                    ),

                                    "Path": (
                                        step_tainted[ref]["Path"]
                                        + [
                                            f"{os.path.basename(target_sh_path)}.$1"
                                        ]
                                    )
                                }

                                break

                        _, sh_detections = (
                            analyze_shell_commands(
                                sh_lines,
                                sh_tainted,
                                context_name=os.path.basename(
                                    target_sh_path
                                )
                            )
                        )

                        all_detections.extend(
                            sh_detections
                        )

    return all_detections


# ==============================================================================
# MAIN
# ==============================================================================

if __name__ == "__main__":

    if len(sys.argv) < 2:

        print(
            "Usage: python exfilguard.py <path_to_workflow.yml>"
        )

        sys.exit(1)

    results = analyze_workflow(
        sys.argv[1]
    )

    if results:

        print(
            "\n[ALERT] Potential Secret Exfiltration Detected!"
        )

        print(
            "=" * 60
        )

        for d in results:

            print(
                f"Context              : {d['Context']}"
            )

            print(
                f"Source               : {d['Source']}"
            )

            print(
                f"Source Category      : {d['Source_Category']}"
            )

            print(
                f"Sink                 : {d['Sink']}"
            )

            print(
                f"Sink Category        : {d['Sink_Category']}"
            )

            print(
                f"Destination Type     : {d['Destination_Type']}"
            )

            print(
                f"Risk Score           : {d['Risk_Score']} / 10"
            )

            print(
                f"Risk Level           : {d['Risk_Level']}"
            )

            print(
                f"Command              : {d['Command']}"
            )

            print(
                f"Path                 : {' -> '.join(d['Path'])}"
            )

            print(
                "-" * 60
            )

    else:

        print(
            "\n[PASS] No secret exfiltration flow detected (BENIGN)."
        )