import os
import re
import yaml
from catalogs import (
    SECRET_PATTERN,
    CLI_SINK_PATTERN,
    DNS_SINK_PATTERN,
    VAR_REF_PATTERN,
)
from config import ExfilGuardConfig, DEFAULT_CONFIG
from engine.common import (
    classify_source,
    classify_sink,
    classify_destination,
    calculate_risk,
)
from engine.models import DetectionResult
from analyzers.bash_analyzer import BashAnalyzer
from analyzers.python_analyzer import PythonAnalyzer
from analyzers.nodejs_analyzer import NodejsAnalyzer


class YamlAnalyzer:
    def __init__(self, config: ExfilGuardConfig = DEFAULT_CONFIG):
        self.config = config
        self.bash_engine = BashAnalyzer() if config.enable_bash else None
        self.python_engine = PythonAnalyzer() if config.enable_python else None
        self.nodejs_engine = NodejsAnalyzer() if config.enable_nodejs else None

    def _get_logical_lines(self, script_content: str):
        lines = script_content.splitlines()
        logical = []
        cur = ""
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            cur = (cur + " " + line) if cur else line
            if cur.endswith("\\"):
                cur = cur[:-1].strip()
            else:
                logical.append(cur)
                cur = ""
        if cur:
            logical.append(cur)
        return logical

    def _resolve_file_path(self, script_path: str, workflow_path: str):
        workflow_dir = os.path.dirname(os.path.abspath(workflow_path))
        target = os.path.join(workflow_dir, script_path.strip().strip("'\""))
        if os.path.isfile(target):
            return target
        scripts_dir = os.path.join(workflow_dir, "scripts", os.path.basename(script_path))
        if os.path.isfile(scripts_dir):
            return scripts_dir
        if os.path.isfile(script_path):
            return os.path.abspath(script_path)
        return None

    def analyze(self, file_path: str):
        if not os.path.exists(file_path):
            return []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                workflow = yaml.safe_load(f)
        except Exception:
            return []

        jobs = workflow.get("jobs", {}) if isinstance(workflow, dict) else {}
        all_detections = []

        for job_name, job in jobs.items():
            job_tainted = {}

            # 1. Job-level env collection
            for var, val in job.get("env", {}).items():
                val_str = str(val)
                sec_match = SECRET_PATTERN.search(val_str)
                inp_match = re.search(r"\$\{\{\s*inputs\.[A-Za-z0-9_]+\s*\}\}", val_str)
                if sec_match:
                    job_tainted[var] = {
                        "Source": sec_match.group(),
                        "Path": [sec_match.group(), f"job.env.{var}"]
                    }
                elif inp_match:
                    job_tainted[var] = {
                        "Source": inp_match.group(),
                        "Path": [inp_match.group(), f"job.env.{var}"]
                    }

            # 2. Steps iteration
            for s_idx, step in enumerate(job.get("steps", []), start=1):
                if not isinstance(step, dict):
                    continue

                step_tainted = job_tainted.copy()

                # Step-level env collection & YAML-level env-to-env propagation
                for var, val in step.get("env", {}).items():
                    val_str = str(val)
                    sec_match = SECRET_PATTERN.search(val_str)
                    inp_match = re.search(r"\$\{\{\s*inputs\.[A-Za-z0-9_]+\s*\}\}", val_str)
                    env_ref = re.search(r"\$\{\{\s*env\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}", val_str)

                    if sec_match:
                        step_tainted[var] = {
                            "Source": sec_match.group(),
                            "Path": [sec_match.group(), f"step.{s_idx}.env.{var}"]
                        }
                    elif inp_match:
                        step_tainted[var] = {
                            "Source": inp_match.group(),
                            "Path": [inp_match.group(), f"step.{s_idx}.env.{var}"]
                        }
                    elif env_ref and env_ref.group(1) in job_tainted:
                        ref_name = env_ref.group(1)
                        step_tainted[var] = {
                            "Source": job_tainted[ref_name]["Source"],
                            "Path": job_tainted[ref_name]["Path"] + [f"step.{s_idx}.env.{var}"]
                        }

                run_script = step.get("run")
                if not run_script:
                    continue

                lines = self._get_logical_lines(run_script)

                # ==============================================================
                # CẤP 1: YAML-ONLY CHECK (Chạy khi tắt Bash để làm Ablation)
                # ==============================================================
                if self.config.enable_yaml:
                    for line in lines:
                        sink_match = CLI_SINK_PATTERN.search(line) or DNS_SINK_PATTERN.search(line)
                        if not sink_match:
                            continue

                        sink_cmd = sink_match.group(1)
                        sec_match = SECRET_PATTERN.search(line)
                        inp_match = re.search(r"\$\{\{\s*inputs\.[A-Za-z0-9_]+\s*\}\}", line)
                        env_match = re.search(r"\$\{\{\s*env\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}", line)
                        step_out_match = re.search(r"\$\{\{\s*steps\.[A-Za-z0-9_]+\.outputs\.[A-Za-z0-9_]+\s*\}\}", line)

                        src_val = None
                        full_path = []

                        if sec_match:
                            src_val = sec_match.group()
                            full_path = [src_val, sink_cmd]
                        elif inp_match:
                            src_val = inp_match.group()
                            full_path = [src_val, sink_cmd]
                        elif env_match and env_match.group(1) in step_tainted:
                            ref_name = env_match.group(1)
                            src_val = step_tainted[ref_name]["Source"]
                            full_path = step_tainted[ref_name]["Path"] + [sink_cmd]
                        elif step_out_match:
                            src_val = step_out_match.group()
                            full_path = [src_val, sink_cmd]

                        if src_val:
                            s_cat = classify_source(src_val)
                            k_cat = classify_sink(sink_cmd)
                            d_type = classify_destination(line)
                            score, level = calculate_risk(s_cat, k_cat, d_type)

                            all_detections.append(
                                DetectionResult(
                                    source=src_val,
                                    source_category=s_cat,
                                    sink=sink_cmd,
                                    sink_category=k_cat,
                                    destination_type=d_type,
                                    risk_score=score,
                                    risk_level=level,
                                    command=line,
                                    context=f"step_{s_idx}.yaml_direct",
                                    path=full_path,
                                )
                            )

                # ==============================================================
                # CẤP 2: BASH ANALYZER
                # ==============================================================
                if self.bash_engine:
                    step_tainted, bash_dets = self.bash_engine.analyze(
                        lines, step_tainted, f"step_{s_idx}"
                    )
                    all_detections.extend(bash_dets)

                    for line in lines:
                        sh_match = re.search(
                            r"(?:bash|sh|\./)\s*([^\s;&|]+\.sh)(.*)", line
                        )
                        if sh_match:
                            sh_file = sh_match.group(1).strip()
                            sh_args = sh_match.group(2).strip()
                            resolved_sh = self._resolve_file_path(sh_file, file_path)
                            if resolved_sh and os.path.exists(resolved_sh):
                                with open(resolved_sh, "r", encoding="utf-8", errors="ignore") as sf:
                                    sh_lines = self._get_logical_lines(sf.read())
                                sh_tainted = step_tainted.copy()
                                for ref in VAR_REF_PATTERN.findall(sh_args):
                                    r = ref[0] or ref[1]
                                    if r in step_tainted:
                                        sh_tainted["1"] = {
                                            "Source": step_tainted[r]["Source"],
                                            "Path": step_tainted[r]["Path"] + [f"{os.path.basename(resolved_sh)}.$1"],
                                        }
                                        break
                                _, ext_sh_dets = self.bash_engine.analyze(
                                    sh_lines, sh_tainted, os.path.basename(resolved_sh)
                                )
                                all_detections.extend(ext_sh_dets)

                # ==============================================================
                # CẤP 3: PYTHON ANALYZER
                # ==============================================================
                if self.python_engine:
                    python_lines = []
                    i = 0
                    while i < len(lines):
                        stripped = lines[i].strip()
                        py_c_match = re.match(r"\bpython(?:3)?\s+-c\s+(['\"])(.*)$", stripped)
                        if py_c_match:
                            quote, py_code = py_c_match.group(1), py_c_match.group(2)
                            while not py_code.endswith(quote):
                                i += 1
                                if i >= len(lines):
                                    break
                                py_code += " " + lines[i].strip()
                            if py_code.endswith(quote):
                                py_code = py_code[:-1]
                            python_lines.append(py_code)
                        else:
                            py_file_match = re.match(r"\bpython(?:3)?\s+([^\s;&|]+\.py)", stripped)
                            if py_file_match:
                                target_py = self._resolve_file_path(py_file_match.group(1), file_path)
                                if target_py and os.path.exists(target_py):
                                    with open(target_py, "r", encoding="utf-8", errors="ignore") as pf:
                                        _, py_file_dets = self.python_engine.analyze(
                                            pf.read().splitlines(),
                                            step_tainted,
                                            f"step_{s_idx}.{os.path.basename(target_py)}",
                                        )
                                        all_detections.extend(py_file_dets)
                        i += 1

                    if python_lines:
                        _, py_dets = self.python_engine.analyze(
                            python_lines, step_tainted, f"step_{s_idx}.python"
                        )
                        all_detections.extend(py_dets)

                # ==============================================================
                # CẤP 4: NODE.JS ANALYZER
                # ==============================================================
                if self.nodejs_engine:
                    node_lines = []
                    j = 0
                    while j < len(lines):
                        stripped = lines[j].strip()
                        node_e_match = re.match(r"\bnode\s+-e\s+(['\"])(.*)$", stripped)
                        if node_e_match:
                            quote, node_code = node_e_match.group(1), node_e_match.group(2)
                            while not node_code.endswith(quote):
                                j += 1
                                if j >= len(lines):
                                    break
                                node_code += " " + lines[j].strip()
                            if node_code.endswith(quote):
                                node_code = node_code[:-1]
                            node_lines.append(node_code)
                        else:
                            node_file_match = re.match(r"\bnode\s+([^\s;&|]+\.js)", stripped)
                            if node_file_match:
                                target_js = self._resolve_file_path(node_file_match.group(1), file_path)
                                if target_js and os.path.exists(target_js):
                                    with open(target_js, "r", encoding="utf-8", errors="ignore") as jf:
                                        _, js_file_dets = self.nodejs_engine.analyze(
                                            jf.read().splitlines(),
                                            step_tainted,
                                            f"step_{s_idx}.{os.path.basename(target_js)}",
                                        )
                                        all_detections.extend(js_file_dets)
                        j += 1

                    if node_lines:
                        _, js_dets = self.nodejs_engine.analyze(
                            node_lines, step_tainted, f"step_{s_idx}.node"
                        )
                        all_detections.extend(js_dets)

        return [d.to_dict() for d in all_detections]
