import yaml
import sys
import re


SECRET_PATTERN = re.compile(
    r"\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}"
)


VAR_PATTERN = re.compile(
    r"\$([A-Za-z_][A-Za-z0-9_]*)"
)


def get_secret_source(value):

    if not isinstance(value, str):
        return None

    match = SECRET_PATTERN.search(value)

    if match:
        return match.group()

    return None


def find_variable_references(text):

    return VAR_PATTERN.findall(text)


def is_curl_command(command):

    return command.strip().startswith("curl")


# Gộp các dòng có dấu \ ở cuối
def get_logical_lines(script):

    lines = script.splitlines()

    logical_lines = []

    current_line = ""

    for line in lines:

        line = line.strip()

        # Bỏ dòng trống
        if not line:
            continue

        # Nếu dòng trước chưa hoàn thành
        if current_line:

            current_line += " " + line

        else:

            current_line = line


        # Nếu kết thúc bằng \
        # nghĩa là lệnh còn tiếp ở dòng sau
        if current_line.endswith("\\"):

            current_line = current_line[:-1].strip()

        else:

            logical_lines.append(
                current_line
            )

            current_line = ""


    # Phòng trường hợp còn dữ liệu
    if current_line:

        logical_lines.append(
            current_line
        )


    return logical_lines


def analyze_run_script(
    script,
    tainted,
    job_name,
    step_index,
    step_name
):

    lines = get_logical_lines(script)


    for line in lines:


        # =========================
        # VARIABLE ASSIGNMENT
        # =========================

        assignment = re.match(

            r"([A-Za-z_][A-Za-z0-9_]*)=(.*)",

            line
        )


        if assignment:

            variable = assignment.group(1)

            expression = assignment.group(2)


            references = find_variable_references(
                expression
            )


            for ref in references:


                if ref in tainted:


                    tainted[variable] = {

                        "Source":
                            tainted[ref]["Source"],


                        "Path":

                            tainted[ref]["Path"]
                            + [variable]


                    }


                    print(

                        f"[TAINT] "
                        f"{ref} -> {variable}"

                    )


                    break


        # =========================
        # CURL SINK
        # =========================

        if is_curl_command(line):


            references = find_variable_references(
                line
            )


            for ref in references:


                if ref in tainted:


                    path = (

                        tainted[ref]["Path"]

                        + ["curl"]

                    )


                    sink = {

                        "Rule": "SNK-01",

                        "Type":
                            "CLI Transfer Utilities",

                        "Command":
                            "curl"

                    }


                    print()

                    print(
                        "[HIGH] Potential Secret Exfiltration"
                    )

                    print(
                        "--------------------------------------"
                    )


                    # =========================
                    # LOCATION
                    # =========================

                    print()

                    print("Location:")

                    print(
                        "  Job:",
                        job_name
                    )

                    print(
                        "  Step:",
                        step_index
                    )

                    print(
                        "  Step Name:",
                        step_name
                    )

                    print(
                        "  Command:",
                        line
                    )


                    # =========================
                    # SOURCE
                    # =========================

                    print()

                    print("Source:")

                    print(
                        "  Rule:",
                        tainted[ref]["Source"]["Rule"]
                    )

                    print(
                        "  Value:",
                        tainted[ref]["Source"]["Value"]
                    )


                    # =========================
                    # SINK
                    # =========================

                    print()

                    print("Sink:")

                    print(
                        "  Rule:",
                        sink["Rule"]
                    )

                    print(
                        "  Type:",
                        sink["Type"]
                    )

                    print(
                        "  Command:",
                        sink["Command"]
                    )


                    # =========================
                    # PATH
                    # =========================

                    print()

                    print("Taint Path:")


                    for node in path:

                        print(
                            f"  -> {node}"
                        )


                    print()


                    # Tránh báo trùng
                    break



def analyze_workflow(file_path):


    with open(

        file_path,

        "r",

        encoding="utf-8"

    ) as file:


        workflow = yaml.safe_load(file)


    jobs = workflow.get(
        "jobs",
        {}
    )


    # =========================
    # ANALYZE EACH JOB
    # =========================

    for job_name, job in jobs.items():


        print()

        print(
            f"Analyzing Job: {job_name}"
        )

        print(
            "=============================="
        )


        # -------------------------
        # Tainted riêng cho Job
        # -------------------------

        job_tainted = {}


        job_env = job.get(
            "env",
            {}
        )


        # =========================
        # JOB ENV
        # =========================

        for variable, value in job_env.items():


            source = get_secret_source(
                value
            )


            if source:


                job_tainted[variable] = {


                    "Source": {

                        "Rule": "SRC-01",

                        "Value": source

                    },


                    "Path": [

                        source,

                        f"job.env.{variable}"

                    ]

                }


        steps = job.get(
            "steps",
            []
        )


        # =========================
        # ANALYZE EACH STEP
        # =========================

        for step_index, step in enumerate(

            steps,

            start=1

        ):


            # -------------------------
            # Tạo scope riêng cho Step
            # -------------------------

            step_tainted = {}


            # Copy biến từ Job env
            for variable, info in job_tainted.items():

                step_tainted[variable] = {

                    "Source":
                        info["Source"],


                    "Path":
                        info["Path"].copy()

                }


            step_name = step.get(

                "name",

                f"Step {step_index}"

            )


            print()

            print(
                f"Analyzing Step {step_index}: "
                f"{step_name}"
            )


            # =========================
            # STEP ENV
            # =========================

            step_env = step.get(

                "env",

                {}

            )


            for variable, value in step_env.items():


                source = get_secret_source(
                    value
                )


                if source:


                    step_tainted[variable] = {


                        "Source": {

                            "Rule":
                                "SRC-01",

                            "Value":
                                source

                        },


                        "Path": [

                            source,

                            f"step.{step_index}.env.{variable}"

                        ]

                    }


            # =========================
            # RUN SCRIPT
            # =========================

            run_script = step.get(
                "run"
            )


            if run_script:


                analyze_run_script(

                    run_script,

                    step_tainted,

                    job_name,

                    step_index,

                    step_name

                )




if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            "Usage: "
            "python exfilguard.py workflow.yml"
        )

        sys.exit(1)


    analyze_workflow(
        sys.argv[1]
    )
