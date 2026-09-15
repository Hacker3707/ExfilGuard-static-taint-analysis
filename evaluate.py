
import os
import traceback
from main import analyze_workflow


POSITIVE_DIR = "testcases/positive"
NEGATIVE_DIR = "testcases/negative"
REGRESSION_DIR = "regress_test"


# ==============================================================================
# RULE ID
# ==============================================================================

SOURCE_RULES = {
    "S_ctx": "RULE-SRC-01 (Context Secrets / GitHub Token)",
    "S_dyn": "RULE-SRC-02 (Cloud IMDS / Dynamic Credentials)",
    "S_prog": "RULE-SRC-03 (Programmatic Env Variable Access)",
    "S_env": "RULE-SRC-04 (Workflow Environment Binding)",
    "S_inp": "RULE-SRC-05 (Untrusted Workflow Trigger Inputs)",
}

SINK_RULES = {
    "K_cli": "RULE-SNK-01 (CLI Network Transfer Utility)",
    "K_dns": "RULE-SNK-02 (DNS Exfiltration Channel)",
    "K_lib": "RULE-SNK-03 (HTTP/Socket Client Library)",
    "K_raw": "RULE-SNK-04 (Raw Network Socket Egress)",
    "K_scm": "RULE-SNK-05 (SCM Push / Insecure Commit)",
    "K_file": "RULE-SNK-07 (File Transfer / Upload)",
    "K_artifact": "RULE-SNK-06 (GitHub Actions Artifact Upload)",
}


def get_src_rule_id(cat):
    return SOURCE_RULES.get(cat, "RULE-SRC-UNKNOWN")


def get_snk_rule_id(cat):
    return SINK_RULES.get(cat, "RULE-SNK-UNKNOWN")


# ==============================================================================
# EVALUATE ONE DIRECTORY
# ==============================================================================

def evaluate_directory(directory, ground_truth):
    results = []

    if not os.path.exists(directory):
        print(f"[WARNING] Directory not found: {directory}")
        return results

    files = sorted(
        filename
        for filename in os.listdir(directory)
        if filename.endswith((".yml", ".yaml"))
    )

    print(f"\n{'=' * 100}")
    print(f"SCANNING: {directory}")
    print(f"GROUND TRUTH: {ground_truth}")
    print(f"FILES: {len(files)}")
    print(f"{'=' * 100}")

    for filename in files:
        file_path = os.path.join(directory, filename)

        print(f"\n{'-' * 100}")
        print(f">>> Evaluating: {file_path}")
        print(f"{'-' * 100}")

        try:
            # ------------------------------------------------------------------
            # Chạy ExfilGuard
            # ------------------------------------------------------------------
            detections = analyze_workflow(file_path)

            # ------------------------------------------------------------------
            # Benchmark detection
            #
            # KHÔNG lọc theo Risk_Level.
            # EXFIL / FILE_EXFIL đều được tính là detection.
            # ------------------------------------------------------------------
            exfil_detections = [
                d for d in detections
                if d.get("Finding_Type") in ["EXFIL", "FILE_EXFIL"]
            ]

            detected = len(exfil_detections) > 0

            if ground_truth == "Positive":
                label = "TP" if detected else "FN"
            else:
                label = "FP" if detected else "TN"

            # ------------------------------------------------------------------
            # Nếu có detection -> lấy finding có Risk Score cao nhất
            # ------------------------------------------------------------------
            if detections:
                max_risk = max(
                    detections,
                    key=lambda d: d.get("Risk_Score", 0)
                )

                risk_score = max_risk.get("Risk_Score", 0)
                risk_level = max_risk.get("Risk_Level", "UNKNOWN")
                sink = max_risk.get("Sink", "-")
                sink_cat = max_risk.get("Sink_Category", "-")
                source = max_risk.get("Source", "-")
                source_cat = max_risk.get("Source_Category", "-")
                destination = max_risk.get("Destination_Type", "UNKNOWN")
                finding_type = max_risk.get("Finding_Type", "-")

            else:
                risk_score = 0
                risk_level = "NONE"
                sink = "-"
                sink_cat = "-"
                source = "-"
                source_cat = "-"
                destination = "-"
                finding_type = "-"

            # ------------------------------------------------------------------
            # Lưu kết quả
            # ------------------------------------------------------------------
            results.append({
                "file": filename,
                "ground_truth": ground_truth,
                "detected": detected,
                "label": label,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "finding_type": finding_type,
                "source": source,
                "source_cat": source_cat,
                "sink": sink,
                "sink_cat": sink_cat,
                "destination": destination,
                "detection_count": len(detections),
                "exfil_count": len(exfil_detections),
            })

            # ------------------------------------------------------------------
            # Summary một testcase
            # ------------------------------------------------------------------
            print(
                f"Result       : "
                f"{'DETECTED' if detected else 'NOT DETECTED'}"
            )

            print(f"Label        : {label}")
            print(f"Finding Type : {finding_type}")
            print(f"Risk         : {risk_score} ({risk_level})")
            print(f"Source       : {source} [{source_cat}]")
            print(f"Sink         : {sink} [{sink_cat}]")
            print(f"Destination  : {destination}")
            print(f"Detections   : {len(detections)}")
            print(f"EXFIL        : {len(exfil_detections)}")

            # ------------------------------------------------------------------
            # In Rule ID + Taint Path của TẤT CẢ detections
            # ------------------------------------------------------------------
            if detections:
                print("\n  --- Detection Details ---")

                for index, d in enumerate(detections, start=1):

                    d_src_cat = d.get(
                        "Source_Category",
                        source_cat
                    )

                    d_snk_cat = d.get(
                        "Sink_Category",
                        sink_cat
                    )

                    src_rule = get_src_rule_id(d_src_cat)
                    snk_rule = get_snk_rule_id(d_snk_cat)

                    d_source = d.get("Source", "-")
                    d_sink = d.get("Sink", "-")
                    d_destination = d.get(
                        "Destination_Type",
                        "UNKNOWN"
                    )

                    d_risk_score = d.get("Risk_Score", 0)
                    d_risk_level = d.get(
                        "Risk_Level",
                        "UNKNOWN"
                    )

                    d_finding_type = d.get(
                        "Finding_Type",
                        "-"
                    )

                    path = d.get("Path", [])
                    path_str = " -> ".join(
                        str(x) for x in path
                    )

                    command = d.get("Command", "-")
                    context = d.get("Context", "-")
                    note = d.get("Note", "")

                    print(f"\n  [{index}]")
                    print(
                        f"      Finding Type : "
                        f"{d_finding_type}"
                    )

                    print(
                        f"      Source       : "
                        f"{d_source} [{d_src_cat}]"
                    )

                    print(
                        f"      Source Rule  : "
                        f"{src_rule}"
                    )

                    print(
                        f"      Sink         : "
                        f"{d_sink} [{d_snk_cat}]"
                    )

                    print(
                        f"      Sink Rule    : "
                        f"{snk_rule}"
                    )

                    print(
                        f"      Destination  : "
                        f"{d_destination}"
                    )

                    print(
                        f"      Risk         : "
                        f"{d_risk_score} ({d_risk_level})"
                    )

                    print(
                        f"      Command      : "
                        f"{command}"
                    )

                    print(
                        f"      Context      : "
                        f"{context}"
                    )

                    print(
                        f"      Taint Path   : "
                        f"{path_str}"
                    )

                    if note:
                        print(
                            f"      Note         : "
                            f"{note}"
                        )

        except Exception as e:
            print(f"[ERROR] {filename}: {e}")
            traceback.print_exc()

    return results


# ==============================================================================
# METRICS
# ==============================================================================

def calculate_metrics(results):
    TP = sum(
        1 for r in results
        if r["label"] == "TP"
    )

    TN = sum(
        1 for r in results
        if r["label"] == "TN"
    )

    FP = sum(
        1 for r in results
        if r["label"] == "FP"
    )

    FN = sum(
        1 for r in results
        if r["label"] == "FN"
    )

    precision = (
        TP / (TP + FP)
        if (TP + FP) > 0
        else 0.0
    )

    recall = (
        TP / (TP + FN)
        if (TP + FN) > 0
        else 0.0
    )

    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    fpr = (
        FP / (FP + TN)
        if (FP + TN) > 0
        else 0.0
    )

    return TP, TN, FP, FN, precision, recall, f1, fpr


# ==============================================================================
# FINAL SUMMARY
# ==============================================================================

def print_final_summary(results):
    TP, TN, FP, FN, precision, recall, f1, fpr = calculate_metrics(results)

    print("\n\n")
    print("=" * 100)
    print("EXFILGUARD DETECTION EFFECTIVENESS")
    print("=" * 100)

    print(f"Total Testcases  : {len(results)}")
    print()

    print(f"True Positive    : {TP}")
    print(f"True Negative    : {TN}")
    print(f"False Positive   : {FP}")
    print(f"False Negative   : {FN}")

    print("-" * 100)

    print(
        f"Precision        : "
        f"{precision:.4f} ({precision * 100:.2f}%)"
    )

    print(
        f"Recall           : "
        f"{recall:.4f} ({recall * 100:.2f}%)"
    )

    print(
        f"F1-score         : "
        f"{f1:.4f} ({f1 * 100:.2f}%)"
    )

    print(
        f"False Positive Rate: "
        f"{fpr:.4f} ({fpr * 100:.2f}%)"
    )

    print("=" * 100)

    # --------------------------------------------------------------------------
    # Bảng tổng hợp
    # --------------------------------------------------------------------------

    print("\nDETAILED RESULTS")
    print("-" * 100)

    print(
        f"{'File':<30}"
        f"{'GT':<12}"
        f"{'Result':<16}"
        f"{'Label':<7}"
        f"{'Finding':<14}"
        f"{'Risk':<10}"
        f"Source -> Sink"
    )

    print("-" * 100)

    for r in results:
        result = (
            "DETECTED"
            if r["detected"]
            else "NOT DETECTED"
        )

        source_sink = (
            f"{r['source_cat']} -> {r['sink_cat']}"
        )

        print(
            f"{r['file']:<30}"
            f"{r['ground_truth']:<12}"
            f"{result:<16}"
            f"{r['label']:<7}"
            f"{r['finding_type']:<14}"
            f"{r['risk_score']:<10}"
            f"{source_sink}"
        )

    print("-" * 100)


# ==============================================================================
# MAIN
# ==============================================================================

def main():
    print("=" * 100)
    print("EXFILGUARD FULL BENCHMARK EVALUATION")
    print("=" * 100)

    all_results = []

    # --------------------------------------------------------------------------
    # Quét TOÀN BỘ Positive
    # --------------------------------------------------------------------------

    all_results.extend(
        evaluate_directory(
            POSITIVE_DIR,
            "Positive"
        )
    )

    # --------------------------------------------------------------------------
    # Quét TOÀN BỘ Negative
    # --------------------------------------------------------------------------

    all_results.extend(
        evaluate_directory(
            NEGATIVE_DIR,
            "Negative"
        )
    )

    # --------------------------------------------------------------------------
    # Quét REGRESS
    # --------------------------------------------------------------------------

    all_results.extend(
        evaluate_directory(
            REGRESSION_DIR,
            "Positive"
        )
    )

    # --------------------------------------------------------------------------
    # Tổng hợp
    # --------------------------------------------------------------------------

    print_final_summary(all_results)


if __name__ == "__main__":
    main()
