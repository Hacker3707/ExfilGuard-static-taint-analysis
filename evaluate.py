import os
import traceback
from main import analyze_workflow

POSITIVE_DIR = "testcases/positive"
NEGATIVE_DIR = "testcases/negative"

# Bảng quy tắc Rule ID chuẩn cho Source và Sink
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
}


def get_src_rule_id(cat: str) -> str:
    return SOURCE_RULES.get(cat, "RULE-SRC-UNKNOWN")


def get_snk_rule_id(cat: str) -> str:
    return SINK_RULES.get(cat, "RULE-SNK-UNKNOWN")


def evaluate_directory(directory, ground_truth):
    results = []

    if not os.path.exists(directory):
        print(f"[WARNING] Directory not found: {directory}")
        return results

    for filename in sorted(os.listdir(directory)):
        if not filename.endswith((".yml", ".yaml")):
            continue

        file_path = os.path.join(directory, filename)
        print(f"\n>>> Evaluating: {file_path}")

        try:
            detections = analyze_workflow(file_path)
            dangerous_detections = [
                d
                for d in detections
                if d.get("Risk_Level") in ["MEDIUM", "HIGH", "CRITICAL"]
            ]

            detected = len(dangerous_detections) > 0

            if ground_truth == "Positive":
                label = "TP" if detected else "FN"
            else:
                label = "FP" if detected else "TN"

            # Trích xuất thông tin rủi ro cao nhất
            if detections:
                max_risk = max(detections, key=lambda d: d.get("Risk_Score", 0))
                risk_score = max_risk.get("Risk_Score", 0)
                risk_level = max_risk.get("Risk_Level", "UNKNOWN")
                sink = max_risk.get("Sink", "-")
                sink_cat = max_risk.get("Sink_Category", "K_cli")
                source = max_risk.get("Source", "-")
                source_cat = max_risk.get("Source_Category", "S_ctx")
                destination = max_risk.get("Destination_Type", "UNKNOWN")
            else:
                risk_score = 0
                risk_level = "NONE"
                sink = "-"
                sink_cat = "-"
                source = "-"
                source_cat = "-"
                destination = "-"

            results.append({
                "file": filename,
                "ground_truth": ground_truth,
                "detected": detected,
                "label": label,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "source": source,
                "source_cat": source_cat,
                "sink": sink,
                "sink_cat": sink_cat,
                "destination": destination,
            })

            print(
                f"{filename:<25}"
                f"{ground_truth:<12}"
                f"{'DETECTED' if detected else 'NOT DETECTED':<18}"
                f"{label:<6}"
                f"Risk={risk_score:<4}"
                f"{risk_level}"
            )

            # In chi tiết Sink, Source, Rule ID và Taint Path
            if detections:
                src_full_rule = get_src_rule_id(source_cat)
                snk_full_rule = get_snk_rule_id(sink_cat)

                print(f"    Source      : {source} [{source_cat}] ({src_full_rule})")
                print(f"    Sink        : {sink} [{sink_cat}] ({snk_full_rule})")
                print(f"    Destination : {destination}")

                for d in detections:
                    d_src_cat = d.get("Source_Category", source_cat)
                    d_snk_cat = d.get("Sink_Category", sink_cat)
                    d_src_code = get_src_rule_id(d_src_cat).split()[0]
                    d_snk_code = get_snk_rule_id(d_snk_cat).split()[0]
                    path_str = " -> ".join(d.get("Path", []))

                    print(f"    Path [{d_src_code} -> {d_snk_code}] : {path_str}")

        except Exception as e:
            print(f"[ERROR] {filename}: {e}")
            traceback.print_exc()

    return results


def calculate_metrics(results):
    TP = sum(1 for r in results if r["label"] == "TP")
    TN = sum(1 for r in results if r["label"] == "TN")
    FP = sum(1 for r in results if r["label"] == "FP")
    FN = sum(1 for r in results if r["label"] == "FN")

    precision = TP / (TP + FP) if (TP + FP) > 0 else 0.0
    recall = TP / (TP + FN) if (TP + FN) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = FP / (FP + TN) if (FP + TN) > 0 else 0.0

    return TP, TN, FP, FN, precision, recall, f1, fpr


def main():
    all_results = []
    all_results.extend(evaluate_directory(POSITIVE_DIR, "Positive"))
    all_results.extend(evaluate_directory(NEGATIVE_DIR, "Negative"))

    TP, TN, FP, FN, precision, recall, f1, fpr = calculate_metrics(all_results)

    print("\n" + "=" * 80)
    print("EXFILGUARD DETECTION EFFECTIVENESS")
    print("=" * 80)
    print(f"True Positive  (TP): {TP}")
    print(f"True Negative  (TN): {TN}")
    print(f"False Positive (FP): {FP}")
    print(f"False Negative (FN): {FN}")
    print("-" * 80)
    print(f"Precision          : {precision:.4f} ({precision * 100:.2f}%)")
    print(f"Recall             : {recall:.4f} ({recall * 100:.2f}%)")
    print(f"F1-score           : {f1:.4f} ({f1 * 100:.2f}%)")
    print(f"False Positive Rate: {fpr:.4f} ({fpr * 100:.2f}%)")
    print("=" * 80)

    print("\nDETAILED RESULTS")
    print("-" * 80)
    for r in all_results:
        print(
            f"{r['file']:<25}"
            f"{r['ground_truth']:<12}"
            f"{'DETECTED' if r['detected'] else 'NOT DETECTED':<18}"
            f"{r['label']:<6}"
            f"Risk={r['risk_score']:<4}"
            f"{r['risk_level']}"
        )


if __name__ == "__main__":
    main()