import os
import traceback
from exfilguard import analyze_workflow

POSITIVE_DIR = "testcases/positive"
NEGATIVE_DIR = "testcases/negative"


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
                d for d in detections
                if d.get("Risk_Level") in ["MEDIUM", "HIGH", "CRITICAL"]
            ]

            detected = len(dangerous_detections) > 0

            if ground_truth == "Positive":
                label = "TP" if detected else "FN"
            else:
                label = "FP" if detected else "TN"

            # Lấy thông tin risk
            if detections:
                max_risk = max(
                    detections,
                    key=lambda d: d.get("Risk_Score", 0)
                )

                risk_score = max_risk.get("Risk_Score", 0)
                risk_level = max_risk.get("Risk_Level", "UNKNOWN")
                sink = max_risk.get("Sink", "UNKNOWN")
                source = max_risk.get("Source", "UNKNOWN")
                destination = max_risk.get(
                    "Destination_Type",
                    "UNKNOWN"
                )
            else:
                risk_score = 0
                risk_level = "NONE"
                sink = "-"
                source = "-"
                destination = "-"

            results.append({
                "file": filename,
                "ground_truth": ground_truth,
                "detected": detected,
                "label": label,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "source": source,
                "sink": sink,
                "destination": destination
            })

            print(
                f"{filename:<25}"
                f"{ground_truth:<12}"
                f"{'DETECTED' if detected else 'NOT DETECTED':<18}"
                f"{label:<6}"
                f"Risk={risk_score:<4}"
                f"{risk_level}"
            )

            if detections:
                print(f"    Source      : {source}")
                print(f"    Sink        : {sink}")
                print(f"    Destination : {destination}")

                for d in detections:
                    print(
                        f"    Path        : "
                        f"{' -> '.join(d['Path'])}"
                    )

        except Exception as e:
            print(f"[ERROR] {filename}: {e}")
            traceback.print_exc()

    return results


def calculate_metrics(results):
    TP = sum(1 for r in results if r["label"] == "TP")
    TN = sum(1 for r in results if r["label"] == "TN")
    FP = sum(1 for r in results if r["label"] == "FP")
    FN = sum(1 for r in results if r["label"] == "FN")

    precision = TP / (TP + FP) if TP + FP > 0 else 0
    recall = TP / (TP + FN) if TP + FN > 0 else 0

    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall > 0
        else 0
    )

    fpr = FP / (FP + TN) if FP + TN > 0 else 0

    return TP, TN, FP, FN, precision, recall, f1, fpr


def main():
    all_results = []

    all_results.extend(
        evaluate_directory(POSITIVE_DIR, "Positive")
    )

    all_results.extend(
        evaluate_directory(NEGATIVE_DIR, "Negative")
    )

    TP, TN, FP, FN, precision, recall, f1, fpr = calculate_metrics(
        all_results
    )

    print("\n" + "=" * 80)
    print("EXFILGUARD DETECTION EFFECTIVENESS")
    print("=" * 80)

    print(f"True Positive  (TP): {TP}")
    print(f"True Negative  (TN): {TN}")
    print(f"False Positive (FP): {FP}")
    print(f"False Negative (FN): {FN}")

    print("-" * 80)

    print(f"Precision         : {precision:.4f} ({precision * 100:.2f}%)")
    print(f"Recall            : {recall:.4f} ({recall * 100:.2f}%)")
    print(f"F1-score          : {f1:.4f} ({f1 * 100:.2f}%)")
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