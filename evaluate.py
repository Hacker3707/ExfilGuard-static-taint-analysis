import os
from exfilguard import analyze_workflow


TESTCASE_DIR = "testcases"


def evaluate():
    tp = 0
    tn = 0
    fp = 0
    fn = 0

    details = []

    # ============================================================
    # Evaluate Positive Test Cases
    # ============================================================
    positive_dir = os.path.join(TESTCASE_DIR, "positive")

    for filename in sorted(os.listdir(positive_dir)):

        if not filename.endswith((".yml", ".yaml")):
            continue

        file_path = os.path.join(positive_dir, filename)

        print(f"\n>>> Evaluating: {file_path}")

        detections = analyze_workflow(file_path)

        detected = len(detections) > 0

        if detected:
            tp += 1
            result = "TP"
        else:
            fn += 1
            result = "FN"

        details.append(
            (filename, "Positive", detected, result)
        )

    # ============================================================
    # Evaluate Negative Test Cases
    # ============================================================
    negative_dir = os.path.join(TESTCASE_DIR, "negative")

    for filename in sorted(os.listdir(negative_dir)):

        if not filename.endswith((".yml", ".yaml")):
            continue

        file_path = os.path.join(negative_dir, filename)

        detections = analyze_workflow(file_path)

        detected = len(detections) > 0

        if detected:
            fp += 1
            result = "FP"
        else:
            tn += 1
            result = "TN"

        details.append(
            (filename, "Negative", detected, result)
        )

    # ============================================================
    # Calculate Metrics
    # ============================================================

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0

    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0
    )

    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

    # ============================================================
    # Print Results
    # ============================================================

    print("=" * 60)
    print("EXFILGUARD DETECTION EFFECTIVENESS")
    print("=" * 60)

    print(f"True Positive  (TP): {tp}")
    print(f"True Negative  (TN): {tn}")
    print(f"False Positive (FP): {fp}")
    print(f"False Negative (FN): {fn}")

    print("-" * 60)

    print(f"Precision       : {precision:.4f} ({precision * 100:.2f}%)")
    print(f"Recall          : {recall:.4f} ({recall * 100:.2f}%)")
    print(f"F1-score        : {f1:.4f} ({f1 * 100:.2f}%)")
    print(f"False Positive Rate: {fpr:.4f} ({fpr * 100:.2f}%)")

    print("=" * 60)

    print("\nDETAILED RESULTS")
    print("-" * 60)

    for filename, label, detected, result in details:
        status = "DETECTED" if detected else "NOT DETECTED"

        print(
            f"{filename:25} "
            f"{label:10} "
            f"{status:15} "
            f"{result}"
        )


if __name__ == "__main__":
    evaluate()