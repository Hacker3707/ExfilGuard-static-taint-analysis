import os
import csv
import argparse

from config import ExfilGuardConfig
from analyzers.yaml_analyzer import YamlAnalyzer


MODES = {
    "1. YAML-only (No script taint)": ExfilGuardConfig(
        enable_yaml=True,
        enable_bash=False,
        enable_python=False,
        enable_nodejs=False
    ),

    "2. YAML + Bash": ExfilGuardConfig(
        enable_yaml=True,
        enable_bash=True,
        enable_python=False,
        enable_nodejs=False
    ),

    "3. YAML + Bash + Python": ExfilGuardConfig(
        enable_yaml=True,
        enable_bash=True,
        enable_python=True,
        enable_nodejs=False
    ),

    "4. Full (YAML + Bash + Py + Node)": ExfilGuardConfig(
        enable_yaml=True,
        enable_bash=True,
        enable_python=True,
        enable_nodejs=True
    )
}


def load_dataset_ground_truth(dataset_dir):
    """
    Load Dataset B ground truth.

    dataset_dir:
        replication/3_dataset_b/workflows/

    ground_truth.csv:
        replication/3_dataset_b/ground_truth.csv
    """

    dataset_dir = os.path.abspath(dataset_dir)

    dataset_root = os.path.dirname(dataset_dir)

    ground_truth_file = os.path.join(
        dataset_root,
        "ground_truth.csv"
    )

    if not os.path.exists(ground_truth_file):
        raise FileNotFoundError(
            f"Ground truth not found: {ground_truth_file}"
        )

    ground_truth = {}

    with open(
        ground_truth_file,
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as f:

        reader = csv.DictReader(f)

        for row in reader:
            workflow_file = row["workflow_file"]
            label = row["label"].strip().lower()

            filename = os.path.basename(workflow_file)

            ground_truth[filename] = label

    return ground_truth


def eval_mode(cfg, dataset_dir=None):
    analyzer = YamlAnalyzer(cfg)

    tp = fp = fn = tn = 0

    # ==========================================================
    # DATASET B
    # ==========================================================

    if dataset_dir is not None:

        ground_truth = load_dataset_ground_truth(dataset_dir)

        if not os.path.exists(dataset_dir):
            raise FileNotFoundError(
                f"Dataset directory not found: {dataset_dir}"
            )

        files = sorted(
            filename
            for filename in os.listdir(dataset_dir)
            if filename.endswith((".yml", ".yaml"))
        )

        for filename in files:

            file_path = os.path.join(
                dataset_dir,
                filename
            )

            label = ground_truth.get(filename)

            if label is None:
                print(
                    f"[WARNING] No ground truth for {filename}"
                )
                continue

            detections = [
                d
                for d in analyzer.analyze(file_path)
                if d.get("Risk_Level")
                in ["MEDIUM", "HIGH", "CRITICAL"]
            ]

            detected = len(detections) > 0

            if label == "exploit":

                if detected:
                    tp += 1
                else:
                    fn += 1

            elif label == "benign":

                if detected:
                    fp += 1
                else:
                    tn += 1

    # ==========================================================
    # DEFAULT TESTCASES
    # ==========================================================

    else:

        pos_dir = "testcases/positive"
        neg_dir = "testcases/negative"

        if os.path.exists(pos_dir):

            for f in os.listdir(pos_dir):

                if f.endswith((".yml", ".yaml")):

                    dets = [
                        d
                        for d in analyzer.analyze(
                            os.path.join(pos_dir, f)
                        )
                        if d.get("Risk_Level")
                        in ["MEDIUM", "HIGH", "CRITICAL"]
                    ]

                    if dets:
                        tp += 1
                    else:
                        fn += 1

        if os.path.exists(neg_dir):

            for f in os.listdir(neg_dir):

                if f.endswith((".yml", ".yaml")):

                    dets = [
                        d
                        for d in analyzer.analyze(
                            os.path.join(neg_dir, f)
                        )
                        if d.get("Risk_Level")
                        in ["MEDIUM", "HIGH", "CRITICAL"]
                    ]

                    if dets:
                        fp += 1
                    else:
                        tn += 1

    # ==========================================================
    # METRICS
    # ==========================================================

    prec = (
        tp / (tp + fp)
        if (tp + fp) > 0
        else 0
    )

    rec = (
        tp / (tp + fn)
        if (tp + fn) > 0
        else 0
    )

    f1 = (
        2 * prec * rec / (prec + rec)
        if (prec + rec) > 0
        else 0
    )

    return tp, fp, fn, tn, prec, rec, f1


def main():

    parser = argparse.ArgumentParser(
        description="Run ExfilGuard ablation study."
    )

    parser.add_argument(
        "--dataset",
        type=str,
        default=None,
        help="Dataset workflow directory."
    )

    args = parser.parse_args()

    print("\n" + "=" * 95)

    print(
        f"{'Ablation Setting':<35} | "
        f"{'TP':<4} | "
        f"{'FP':<4} | "
        f"{'FN':<4} | "
        f"{'TN':<4} | "
        f"{'Precision':<10} | "
        f"{'Recall':<10} | "
        f"{'F1-Score':<10}"
    )

    print("=" * 95)

    for title, cfg in MODES.items():

        tp, fp, fn, tn, prec, rec, f1 = eval_mode(
            cfg,
            args.dataset
        )

        print(
            f"{title:<35} | "
            f"{tp:<4} | "
            f"{fp:<4} | "
            f"{fn:<4} | "
            f"{tn:<4} | "
            f"{prec * 100:6.2f}%    | "
            f"{rec * 100:6.2f}%    | "
            f"{f1 * 100:6.2f}%"
        )

    print("=" * 95)


if __name__ == "__main__":
    main()