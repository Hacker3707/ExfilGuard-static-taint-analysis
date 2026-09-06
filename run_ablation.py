import os
from config import ExfilGuardConfig
from analyzers.yaml_analyzer import YamlAnalyzer

MODES = {
    "1. YAML-only (No script taint)": ExfilGuardConfig(enable_yaml=True, enable_bash=False, enable_python=False,
                                                       enable_nodejs=False),
    "2. YAML + Bash": ExfilGuardConfig(enable_yaml=True, enable_bash=True, enable_python=False, enable_nodejs=False),
    "3. YAML + Bash + Python": ExfilGuardConfig(enable_yaml=True, enable_bash=True, enable_python=True,
                                                enable_nodejs=False),
    "4. Full (YAML + Bash + Py + Node)": ExfilGuardConfig(enable_yaml=True, enable_bash=True, enable_python=True,
                                                          enable_nodejs=True)
}


def eval_mode(cfg):
    analyzer = YamlAnalyzer(cfg)
    pos_dir = "testcases/positive"
    neg_dir = "testcases/negative"

    tp = fp = fn = tn = 0
    if os.path.exists(pos_dir):
        for f in os.listdir(pos_dir):
            if f.endswith((".yml", ".yaml")):
                dets = [d for d in analyzer.analyze(os.path.join(pos_dir, f)) if
                        d.get("Risk_Level") in ["MEDIUM", "HIGH", "CRITICAL"]]
                if dets:
                    tp += 1
                else:
                    fn += 1

    if os.path.exists(neg_dir):
        for f in os.listdir(neg_dir):
            if f.endswith((".yml", ".yaml")):
                dets = [d for d in analyzer.analyze(os.path.join(neg_dir, f)) if
                        d.get("Risk_Level") in ["MEDIUM", "HIGH", "CRITICAL"]]
                if dets:
                    fp += 1
                else:
                    tn += 1

    prec = tp / (tp + fp) if (tp + fp) > 0 else 0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0
    return tp, fp, fn, tn, prec, rec, f1


print("\n" + "=" * 95)
print(
    f"{'Ablation Setting':<35} | {'TP':<4} | {'FP':<4} | {'FN':<4} | {'TN':<4} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10}")
print("=" * 95)

for title, cfg in MODES.items():
    tp, fp, fn, tn, prec, rec, f1 = eval_mode(cfg)
    print(
        f"{title:<35} | {tp:<4} | {fp:<4} | {fn:<4} | {tn:<4} | {prec * 100:6.2f}%    | {rec * 100:6.2f}%    | {f1 * 100:6.2f}%")
print("=" * 95)