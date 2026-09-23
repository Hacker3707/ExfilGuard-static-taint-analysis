# ExfilGuard-static-taint-analysis

ExfilGuard - Detecting Secret Exfiltration in GitHub Actions Workflows Using Static Taint Analysis.

ExfilGuard is a static taint analysis framework for detecting potential secret exfiltration in GitHub Actions workflows. The framework analyzes workflow YAML files together with embedded Bash, Python, and Node.js scripts to track sensitive data flows from sources, including repository secrets and environment variables, to network-related sinks such as HTTP requests, command-line transfer utilities, and DNS queries. ExfilGuard constructs interpretable taint-flow paths and assigns risk levels to suspicious flows, enabling developers to identify both the origin and potential destination of sensitive data exposure.

The framework is evaluated on two benchmarks: a controlled scenario suite, reported with precision, recall, and F1-score, and a manually annotated real-world corpus, reported with false-positive rate and alert density. The real-world corpus contains no confirmed exfiltration case under the locked annotation definition; therefore, recall is not defined for that corpus and is reported only for the controlled benchmark.

## Dataset A — Final

### 1. Purpose

Dataset A is the workflow dataset used to identify and characterize GitHub Actions workflows relevant to secret-exfiltration analysis.

The dataset serves three main purposes:

1. Filter and collect workflows containing secret-related references and/or network operations.
2. Extract workflow-level features, including script language and network-sink indicators.
3. Manually review a stratified subset of workflows to provide labeled cases for later detector evaluation.

The manually reviewed subset is intended as a reference set for calculating Precision, Recall, and F1-score in the subsequent detector/evaluation task.

### 2. Final Dataset

- Total unique workflows: 23,526
- Manually reviewed workflows: 300
- EXFIL: 13
- NO_EXFIL: 262
- UNCLEAR: 25

### 3. Dataset Files

#### `data/dataset_a.csv`
Final workflow-level dataset containing metadata for the collected workflows.

#### `data/dataset_a_full.jsonl`
Full JSONL representation of Dataset A.

#### `data/features.jsonl`
Extracted workflow features, including secret-related indicators, network-sink indicators, and script-language information.

#### `data/ground_truth.csv`
Working ground truth for the 300 manually reviewed workflows.

The current working ground truth retains Annotator 1's labels after inter-annotator agreement analysis.

#### `data/review_sheet.csv`
Manual review sheet containing the sampled workflows and annotation fields.

#### `data/review_snippets/`
Workflow snippets used during manual annotation.

#### `data/labels_a1.csv`
Labels produced by Annotator 1.

#### `data/labels_a2.csv`
Labels produced by Annotator 2.

#### `data/agreement_report.md`
Inter-annotator agreement results.

#### `data/stats_4_1.md`
Dataset statistics and sampling information.

#### `data/filter_log.md`
Record of dataset filtering and exclusions.

### 4. Annotation Labels

#### EXFIL
A workflow contains a complete path from a secret source to a network sink where the secret content may be transmitted externally.

#### NO_EXFIL
The workflow may contain secrets and/or network operations, but no complete secret-to-network exfiltration path is established.

#### UNCLEAR
The available workflow content is insufficient to determine whether a secret-to-network path exists, for example when relevant behavior is implemented in an external script or local action whose implementation is not available.

### 5. Annotation Summary

Two annotators independently reviewed the same 300 workflows.

- Raw agreement: 0.827
- Cohen's kappa: 0.208
- Disagreements: 52

Because the inter-annotator agreement was low, Annotator 1's labels were retained as the working ground truth for subsequent experiments.

This should be treated as a working ground truth rather than an adjudicated gold standard.

### 6. Reproducibility

The `src/` directory contains the scripts used for repository sampling, workflow collection, feature extraction, manual-review sampling, annotation, and label merging.

The original configuration and execution environment should be retained separately if full dataset reconstruction is required.

### 7. Handover to the Next Task

The next task can use:

1. `data/features.jsonl` to obtain workflow features.
2. `data/ground_truth.csv` as the reference labels for the 300 manually reviewed workflows.
3. `data/review_snippets/` to inspect the corresponding workflow content.
4. `data/dataset_a.csv` for workflow metadata.

The next task should not modify the Dataset A labels directly. Detector predictions should be stored separately and compared against `ground_truth.csv`.


## Dataset B

Dataset B is a controlled benchmark of 30 hand-written workflows, consisting of 18 exploit cases and 12 benign cases across six scenario families. All Dataset B workflows are syntax-validated before evaluation using `validate_dsb.py`. The reported results use the validated benchmark version, which is frozen and versioned alongside the ExfilGuard release used for evaluation.

### Dataset B Validation

python3 replication/3_dataset_b/validate_dsb.py replication/3_dataset_b