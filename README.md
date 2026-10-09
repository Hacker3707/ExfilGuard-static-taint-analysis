# ExfilGuard

**Detecting Secret Exfiltration in GitHub Actions Workflows Using Static Taint Analysis**

University of Economics Ho Chi Minh City (UEH), Group 5. Accepted at ICAIN 2026.

ExfilGuard is a static taint analysis framework for detecting potential secret exfiltration in
GitHub Actions workflows. It analyses workflow YAML together with embedded Bash, Python and
Node.js code, tracking sensitive data from sources such as repository secrets and environment
variables to network sinks such as HTTP requests, command-line transfer utilities and DNS
queries. Each finding is reported as an interpretable taint path with a deterministic risk score,
so a reviewer can see both where the secret came from and where it was about to go.

ExfilGuard is a command-line analyser written in pure Python. It needs no GPU, no notebook
environment and no network access at analysis time.

- **Reproducibility build:** tag `v1.1-camera-ready` on `main`
- **Submission build:** tag `v1.0-replication`, commit `970aa78`

---

## Read this before reproducing anything

**The repository has two entry points and only one of them reproduces the paper.**

Every number reported in the paper comes from `YamlAnalyzer(DEFAULT_CONFIG)`, which is what
`main.py`, `run_ablation.py`, `sensitivity_threshold.py` and `score_boundary.py` all call.

`exfilguard.py` at the repository root is a separate single-file build. It reports more findings:
a 7.6 % false positive rate on Dataset A instead of 4.2 %, and 15 of 18 on Dataset B instead of
18 of 18. Any reproduction must go through `main.py` or the analyser class, never through
`exfilguard.py`.

---

## Quick start

```bash
git clone https://github.com/Hacker3707/ExfilGuard-static-taint-analysis.git
cd ExfilGuard-static-taint-analysis

python3 -m venv .venv
source .venv/bin/activate          # Ubuntu / WSL2
# . .venv/Scripts/activate         # Git Bash on Windows

pip install -r requirements.txt

python3 main.py testcases/positive/P01-direct-secret-curl.yml
```

Expected output: one finding with source category `S_ctx`, sink category `K_cli` and risk score
9.0 (CRITICAL). If that works, the installation is complete.

A virtual environment is required on Ubuntu, where a system-wide install is blocked by PEP 668
and fails with `externally-managed-environment`.

### System requirements

| Component | Recommended |
|---|---|
| Operating system | Windows 11 with WSL2 (Ubuntu), or Ubuntu 22.04 LTS |
| Python | 3.11 or newer |
| Shells | Git Bash for the repository, PowerShell for the Windows baseline binaries, WSL2 for Poutine |
| GPU | Not required |
| RAM | 8 GB |
| Disk | About 60 MB, or about 250 MB with the optional raw corpus |
| Internet | Only to clone the repository and install the baseline tools |

### Dependencies

| Category | Libraries |
|---|---|
| Workflow parsing | PyYAML |
| Optional utilities | requests |
| Standard library | os, sys, re, json, shlex, ast, dataclasses, typing, traceback |

---

## The two benchmarks

They answer different questions and **must never be combined into a single aggregate score.**

| | Dataset A | Dataset B |
|---|---|---|
| Purpose | Real-world false-alert behaviour and alert density | Controlled functional benchmark for path reachability |
| Size | 23,526 unique workflows across 4,880 repositories | 30 hand-written workflows, B01 to B30 |
| Annotated | 300 workflows, stratified | All 30, ground truth known by construction |
| Composition | 262 NO_EXFIL, 38 UNCLEAR, 0 EXFIL (v2 lock) | 18 exploit, 12 benign |
| Denominator | 262 workflows, 38 UNCLEAR excluded per protocol | 30 workflows |
| Metrics | False positive rate, alerts per 1,000 workflows | Precision, recall, F1 |
| Provenance | Crawled from public GitHub repositories via the Search API | Hand-crafted by the team, syntax-validated |

Recall is undefined on Dataset A because no confirmed EXFIL case was identified under the locked
annotation definition. The paper reports the false positive rate and alert density instead, and
says so explicitly rather than reporting a zero.

A third set, the **boundary benchmark**, holds 17 adversarial cases written to probe the limits of
the propagation model. It is reported separately and excluded from every metric in the paper.

### Dataset A collection procedure

Repositories were retrieved through the GitHub Search API on 5 September 2026:

- Public, non forked, non archived, at least 10 stars, pushed on or after 1 September 2025
- Stratified over 8 primary languages and 6 star bands, giving 48 cells, capped at 150
  repositories per cell
- All `.yml` and `.yaml` files under `.github/workflows/`, at most 256 KB per file and 20 files
  per repository

The crawl returned 23,995 files. After removing 17 unparseable files and 452 SHA-256 duplicates,
Dataset A contains 23,526 unique workflows across 4,880 repositories.

The 300-workflow annotation sample was drawn from four strata:

| Stratum | Corpus | Annotated |
|---|---|---|
| S1 both secret and sink | 2,204 (9.4 %) | 150 |
| S2 secret only | 9,310 (39.6 %) | 70 |
| S3 sink only | 1,258 (5.3 %) | 40 |
| S4 neither | 10,754 (45.7 %) | 40 |

S1 is oversampled roughly fivefold, so alert density measured on this sample is an upper bound
with respect to the corpus and must not be read as a deployment-wide rate without reweighting.

### Ground-truth lock files

The annotation labels are cryptographically locked. Two versions are published.

| Version | Labels | SHA-256 prefix | Role |
|---|---|---|---|
| v1, pre-detector | 265 NO_EXFIL, 35 UNCLEAR | `e9e819f9…` | Locked before any tool was executed |
| v2, post targeted audit | 262 NO_EXFIL, 38 UNCLEAR | `2aa0f8b7…` | Main result; the sensitivity analysis reports both |

```bash
sha256sum replication/1_ground_truth/ground_truth.csv
# must match the digest recorded in GROUND_TRUTH_LOCK_v2.md
```

The v1 label file was overwritten when v2 was locked. Its digest is preserved in
`GROUND_TRUTH_LOCK_v1.md`, and v1 is reconstructed from v2 plus `adjudication.csv` by
`src/15_audit_trail.py`; the reconstruction is recorded in `AUDIT_TRAIL.md`.

Two annotators independently reviewed the same 300 workflows under the locked annotation
guideline v1.0. Disagreements were resolved by the adjudication protocol in `replication/docs/`,
not by preferring one annotator.

---

## Reproducing the results in the paper

Run the first five commands from inside `replication/`, and the rest from the repository root.
The scripts resolve paths relative to the working directory, so the leading `cd` matters.

| Paper item | Command | Expected output |
|---|---|---|
| Table 3, audit summary | `cd replication`<br>`python3 src/11_finalize_ground_truth.py --verify` | Three `[OK]` lines; ground truth unchanged since locking |
| Table 4, Figure 3, Dataset A | `python3 src/12_build_master_results.py --metrics` | ExfilGuard 4.2 %, Gitleaks 1.5 %, Poutine 48.1 %, Zizmor 90.1 % |
| Sensitivity, v1 versus v2 | `python3 src/15_audit_trail.py` | v1 265/35, v2 262/38; ExfilGuard 5.3 % then 4.2 %, down 1.1 pp; ordering unchanged |
| Table 5, Dataset B | `python3 src/14_dataset_b.py --metrics` | ExfilGuard 18/0/12/0; Zizmor 16/11/1/2; Gitleaks and Poutine 0 TP |
| Dataset B validation | `python3 3_dataset_b/validate_dsb.py 3_dataset_b/` | 30 valid files, 0 errors |
| Figure 4, ablation | `cd ..`<br>`python3 run_ablation.py --dataset replication/3_dataset_b/workflows/` | 0/18, 11/18, 15/18, 18/18, precision 100 % throughout |
| CWD invariance regression test | `bash regress_test/test_cwd_invariance.sh` | PASS |
| Table 6, threshold sensitivity | `python3 sensitivity_threshold.py` | Dataset A 4.2 % at LOW and MEDIUM, 3.8 % at HIGH and CRITICAL; Dataset B recall 100 % from LOW to HIGH, 66.7 % at CRITICAL |
| Tables 7 and 8, boundary benchmark | `python3 score_boundary.py` | 3 TP, 12 FN, 1 FP, 1 TN over 15 exploits and 2 benign controls. Detected: B36, B39, B46. False alarm: B34 |
| Table 8, baselines on the boundary set | run in a **copy** of the repository:<br>`python3 src/14_dataset_b.py --prepare 6_dataset_b_extended`<br>`python3 src/14_dataset_b.py --run gitleaks` (then `zizmor`, `poutine`) | Gitleaks 0/15, Poutine 1/15, Zizmor 15/15 while alerting on all 17 inputs. `--prepare` overwrites `out_dsb/`, so never run it in the main checkout |

### Secret-related share of the baseline findings

The "fewer than 1 %" statement in the abstract is derived by counting entries in the `rules`
array of the raw findings files, not by summing the `findings` integer.

| Tool | Total findings | Secret-related | Share | Rules counted |
|---|---|---|---|---|
| Zizmor | 2,318 | 21 | 0.9 % | `github-env` (12), `overprovisioned-secrets` (6), `secrets-inherit` (3) |
| Poutine | 555 | 4 | 0.7 % | `job_all_secrets` (4) |

---

## Baseline tools

These exact versions must be used to reproduce the reported numbers.

| Tool | Version | Source |
|---|---|---|
| Gitleaks | v8.30.1 | github.com/gitleaks/gitleaks |
| Zizmor | v1.30.0 | github.com/woodruffw/zizmor |
| Poutine | v1.1.6 | github.com/boostsecurityio/poutine |

Re-running them is **optional**. Every reported metric is computed from the per-workflow verdicts
already stored in `replication/out/` and `replication/out_dsb/`, which `src/13_run_detectors.py`
produced from the raw output. No table in the paper requires the baseline tools to be installed.

<details>
<summary>Installation commands for the baseline tools</summary>

Gitleaks, PowerShell:

```powershell
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\tools"
Invoke-WebRequest -TimeoutSec 300 `
  -Uri "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_windows_x64.zip" `
  -OutFile "$env:USERPROFILE\tools\gitleaks.zip"
Expand-Archive -Path "$env:USERPROFILE\tools\gitleaks.zip" -DestinationPath "$env:USERPROFILE\tools" -Force
$env:Path += ";$env:USERPROFILE\tools"
gitleaks version
```

Zizmor, PowerShell:

```powershell
python -m pip install --user pipx
python -m pipx ensurepath
pipx install zizmor==1.30.0
zizmor --version
```

Poutine ships no Windows binary, so it runs inside WSL2:

```bash
curl -L -o poutine.tar.gz \
  "https://github.com/boostsecurityio/poutine/releases/download/v1.1.6/poutine_Linux_x86_64.tar.gz"
tar -xzf poutine.tar.gz && rm poutine.tar.gz
poutine version
```

Invocations used for the reported output:

| Tool | Dataset A | Dataset B |
|---|---|---|
| Gitleaks | `gitleaks dir replication/4_dataset_a_sample/ --report-format json --report-path <out>/gitleaks_dsa.json --exit-code 0` | same with `replication/3_dataset_b/workflows/` |
| Zizmor | `zizmor --format json replication/4_dataset_a_sample/ > <out>/zizmor_dsa.json` | same with `replication/3_dataset_b/workflows/` |
| Poutine | `poutine analyze_local --format json replication/4_dataset_a_sample/ > <out>/poutine_dsa.json` | same with `replication/3_dataset_b/workflows/` |

</details>

---

## Repository layout

```
ExfilGuard-static-taint-analysis/
├── main.py                    entry point, analyses one workflow file
├── exfilguard.py              separate single-file build, does NOT reproduce the paper
├── config.py                  DEFAULT_CONFIG, ablation switches
├── catalogs.py                source and sink catalogues, rule identifiers
├── risk_scoring.py            deterministic risk score R(P)
├── evaluate.py                built-in test suite
├── run_ablation.py            the four ablation configurations
├── sensitivity_threshold.py   recounts alerts at each reporting level
├── score_boundary.py          scores the boundary benchmark
├── analyzers/                 yaml, bash, python, nodejs analysers
├── engine/
├── scripts/                   external scripts referenced by test workflows
├── testcases/                 P01 to P22 positive, N01 to N10 negative
├── regress_test/test_cwd_invariance.sh
└── replication/               see below
```

### Replication package

| Path | Content |
|---|---|
| `replication/README.md` | How the scripts resolve paths, and the full command list |
| `replication/1_ground_truth/` | `ground_truth.csv`, `ground_truth_eval.csv`, three lock files, `AUDIT_TRAIL.md`, `adjudication.csv` (78 cases), `targeted_audit_ids.txt` (13 ids), `review_sheet.csv` and the two annotator label files |
| `replication/2_ket_qua/` | `master_results.csv`, `metrics.md`, `metrics_dsb.md`, `metrics_sensitivity.md`, `ablation_dsb.txt`, `dsb_index.csv` |
| `replication/3_dataset_b/` | 30 workflows B01 to B30, `scripts/`, `ground_truth.csv`, `validate_dsb.py` |
| `replication/4_dataset_a_sample/` | 300 annotated workflows, named `AXXXX__<original name>.yml` |
| `replication/5_baseline_output/` | Documentation of the raw output files stored in `out/` and `out_dsb/` |
| `replication/6_dataset_b_extended/` | Boundary benchmark: 17 workflows B31 to B47 plus two called workflows, `scripts/`, `ground_truth.csv`, `results.csv`, `raw/`, `baselines/`, `threshold_sensitivity.md` and `.csv`. Excluded from every metric in the paper |
| `replication/out/`, `out_dsb/` | Raw output of all four analysers for Dataset A and Dataset B |
| `replication/data/` | Flat working copy of `1_ground_truth/` and `2_ket_qua/`; the scripts read from this path |
| `replication/src/` | Scripts 01 to 15: crawling, filtering, annotation, locking, detector execution, metrics, audit trail |
| `replication/docs/` | Locked annotation guideline v1.0, adjudication protocol, metrics plan, error-analysis notes, baseline run log |
| GitHub Release asset | `dataset_a_corpus_raw.zip`, the 23,995 initially crawled files, 189 MB, too large for Git |

---

## Troubleshooting

| Issue | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'yaml'` | Activate the virtual environment, then `pip install -r requirements.txt` |
| `error: externally-managed-environment` | Create and activate a virtual environment, or use pipx for command-line tools |
| A script says `data/GROUND_TRUTH_LOCK.md` or `data/master_results.csv` is missing | The command ran from the repository root. Run `cd replication` first |
| `--verify` reports that `ground_truth.csv` changed since locking | The working copy under `replication/data/` was regenerated. Restore it from `replication/1_ground_truth/` and re-run |
| Ablation numbers do not match Figure 4 | `run_ablation.py` ran without `--dataset` and used `testcases/` instead of Dataset B |
| Results differ depending on the working directory | The build predates commit `b4e16ce`. Update and re-run `regress_test/test_cwd_invariance.sh` |
| Analysis returns an empty list for a valid workflow | The YAML is malformed. Run `validate_dsb.py`, or look for an unquoted colon inside a `run:` value |
| Numbers do not match the paper at all | You are probably running `exfilguard.py`. Use `main.py` |
| A tool download returns 404 | Check the asset name: `gitleaks_8.30.1_windows_x64.zip`, `gitleaks_8.30.1_linux_x64.tar.gz`, `poutine_Linux_x86_64.tar.gz` |
| `sha256sum` of a lock file does not match | The file was opened and re-saved by a spreadsheet application, which rewrites line endings. Restore it from the repository |

---

## Notes and known limitations

- **Gitleaks version invariance.** Dataset A was scanned with both v8.16.0 and v8.30.1. Both flag
  the same four workflows, A0039, A0235, A0251 and A0259, and the positive control fires the
  `github-pat` rule under both. The reported metrics are invariant; the paper reports v8.30.1.
- **Zizmor nominal recall versus discrimination.** Zizmor reaches 88.9 % recall on Dataset B but
  alerts on 11 of the 12 benign controls, including all four hard negatives built to contain no
  taint path. It returns the same three configuration findings for an exploit case and its benign
  counterpart, so its alerts reflect workflow hygiene rather than secret reachability. The same
  behaviour appears on the boundary benchmark, where it alerts on all 17 inputs.
- **One-way hashing is not a sanitiser.** Dataset B classifies B18 (`python_hash_then_http`) as an
  exploit because the hashed secret reaches an outbound sink, and B10 and B19 as benign because
  the hashed value is only logged. ExfilGuard models this policy.
- **Reconciling two counts of the same set.** `master_results.csv` marks 232 rows as
  `agreement-no-review` while `GROUND_TRUTH_LOCK_v2.md` records 222. The difference of 10 is the
  targeted-audit subset whose original NO_EXFIL labels were confirmed: those cases have an
  adjudication record but keep their original `path_type`. 232 minus 10 equals 222, consistent
  with the 78 total manual adjudications reported in the paper.
- **Known engine false negative.** Testcase P21 is an expected false negative: taint is not
  propagated through `$GITHUB_OUTPUT` to `steps.<step_id>.outputs.<name>`. The limitation is
  recorded in `CHANGELOG.md` and no claim in the paper depends on it.
- **Dataset B and ExfilGuard were built by the same team.** The perfect scores on Dataset B show
  that the implemented propagation rules behave as specified. They are not evidence of robustness
  against arbitrary real-world obfuscation. The boundary benchmark exists to make that limit
  concrete.
- **Reported results** were produced by the analysis engine as of commit `5279e4d`. Later commits
  fix a path-resolution defect, add the working-directory invariance test, declare a missing
  dependency, add the `--dataset` option and add the replication package. None of them changes a
  reported number, and all are listed in `CHANGELOG.md`. Reproduce from `main`, not from
  `5279e4d`, because the replication package does not exist at that commit.

---

## License

Code in this repository is released under the MIT License. See [LICENSE](LICENSE).

`replication/4_dataset_a_sample/` and the `dataset_a_corpus_raw.zip` release asset contain
workflow files collected from public third-party repositories. Those files are **not** covered by
the MIT License; they remain under the licences of their original projects and are redistributed
here only to support verification of the published results. See the scope note in `LICENSE`.
