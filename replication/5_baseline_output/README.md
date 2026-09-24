# Baseline and detector raw output

The output files are stored one level up, in `replication/out/` for Dataset A and
`replication/out_dsb/` for Dataset B, because the parsing scripts in
`replication/src/` read them from those fixed locations.

Each tool produces a `.csv` with one row per workflow carrying the binary verdict,
and a `_findings.jsonl` with one record per workflow listing every rule that fired.
The `.csv` files feed `src/12_build_master_results.py` and `src/14_dataset_b.py`.
Finding-level counts below are obtained by counting entries in the `rules` array of
the `.jsonl` files.

## Dataset A (`replication/out/`)

All counts are over the 300 annotated workflows. The paper reports rates over the
262 evaluable workflows, obtained by excluding the 38 UNCLEAR cases.

| Tool | Workflows flagged | Of which NO_EXFIL | Of which UNCLEAR | Findings |
|---|---|---|---|---|
| ExfilGuard | 18 | 11 (FPR 4.2%) | 7 | 37 |
| Gitleaks v8.30.1 | 4 | 4 (FPR 1.5%) | 0 | 16 |
| Zizmor v1.30.0 | 272 | 236 (FPR 90.1%) | 36 | 2,318 |
| Poutine v1.1.6 | 151 | 126 (FPR 48.1%) | 25 | 555 |

### Secret-related findings

Zizmor: 21 of 2,318 findings, that is 0.9%, come from the three rules that concern
secret handling, namely `github-env` (12), `overprovisioned-secrets` (6) and
`secrets-inherit` (3). The remaining findings concern supply-chain and permission
posture, led by `unpinned-uses` (922), `artipacked` (561), `template-injection` (406)
and `excessive-permissions` (225).

Poutine: 4 of 555 findings, that is 0.7%, come from `job_all_secrets`. The remaining
findings are led by `github_action_from_unverified_creator_used` (386),
`known_vulnerability_in_build_component` (50) and `untrusted_checkout_exec` (41).

These two figures are the evidence behind the "fewer than 1 %" statement in the
abstract and in Section 4.2.

### The four Gitleaks alerts

A0039 (`discord-client-id`, 8 findings), A0235, A0251 and A0259 (`generic-api-key`,
1 to 2 findings each). Manual review confirmed all four are high-entropy strings that
are public by design: a GPG key fingerprint published to a keyserver, and commit SHAs
used to pin actions, which is itself a security best practice.

### Auxiliary files

| File | Purpose |
|---|---|
| `zizmor_filtered.csv`, `zizmor_filtered_findings.jsonl` | Convenience re-run of `13_run_detectors.py --only-rules`, kept for inspection. The authoritative secret-related count is the 21 derived from the `rules` field of the unfiltered output. |
| `exfilguard_bench.csv`, `exfilguard_bench_findings.jsonl` | ExfilGuard over the repository test suite in `testcases/`, kept for regression comparison. Not used for any number in the paper. |
| `gitleaks_8.16.0.csv` | Earlier run with the Ubuntu apt package. Both versions flag the same 4 workflows; the paper reports v8.30.1. |
| `controls/gitleaks-positive-control.json` | A mock GitHub PAT that Gitleaks detects through its `github-pat` rule, establishing that its zero recall on Dataset B is a property of the benchmark rather than a misconfiguration. |
| `controls/versions.txt` | Tool versions used for the reported runs. |

## Dataset B (`replication/out_dsb/`)

| Tool | TP | FP | TN | FN |
|---|---|---|---|---|
| ExfilGuard | 18 | 0 | 12 | 0 |
| Zizmor | 16 | 11 | 1 | 2 |
| Gitleaks | 0 | 0 | 12 | 18 |
| Poutine | 0 | 0 | 12 | 18 |

Gitleaks and Poutine detect nothing because Dataset B references credentials
symbolically through `${{ secrets.* }}` rather than as hardcoded literals, and
because Poutine targets supply-chain and permission policy rather than
embedded-script data flow.
