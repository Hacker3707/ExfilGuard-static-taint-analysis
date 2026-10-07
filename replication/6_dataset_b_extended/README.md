# Extended boundary benchmark

Ten adversarial workflows, nine exploits and one benign control, built to
probe the limits of the propagation model. This set is NOT part of Dataset B
and is excluded from every metric reported in the paper.

- `workflows/` ten workflow files, B31 to B40
- `scripts/` helper scripts referenced by B32 and B40
- `ground_truth.csv` label and expected taint path for each case
- `results.csv` detector verdict for each case
- `raw/` full ExfilGuard output for each case

Result: 1 of 9 exploits detected, 1 false alarm on the benign control.
