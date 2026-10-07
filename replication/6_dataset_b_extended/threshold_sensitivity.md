# Threshold sensitivity for ExfilGuard

Alerts recounted at each minimum risk level, using the same analyser configuration as the published results. The published numbers use MEDIUM.

## Dataset A

Total 300 workflows, of which 262 are adjudicated and 38 remain unclear. No positive instance, so only the false positive rate is defined.

| Minimum risk level | Alerts | False positive rate | Alerts per 1000 |
|---|---|---|---|
| LOW | 11 | 4.2 % | 42.0 |
| MEDIUM | 11 | 4.2 % | 42.0 |
| HIGH | 10 | 3.8 % | 38.2 |
| CRITICAL | 10 | 3.8 % | 38.2 |

## Dataset B

30 cases, 18 exploit and 12 benign.

| Minimum risk level | TP | FN | FP | TN | Recall | False positive rate |
|---|---|---|---|---|---|---|
| LOW | 18 | 0 | 0 | 12 | 100.0 % | 0.0 % |
| MEDIUM | 18 | 0 | 0 | 12 | 100.0 % | 0.0 % |
| HIGH | 18 | 0 | 0 | 12 | 100.0 % | 0.0 % |
| CRITICAL | 12 | 6 | 0 | 12 | 66.7 % | 0.0 % |

## Extended boundary benchmark

17 cases, 15 exploit and 2 benign.

| Minimum risk level | TP | FN | FP | TN | Recall | False positive rate |
|---|---|---|---|---|---|---|
| LOW | 3 | 12 | 1 | 1 | 20.0 % | 50.0 % |
| MEDIUM | 3 | 12 | 1 | 1 | 20.0 % | 50.0 % |
| HIGH | 2 | 13 | 1 | 1 | 13.3 % | 50.0 % |
| CRITICAL | 1 | 14 | 1 | 1 | 6.7 % | 50.0 % |
