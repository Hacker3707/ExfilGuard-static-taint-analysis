# Metrics — Dataset B (controlled benchmark)

- Tong ca: **30** (18 exploit, 12 benign)
- Scenario: **6**

> Dataset B CO positive nen P/R/F1 tinh duoc. Dataset A khong. Hai bang phai de rieng, khong gop.

## Tong the

| Tool | TP | FP | TN | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| exfilguard | 18 | 0 | 12 | 0 | 100.0% | 100.0% | 100.0% |
| gitleaks | 0 | 0 | 12 | 18 | n/a | 0.0% | n/a |
| poutine | 0 | 0 | 12 | 18 | n/a | 0.0% | n/a |
| zizmor | 16 | 11 | 1 | 2 | 59.3% | 88.9% | 71.1% |

## Recall theo scenario

| Tool | S1_Direct_Secret_Curl | S2_Secret_Variable_Curl | S3_Secret_Bash_HTTP | S4_Secret_Python_Requests | S5_Secret_Node_HTTP | S6_Secret_DNS_Sink |
|---|---|---|---|---|---|---|
| exfilguard | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 |
| gitleaks | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 |
| poutine | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 |
| zizmor | 2/3 | 3/3 | 3/3 | 3/3 | 3/3 | 2/3 |

## Recall theo difficulty

| Tool | easy | hard | medium |
|---|---|---|---|
| exfilguard | 2/2 | 10/10 | 6/6 |
| gitleaks | 0/2 | 0/10 | 0/6 |
| poutine | 0/2 | 0/10 | 0/6 |
| zizmor | 2/2 | 9/10 | 5/6 |

## Ca sai — doc tung ca de viet error analysis

**exfilguard**: khong sai ca nao.
**gitleaks** (18 ca sai)

| case | loai | difficulty | pattern |
|---|---|---|---|
| B01 | FN | easy | direct_secret_to_curl |
| B02 | FN | medium | direct_secret_to_curl |
| B03 | FN | hard | concatenated_secret_to_curl |
| B06 | FN | easy | one_hop_propagation |
| B07 | FN | medium | three_hop_propagation |
| B08 | FN | hard | base64_then_curl |
| B11 | FN | medium | embedded_bash_http |
| B12 | FN | hard | bash_base64_http |
| B13 | FN | hard | bash_multi_hop_http |
| B16 | FN | medium | python_requests_post |
| B17 | FN | hard | python_json_propagation |
| B18 | FN | hard | python_hash_then_http |
| B21 | FN | medium | node_fetch_body |
| B22 | FN | hard | node_concat_http |
| B23 | FN | hard | node_multihop_http |
| B26 | FN | medium | nslookup_secret_subdomain |
| B27 | FN | hard | dig_secret_subdomain |
| B28 | FN | hard | python_dns_sink |

**poutine** (18 ca sai)

| case | loai | difficulty | pattern |
|---|---|---|---|
| B01 | FN | easy | direct_secret_to_curl |
| B02 | FN | medium | direct_secret_to_curl |
| B03 | FN | hard | concatenated_secret_to_curl |
| B06 | FN | easy | one_hop_propagation |
| B07 | FN | medium | three_hop_propagation |
| B08 | FN | hard | base64_then_curl |
| B11 | FN | medium | embedded_bash_http |
| B12 | FN | hard | bash_base64_http |
| B13 | FN | hard | bash_multi_hop_http |
| B16 | FN | medium | python_requests_post |
| B17 | FN | hard | python_json_propagation |
| B18 | FN | hard | python_hash_then_http |
| B21 | FN | medium | node_fetch_body |
| B22 | FN | hard | node_concat_http |
| B23 | FN | hard | node_multihop_http |
| B26 | FN | medium | nslookup_secret_subdomain |
| B27 | FN | hard | dig_secret_subdomain |
| B28 | FN | hard | python_dns_sink |

**zizmor** (13 ca sai)

| case | loai | difficulty | pattern |
|---|---|---|---|
| B02 | FN | medium | direct_secret_to_curl |
| B05 | FP | medium | dummy_named_secret |
| B09 | FP | hard | masked_before_logging |
| B10 | FP | medium | secret_hash_only |
| B14 | FP | hard | masked_bash_log |
| B15 | FP | hard | dummy_bash_http |
| B19 | FP | hard | python_hash_only |
| B20 | FP | medium | python_fixed_http |
| B24 | FP | hard | node_dummy_http |
| B25 | FP | medium | node_fixed_http |
| B27 | FN | hard | dig_secret_subdomain |
| B29 | FP | hard | fixed_dns_lookup |
| B30 | FP | hard | secret_masked_no_dns |

