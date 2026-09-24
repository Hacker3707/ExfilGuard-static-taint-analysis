# Replication package

Chay moi lenh tu trong thu muc `replication/`, tru ablation va regression test
chay tu thu muc goc cua repository.

Cac script trong `src/` phan giai duong dan tuong doi theo thu muc dang chay,
nen chung doc `data/`, `docs/`, `out/` va `out_dsb/`. Thu muc `data/` la ban sao
phang cua `1_ground_truth/` va `2_ket_qua/`, ton tai de script chay duoc; noi
dung giong het, chi khac cach sap xep.

## Lenh tai lap ket qua

    cd replication
    python3 src/11_finalize_ground_truth.py --verify
    python3 src/12_build_master_results.py --metrics
    python3 src/15_audit_trail.py
    python3 src/14_dataset_b.py --metrics
    python3 3_dataset_b/validate_dsb.py 3_dataset_b/

    cd ..
    python3 run_ablation.py --dataset replication/3_dataset_b/workflows/
    bash regress_test/test_cwd_invariance.sh
