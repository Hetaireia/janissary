# 7.5.0 Baseline - Three-Run Summary

**Generated:** 2026-10-28T06:25:43Z  
**Repo:** `C:\Users\M5 E60\janissary-project\janissary\janissary`  
**Baseline commit of record:** `e5b484078223f626e32b7ab8552ee947ff71253d` (tag 7.5.0)  
**Scanner:** `janissary 7.5.0` (editable install; `src/` identical between 7.5.0 tag and HEAD)  
**Target:** OWASP Benchmark Java `20cbf3d11123347e47ed89541e6942836def53f7`  
**Invocation:** `tools_default.env` (JANISSARY_TIMEOUT=180)

## Result

Precision = **1.000, FP = 0, in all three runs.**

The dev-split precision claim is now empirically reproduced on 7.5.0 with n=3.

## Per-run

| Run | Dir | Wall time | Precision | Recall | F1 |
|---|---|---|---|---|---|
| 1 | `20261027T220142Z-janissary-r1` | 54m 22s | 1.000 | 0.831 | 0.908 |
| 2 | `20261027T230832Z-janissary-r2` | 52m 51s | 1.000 | 0.830 | 0.907 |
| 3 | `20261028T000025Z-janissary-r3` | 52m 15s | 1.000 | 0.824 | 0.904 |

## Aggregate (DAST-applicable, n=3, sample std)

| Metric | Mean | Std | Range |
|---|---|---|---|
| Precision | 1.0000 | 0.0000 | [1.0000 .. 1.0000] |
| Recall | 0.8283 | 0.0038 | [0.8240 .. 0.8310] |
| F1 | 0.9063 | 0.0021 | [0.9040 .. 0.9080] |

## Comparison to README claim

| Metric | README claim | This baseline (unassisted) | Delta |
|---|---|---|---|
| Precision | 1.000 (0 FP) | **1.000 (0 FP)** | **matched** |
| Recall | 0.854 | 0.828 | -0.026 |
| F1 | 0.921 | 0.906 | -0.015 |
| Historical unassisted 3-run | 0.903 ± 0.009 | **0.906 ± 0.002** | **+0.003, tighter** |

The 0.921 headline is the **FN-recovery protocol** figure (Amendment 20). The unassisted 7.5.0 measurement is 0.906 ± 0.002, which is consistent with — and tighter than — the historical unassisted 0.903 ± 0.009.

## What this does NOT claim

- **No real-world false-positive rate.** That is Phase 3 (locked set) under Amendment 23 Item A.
- **No held-out precision.** That is Phase 3 under Item B.
- **No competitor comparison.** That is Phase 3 under Item C.
- **No independent reproduction.** That is Phase 4 under Item D.

The claim justified by this baseline is narrow and exact:

> **On the OWASP Benchmark DAST-applicable dev split, `janissary 7.5.0` produced zero false positives in three independent runs** (P=1.000, 0 FP, n=3).

## Provenance

- Container: `janissary/owasp-benchmark:20cbf3d-ldapfix-v2` (built from current `20cbf3d` base + repo `entrypoint.sh` with HSQLDB schema-init and LDAPServer startup fixes).
- Runner: `benchmark/track_a/runner.py` at harness commit `5764d76d946ed7cbdf7f28db24e34df707111016`.
- Manifest tool_version: `7.5.0` on every run.
- Zero entries in any `timeouts.jsonl`; zero `wrong_family`; zero `orphan`.

## Artifacts

- Per-run scores: `artifacts/7.5.0-baseline/summary/run-{1,2,3}-score.txt`.
- Raw run directories: `benchmark/track_a/runs/20261027T220142Z-janissary-r1/`, `.../20261027T230832Z-janissary-r2/`, `.../20261028T000025Z-janissary-r3/`.
- Invocation config: `artifacts/7.5.0-baseline/invocations/tools_default.env`.

