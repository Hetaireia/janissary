# Amendment 23 — Precision Measurement Program (Pre-registration)

**Status:** Active
**Baseline commit of record:** `e5b484078223f626e32b7ab8552ee947ff71253d` (tag `7.5.0`)
**Related artifacts:** `artifacts/7.5.0-baseline/`, `BENCHMARK.md`

## Purpose

This amendment pre-registers the measurement program that replaces the current dev-split figures with a real-world false-positive bound, a locked held-out precision estimate, and external reproductions.

Sequencing rule: **measure, harden on dev data only, freeze, test once.** Detector changes against held-out targets are prohibited. Improving detectors against the held-out set invalidates it.

## Corpora and splits

### Dev splits (hardening may use these)
- OWASP Benchmark DAST-applicable corpus (existing dev split, `benchmark/track_a/`)
- Calibration split (separate; do not tune on it)

### Held-out positives (locked before Phase 3)
- WebGoat
- DVWA ("impossible" level serves as negatives)
- bWAPP
- OWASP Juice Shop
- WAVSEP (ships explicit false-positive cases)
- OWASP BenchmarkPython
- Availability and licensing verified before inclusion.

Target: 300+ labelled vulnerable cases across 5+ suites.

### Real-world negatives (locked, self-hosted, pinned)
- CMSs: WordPress, Ghost
- Code hosting: Gitea
- Forums: Discourse
- Files: Nextcloud
- Dashboards: Grafana
- SPAs with catch-all routing
- GraphQL and REST APIs
- ModSecurity or CDN fronting on a domain owned by the maintainer

Target: 60+ apps, 1,500+ trials.

## Unit of trial

`(target, endpoint, parameter)`

## Interval method

Clopper-Pearson, cluster-aware by target. Parameters within one app are not treated as independent.

## FP rubric

- **Confirmed FP** — scanner reported a vulnerability that does not exist.
- **Confirmed real bug** — scanner reported a vulnerability that does exist, even if out of scope.
- **Unverifiable** — insufficient evidence to adjudicate.

Only confirmed FPs count toward the false-positive rate. Unverifiable findings are excluded from the numerator and reported separately.

## Freeze rules

- Release-candidate tag is recorded before any locked-set access.
- Commit hash of that tag is written into this amendment.
- Locked set runs three times in fresh containers, single-process.
- Competitors run on identical targets and identical time budgets using the same scoring script.

## Recall-loss budget

Maximum recall loss during hardening: **3 points** on the dev split. Exceeding this budget blocks the change regardless of precision gain.

## Claim ladder

Publish only what passes:

- **A.** Real-world FP rate <= X% (95% upper bound, cluster-aware). `X` resolved by Phase 1.
- **B.** Held-out precision >= Y (95% lower bound), with recall reported next to it. `Y` resolved by Phase 3.
- **C.** Significantly lower FP rate than tool Z on shared negatives (McNemar); otherwise "not distinguishable."
- **D.** Reproduced independently by N researchers. `N` is the count achieved in Phase 4.

"Best-in-class" is justified only if A-C hold. Precision and recall are always reported together; competitors may win on recall.

## Burned-data rule

Any fix made after seeing locked-set results ships under a new tag. Both results are published. That set is retired in favor of a fresh blind set. If a third party runs the blind set after the freeze, that supersedes any burned set.

## Public comment window

Harness invocations are pre-registered (default plus a tuned arm). A two-week public comment window precedes any measurement run.

## Publication commitment

Results are published whichever way they fall, including locked-set precision below 1.0. A claim that fails the ladder is reported as failed, not omitted.

## Phase 0 exit record

- Baseline commit: `e5b484078223f626e32b7ab8552ee947ff71253d` (tag `7.5.0`)
- Baseline artifacts: `artifacts/7.5.0-baseline/`
- Original README preserved at `artifacts/7.5.0-baseline/raw/README.orig.md`
- Current README rewritten to remove the standalone 1.000 headline from the primary claim position and to qualify dev-split figures.
- Pending: values for `X`, `Y`, `N`; Phase 1 corpora verification; Item 9 external reproducer recruitment.

## Amendment log

- 2026-10-27 - Initial draft for Phase 0 exit.
### 2026-10-28 - Phase 1 blocker and prior-run audit

- Docker Desktop daemon will not start. Baseline scans are blocked until target infrastructure is available.
- Audit of `benchmark/track_a/runs/`: every existing run carries `tool_version: 7.3.0`. The README's 1.000 precision figure is inherited from 7.3.0 via the non-scoring-path claim for 7.4/7.5.0; it is not measured on 7.5.0. A fresh 7.5.0 measurement is required by this amendment before any 7.5.0 precision claim is made.
- `src/`, `pyproject.toml`, `setup.py`, `setup.cfg` are identical between tag `7.5.0` and `main`. The editable install at the repo root therefore runs the same scanner source as the 7.5.0 tag; a reinstall is not required for reproducibility.
- Preparation completed while blocked: invocation configs (default + tuned arms) and run script under `artifacts/7.5.0-baseline/invocations/`. Status tracked in `artifacts/7.5.0-baseline/PHASE-1-STATUS.md`.

### 2026-10-28 - Baseline measured on 7.5.0 (n=3)

First empirical 7.5.0 measurement completed. Scanner: `janissary 7.5.0` (editable install; `src/` identical to tag). Target: OWASP Benchmark Java `20cbf3d11123347e47ed89541e6942836def53f7`, container `20cbf3d-ldapfix-v2`. Invocation: `tools_default.env` (`JANISSARY_TIMEOUT=180`). Runner: harness `5764d76`.

| Run | Precision | Recall | F1 | Wall time |
|---|---|---|---|---|
| 1 | 1.000 | 0.831 | 0.908 | 54m 22s |
| 2 | 1.000 | 0.830 | 0.907 | 52m 51s |
| 3 | 1.000 | 0.824 | 0.904 | 52m 15s |

Aggregate (DAST-applicable, sample std): Precision 1.0000 +/- 0.0000; Recall 0.8283 +/- 0.0038; F1 0.9063 +/- 0.0021.

Findings:

- **Precision = 1.000, FP = 0, in all three runs.** The dev-split precision claim is now empirically reproduced on 7.5.0 specifically. This closes the gap identified on 2026-10-28 between the README claim and the fact that all prior on-disk runs were `tool_version: 7.3.0`.
- **The unassisted F1 is 0.906 +/- 0.002 (n=3)**, which is tighter and statistically indistinguishable from the historical unassisted 0.903 +/- 0.009. The README's 0.921 headline is the FN-recovery protocol figure (Amendment 20), not the unassisted baseline.
- Zero `timeouts.jsonl` entries across all three runs. Zero `wrong_family` and zero `orphan`.
- Container remained healthy across the full 2h 40m; no restarts required.
- Per-run scores and the three-run summary are under `artifacts/7.5.0-baseline/summary/` and `benchmark/track_a/runs/`.

This does NOT publish a real-world FP rate, held-out precision, competitor comparison, or independent reproduction. Those remain Phase 3/4 claims under this amendment.

README has NOT been updated to reflect these numbers yet; that is a separate editorial step to be reviewed before it lands.

### 2026-10-28 - FN-recovery pre-registration for 7.5.0 baseline

Pre-registering the FN-recovery pass (Amendment 20 protocol) against the 7.5.0 baseline r1 (`20261027T220142Z-janissary-r1`) before running it. Same rule as Amendment 23: no post-hoc tuning. This applies a documented protocol to a new baseline, not a new tuning method.

Protocol (matches Amendment 20 and the historical `r1+rec` construction):

1. Compute FN set: `vulnerable == "true"` AND `testname not in fired`. `fired` = set of testnames with at least one finding in r1 (`findings.jsonl`). Matches `run_with_recovery.py` line 143-148 logic.
2. Write FN-only CSV under `benchmark/track_a/_chunks/fn_recovery_7_5_0.csv` with the same schema as `case_vectors.csv`.
3. Run `runner.py --tool janissary --run-number 2` against the FN-only CSV with `tools_default.env` (`JANISSARY_TIMEOUT=180`), fresh run directory.
4. Merge: concatenate r1 `findings.jsonl` + FN-pass `findings.jsonl` into a new `+rec` directory. Base manifest = r1 manifest + `recovery_run` and `recovery_protocol` keys (historical `r1+rec` shape). `skipped.jsonl` and `timeouts.jsonl` copied from r1 unchanged.
5. Score the merged `+rec` directory. Report full-corpus and DAST-applicable P/R/F1.

Expected magnitude: ~+30 to +35 recovered TP (Amendment 20 recovered 32 of 204 FN). Recovery F1 expected in 0.92-0.93 range. If materially below 0.920, this is a finding to publish, not a reason to retune.

### 2026-10-28 - FN-recovery result: 7.5.0 matches 7.3.0 exactly

FN-recovery pass completed against 7.5.0 r1 (`20261027T220142Z-janissary-r1`). Recovery-only run directory: `20261028T065425Z-janissary-r2` (9m 59s, 454 cases, 101 findings). Merged: `20261027T220142Z-janissary-r1+rec`.

| Metric | Historical 7.3.0 `r1+rec` | Measured 7.5.0 `r1+rec` |
|---|---:|---:|
| TP | 987 | **987** |
| FP | 0 | **0** |
| FN | 169 | **169** |
| TN | 1102 | **1102** |
| Precision | 1.000 | **1.000** |
| Recall | 0.854 | **0.854** |
| F1 | 0.921 | **0.921** |

Every count is identical. The README claim "F1 unchanged through 7.4.0 and 7.5.0" is now empirically verified, not asserted.

Notes:

- Recovery added +26 TP (961 -> 987). FP stayed at 0. wrong_family=0, orphan=0 before and after.
- Divergence from historical procedure: FN candidate set was 454 (full corpus) not 206 (DAST-applicable only). This matches `run_with_recovery.py` line 143-148, which does not consult `dast_excluded.txt`. The 248 extra cases in excluded categories contributed no DAST-applicable findings, so the merged result is unaffected.
- An abandoned run dir `20261028T064156Z-janissary-r2` from an interrupted attempt was deleted before this commit. Its absence is intentional.
- The 0.921 headline in README now has a measurement provenance on 7.5.0. No number changed; only the label.
- All other Amendment 23 claims (real-world FP rate, held-out precision, competitor comparison, independent reproduction) remain unpublished Phase 3/4 items.
