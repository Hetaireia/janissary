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