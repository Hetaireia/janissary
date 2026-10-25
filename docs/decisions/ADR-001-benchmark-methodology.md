# ADR-001: Benchmark methodology

**Status:** Accepted
**Date:** 2026-10-25
**Supersedes:** the narrative spread across `BENCHMARK.md` Amendments 19-22 (as a single normative reference; the amendments remain as audit trail)

## Context

JANISSARY's positioning is precision, not scale. A precision claim requires a reproducible, honest benchmark. The benchmark accumulated across Amendments 19-22 of `BENCHMARK.md` without a single methodology document. Each amendment was correct at the time, but a reader encountering the repo for the first time had no single place to understand *how* the numbers were produced or *what* they do and do not measure. This ADR consolidates that methodology and sets the rules for future claims.

## Decision

### Corpus

The benchmark is scored against the **OWASP Benchmark DAST-applicable subset** only.

- Full corpus: 2,740 cases (`benchmark/track_a/case_vectors.csv`)
- DAST-applicable: 2,258 cases
- Excluded: 236 hash + 246 crypto cases
  (`benchmark/track_a/dast_excluded.txt`)

Reporting on the DAST-applicable subset is mandatory. The FULL CORPUS number may appear as a secondary figure but **never as the headline**. Rationale: hash and crypto categories test cryptographic function selection, not web injection. A DAST tool that scores on those is measuring the wrong thing.

### Protocol

The protocol is a **3-run unassisted baseline + FN-recovery pass**.

- **Baseline:** 3 fresh runs, fresh target container per run, same commit, same case set. Each run is scored independently.
- **Recovery:** a second pass over the zero-finding subset of a baseline run, with `JANISSARY_TIMEOUT=180`. The recovery pass is applied per-run and reported both per-run and as a merged figure.
- **Skip parity:** skipped cases must match across runs. A run with a different skip set is not comparable and must be re-run or explicitly annotated. The 93-skip set of r1/r2/r3 in the current baseline is a fixed property of the case corpus plus tool scope; a future run with 80 or 100 skips signals a scope change that requires re-baselining.
- **Timeout accounting:** a timeout is recorded as a false negative, not excluded. This is a conservative choice: a scanner that cannot finish a case has not demonstrated detection.

Rationale: single-run variance is material. Observed F1 on the same commit across three runs: 0.902, 0.913, 0.895. Treating one run as truth would be a claim the data does not support. Three runs gives a defensible mean and a stated standard deviation.

### Disclosure norms

Every published benchmark number must state, in the same paragraph or table:

1. Baseline mean and standard deviation (n=3)
2. Recovery number, and which baseline runs it was applied to
3. Skip count and whether it matched the other runs
4. Timeout count and their treatment (counted as FN)
5. Any crashes, and whether they affected the scored run

The recovery number may be **higher** than the baseline mean (currently 0.921 vs 0.903). This is expected — the recovery protocol targets specifically the cases a baseline run missed. It must be disclosed within two lines of the recovery number itself, not in a footnote or a linked document. A skeptical reader noticing the gap between 0.921 and 0.903 is doing exactly what a skeptical reader should do.

### Threshold gate

CI enforces two checks:

- **PR gate (implemented, `.github/workflows/benchmark-gate.yml`):** deterministic rescore of the committed `r1+rec` run. `--min-f1 0.92 --max-fp 0`. Catches scorer regressions and committed-artifact drift. It does **not** catch detection regressions — that is the nightly gate's job.
- **Nightly gate (planned, Phase 0.1b):** end-to-end run against a published target image, 500-case stratified subset or full corpus, `--min-f1 0.89 --max-fp 0`. Currently blocked on two prerequisites: (a) OWASP Benchmark image not on a public registry, (b) `benchmark/track_a/tools.env` hardcodes a Windows `JANISSARY_BIN` path.

Rationale for the split: PR feedback must be fast (seconds, not minutes) and deterministic. Detection regressions are worth catching but not at a 15-65 minute cost per push.

### Amendment trail

`BENCHMARK.md` Amendments 19-22 remain in the repo as the audit trail. This ADR is the normative summary. If an amendment and this ADR conflict, this ADR wins. If a claim here is discovered to be wrong, this ADR is amended and the benchmark is re-run — the ADR is not retroactively edited.

## Consequences

- Every new benchmark claim requires a fresh 3-run, or an explicit annotation that it is a single run with a stated reason. The annotation is not a substitute for the protocol; it is an admission that the protocol was not followed.
- Amendment-style addenda to `BENCHMARK.md` remain valid for detailed findings (e.g. a specific per-category regression or a recovered TP breakdown). They must not contradict this ADR.
- The 0.921 recovery headline is stable until a new 3-run baseline supersedes it. A single re-run — even one that reproduces 0.921 exactly — does not supersede it. Supersession requires a fresh 3-run.
- Any future change to the corpus (adding/removing cases), the exclusion set, or the protocol itself is an ADR-level change, not an amendment.

## References

- `BENCHMARK.md` — Amendments 19-22 (audit trail)
- `benchmark/track_a/score_dast_aware.py` — reference implementation
- `.github/workflows/benchmark-gate.yml` — CI gate (PR)
- `README.md` — benchmark section (user-facing summary)