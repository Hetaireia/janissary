# M83 Aggregation Rule

**Prepared:** 2026-11-15
**Status:** Accepted current benchmark policy
**Authority:** Strategic roadmap Stage 1 exit, M83 report item 11
**Scope:** Documentation of existing behaviour. No code, test, corpus, or milestone change.

## 1. Purpose

This document records the aggregation rule that `benchmark/track_a/score_dast_aware.py` currently applies when mapping findings to benchmark case outcomes. It exists because the rule was implicit in code, not stated in documentation.

The rule is an accepted policy choice for the current benchmark. It is not a universal property of benchmark scoring, and alternative rules could be justified with different objectives.

## 2. The rule

**A benchmark case is detected if and only if at least one finding exists on that case's URL path, with a finding family that matches the case's benchmark category family.**

Three properties define the rule:

1. **Family-scoped.** Only findings whose family matches the case's category family count. An `xss` finding on an `xss-01` case counts. An `ssrf` finding on an `xss-01` case does not — SSRF has no benchmark category and is excluded.
2. **Path-keyed.** The finding's URL path (after stripping the `/benchmark` prefix) must map to a case in the corpus. A finding on a path not in the corpus is an orphan and counts toward nothing.
3. **Any-finding-wins.** One matching finding is sufficient. Multiple findings on the same path are collapsed. Threshold rules (e.g. N findings required) are not applied.

## 3. Implementation locations

**Scorer:** `benchmark/track_a/score_dast_aware.py`

- `:24` — `OUT_OF_SCOPE_CLASSES = {"ssrf"}` — findings whose class is in this set are counted as out-of-scope and never reach the detection path
- `:9-22` — `FAMILY_OF` — maps finding classes to benchmark families; `sqli_blind` maps to `sqli`, other classes map to their own name
- `:56` — `def score(run_dir, cases_csv, label="full")` — the top-level scorer
- `:66-67` — reads `findings.jsonl` from the run directory; this is the sole input the rule consumes
- `:82-85` — for each finding, after orphan and out-of-scope filtering, compute `emitted_fam = FAMILY_OF.get(d["class"], d["class"])` and `truth_fam = family(by_path[p]["category"])`; if equal, record the family against the path in `correct_on_path[p]`
- `:90` — `def tally(filter_excluded)` — converts `correct_on_path` into TP/FP/FN/TN
- `:100` — `vuln = c["vulnerable"].strip().lower() == "true"` — the ground-truth label is read from the case vectors CSV
- `:101` — `detected = family(cat) in correct_on_path.get(c["urlpath"], set())` — the aggregation test applied per case

**Recovery merge:** `benchmark/track_a/run_with_recovery.py`

- `:2-7` — docstring: "FN recovery pass on top of a Track A runner run... that subset, and merges both findings files into a recovered run dir"
- `:67` — `def _fired_cases(run_dir)` — identifies testnames with findings in pass 1
- `:108` — `def _merge(pass1, pass2, out_dir)` — produces the merged run directory
- `:123` — `def main()` — orchestrates pass 1, computes the zero-finding vulnerable subset, runs pass 2 on that subset, calls `_merge`
- `:164-166` — the merged directory is created as `merged-recovery-{stamp}` and logged

Scoring operates on the merged `findings.jsonl` identically to a normal run. The scorer does not distinguish pass-1 findings from pass-2 findings, and does not know whether a given finding was produced by the original or recovery pass.

## 4. Recovery-pass semantics

The `run_with_recovery.py` driver produces a merged run directory from two passes:

1. **Pass 1** — normal runner invocation against the full corpus.
2. **Pass 2** — runner invocation against the subset of vulnerable cases with zero findings in pass 1.
3. **Merge** — the combined run directory contains findings from both passes.

**Accepted current behaviour:** the merged findings are the union of pass-1 and pass-2 findings. The scorer is applied to the merged file identically to a normal run. Any finding present in either pass contributes identically to detection.

**Consequence:** the merged run's precision and recall reflect the union of both passes. A case detected only in pass 2 is scored the same as a case detected in pass 1. Whether second-pass findings should be flagged as "recovered after retry" rather than counted identically is a separate question, not addressed by this policy. It is outside the scope of what this document records.

## 5. Alternative rules not currently used

Recorded here for clarity on why the current rule is what it is. None of these are proposed as replacements; they are documented as alternatives considered and not adopted.

**Threshold rule** — case detected only if at least N findings, or at least a fraction of payload attempts, produce findings. Not used. Reason: the corpus provides case-level `vulnerable` labels but no per-payload expected outcomes, so a threshold rule cannot be calibrated from the data. A case-level label says "vulnerable"; it does not say how many payloads should fire.

**Recorder-aware rule** — case detected if the recorder's per-case classification is `delivered` under the frame's taxonomy (`docs/l03_sqli_classification.md` section 2). Not used for three reasons: (a) the recorder's classification is traversal-specific, not applicable to the 11 other benchmark categories; (b) the taxonomy's `delivered` requires reproducibility across runs, which the current scorer does not track; (c) no scorer or tool currently consumes recorder output — see M83 report section 5.2.

**First-finding rule** — case detected if the first finding on the path matches the family. Not used. Reason: `findings.jsonl` order is not guaranteed across runs, so "first" is not a stable concept. Any-finding-wins is order-independent by construction.

## 6. What this document does not establish

- It does not establish that the rule has been empirically validated against recorder evidence. That is the subject of a separate diagnostic not yet implemented.
- It does not change the scorer, recovery implementation, tests, corpus, or milestone register.
- It does not decide whether the benchmark metric should account for recorder-confirmed indeterminacy (M83 Stage 1 synthesis section 12). That is a deferred policy question.
- It does not generalise the recorder's traversal-lens classification to other vulnerability families. The recorder observes what it observes; the scorer aggregates what it aggregates; the two are not the same lens.

## 7. Accepted status

This rule is accepted as the current policy. It is retained without change. If a future decision is made to replace or extend it — for example, with a metric that counts recorder-confirmed indeterminacy, or a threshold rule calibrated against new per-payload expectations — that decision would supersede this document, not amend it. This document records what is, not what could be.

**Accepted:** 2026-11-15
**Applies from:** all current benchmark runs
**Supersedes:** nothing (this is the first formal statement)

