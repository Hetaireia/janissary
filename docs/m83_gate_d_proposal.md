# M83 — Path Traversal Classification Harness: Implementation Design

**Status:** Gate D and Gate D.1 approved 2026-11-14. Gate E not authorized.
**Scope document:** `docs/m83_scope.md`
**This document:** implementation design. Its approval does not authorize implementation — Gate E is a separate decision.

## Version history

| Version | Date | Content |
|---|---|---|
| Gate D | 2026-11-14 | Initial design. Two-phase architecture, structural signatures, four reachable classifications, thirteen acceptance criteria. |
| Gate D amendments | 2026-11-14 | Four corrections: nested recorder-failure isolation, UUID token-boundary masking, three-level evidence model, observation-level records. |
| Gate D.1 | 2026-11-14 | Subprocess attachment. CLI contract and capability probe. Five-state per-case recording coverage taxonomy. Four-state missing-case taxonomy. Criterion 15. |

## 1. Scope and constraints

From `docs/m83_scope.md`: classify each pathtraver case against the §5.2 classes, preserving evidence. The five-class vocabulary is unchanged. The recorded decisions are authoritative: **R1b** (denominator = executed cases only), **R2a** (strict inconclusive), **R3a** (leakage folded into inconclusive). The constraint stands verbatim: "never loosen the traversal oracle simply to improve its benchmark score."

**Four reachable classifications** in the first implementation: `existence_divergence`, `no_observable_divergence`, `payload_neutralised`, `inconclusive`.

**`distinctive_content` is deferred.** It belongs to the collapse oracle (`check_traversal_collapse_oracle`, `collapse_oracle.py:108`), not the path-traversal existence oracle. The first implementation never emits this classification. Tests assert zero emissions; the boundary is enforced, not merely documented.

## 2. Two-phase architecture

**Phase 1 — collection (scanner).** When recording is enabled, the scanner constructs a `PathtraverRecorder` and records each oracle observation to a per-case raw file. Scanner-side data: oracle inputs, response bodies, comparison booleans, re-derived classification, `observation_id`.

**Phase 2 — enrichment (runner).** The runner supplies benchmark identity. It writes `case_selection.json` before scans begin, collects per-case raw files after scans complete, joins each raw record to its case via `case_id`, and writes the enriched `case_records.jsonl`.

**Join key.** `case_id` — unique, stable, assigned by the runner. Not URL. Duplicate URLs do not collapse because each case has a distinct `case_id`. Multiple observations per case are distinguished by `observation_id` within the same `case_id`.

**Unmatched records preserved.** A raw record whose `case_id` is absent from `case_selection.json` appears in `case_records.jsonl` with `enriched: false` and an `enrichment_reason`. It is not silently dropped.
## 3. Structural signature and evidence

Three independent levels of evidence per probe (exists and noexist):

**Level 1 — reproducibility of the comparison.** `structural_signature_exists` and `structural_signature_noexist` carry the SHA-256 of each normalised complete body. A reviewer recomputes `structural_diff = (sig_exists != sig_noexist)` without any body.

**Level 2 — inspection of retained prefix.** `body_stored_exists` and `body_stored_noexist` carry the first 4096 characters of each body. Prefix inspection is guaranteed.

**Level 3 — non-recovery of truncated originals.** `evidence_hash_exists` and `evidence_hash_noexist` are SHA-256 of complete original bodies, computed before truncation. These are integrity anchors, not recovery mechanisms. A truncated body cannot be reconstructed from its hash. If the decisive difference lies beyond 4096 characters, the retained prefixes will not show it — this is a documented limitation, not a silent one.

`BODY_STORE_LIMIT = 4096` characters (not bytes).

**Normalisation rules.** Deterministic, documented in the module:

1. Collapse whitespace runs to single spaces; strip ends.
2. Mask UUID v4 with token-boundary matching (`(?<![0-9a-f])...(?![0-9a-f])`, `re.IGNORECASE`). Non-v4 UUIDs pass through unmasked — deliberate under-masking, documented.
3. Mask 32-64 character hex strings appearing as standalone tokens.
4. Mask base64-like strings only when adjacent to a recognised key marker (documented list: `value=`, `token=`, `id=`, `nonce=`, `__NEXT_DATA__`, `csrf`, `session`). Bare long mixed-case strings are never masked by shape alone.
5. Strip HTML tags via selectolax; retain text content.
6. SHA-256 of the result.

`structural_diff` is a differential boolean. Not "either has a hash."
## 4. Recorder and failure isolation

**Default path unchanged.** `Scanner(record_case_dir=None)` behaves identically to today. Recorder code is unreachable.

**Nested failure boundaries.** Two independent failure domains: the primary record write and the failure log write. Both are contained.

```
try:
    recorder.record(...)
except Exception as e:
    recorder._record_failure_safe(url=..., param=..., exception=repr(e))
    # Finding emission proceeds as if recorder absent.
```

```
def _record_failure_safe(self, *, url, param, exception) -> None:
    self._diagnostics.failure_count += 1
    try:
        self._write_failure_line(url=url, param=param, exception=exception)
    except Exception:
        self._diagnostics.failure_log_broken = True
        # No re-raise.
```

**Input immutability.** The recorder receives snapshots and payloads by reference; it does not modify them.

**Diagnostics surface on the scanner's per-case status file (§8).** Not on the scan summary — the CLI has no summary object spanning subprocess boundaries. Per-case `recording_status.json` is the surface.
## 5. Classification derivation

Same predicates, same helpers imported from `analyzer.py` (`_PATHTRAVER_EXISTS`, `_PATHTRAVER_NOEXIST`, `_pathtraver_signal`). No re-implementation.

| Oracle outcome | Recorder check (in order) | Class | Reason prefix |
|---|---|---|---|
| Fires | — | `existence_divergence` | Oracle's `detail` verbatim |
| Silent | Payload leakage | `inconclusive` | `"payload leakage: ..."` |
| Silent | Baseline poisoned | `inconclusive` | `"baseline poisoned: ..."` |
| Silent | Signal extraction failed | `inconclusive` | `"signal extraction failed: ..."` |
| Silent | Signals agree | `no_observable_divergence` | `"both probes reported '<sig>'"` |
| Cannot reconstruct | Contradictory or exception | `inconclusive` | `"recorder could not reconstruct branch: ..."` |

**`payload_neutralised` precedence.** Applied by the runner only when no scanner record exists for the case. Conflicts preserved in `enrichment_conflicts.jsonl`.

**Tests** (`tests/unit/test_harness_pathtraver_classification.py`) prove branch agreement with the real oracle across five fixtures and assert helper import from `analyzer.py` — no local redefinition.
## 6. Subprocess attachment

The runner is a subprocess driver (`runner.py:211-250`): one `janissary scan` subprocess per case. No in-process `Scanner` exists to attach to.

**Scanner side.** `Scanner.__init__` gains `record_case_dir: Path | None = None`. When set, the scanner constructs its own `PathtraverRecorder`. The harness module is imported lazily — never imported when `record_case_dir is None`.

**CLI side.** `janissary scan` gains `--record-case-dir PATH`. Argument parser addition in `cli.py`. `cmd_scan` passes `record_case_dir=Path(args.record_case_dir) if args.record_case_dir else None` to the scanner.

**Runner side, per case:**

| Step | Action |
|---|---|
| Pre-flight (once per run) | Create `run_dir/case_raw/`; verify writable. If fails: recording disabled at run level (§8). |
| Case ID | `case_id = _sanitize_case_id(c["testname"])` — deterministic; only `[A-Za-z0-9_-]`, 64-char cap, hash suffix if truncated. Collision check across all case_ids; collision fails the run before any scans. |
| Attempt bookkeeping | Append `{"case_id":..., "event":"attempt_started", "started_at":...}` to `case_attempts.jsonl` before subprocess spawn. |
| Directory | `case_dir = run_dir/case_raw/case_id`; `case_dir.mkdir()` — raises if already exists. |
| Command | Append `--record-case-dir`, `str(case_dir)` to `cmd`. |
| Outcome bookkeeping | Append `{"case_id":..., "event":"attempt_finished", "rc":..., "timed_out":...}` after subprocess returns. `attempt_errored` event on subprocess exception. |
| Enrichment (once per run) | Read all `case_raw/*/case_records_raw.jsonl`, join on `case_id`, write `case_records.jsonl` and the coverage files (§8). Reconcile against `case_attempts.jsonl` and `case_selection.json`. |

**Retry pass.** `_retry_zero_pass` uses `run_dir/pass2` as its own run directory. Recording for the retry pass is independent — same logic, same tree structure.

**Multiple scans per case.** Not present in the current runner. Design allowance: suffix directories (`case_raw/<case_id>_1/`, `_2/`) if a future runner modification invokes multiple scans per case. Gate E implements the current one-scan-per-case model.
## 7. CLI contract and capability probe

**Three properties, tested together (criterion 14):**

- Flag present + valid directory → `case_records_raw.jsonl` (if observations), `recorder_failures.jsonl` (if failures), `recording_status.json` (always) written in assigned directory.
- Flag absent → existing scan behavior byte-identical to pre-change baseline.
- Flag present + invalid directory → scan exits non-zero with clear error before any scan work.

**Capability probe.** The runner supports an external `JANISSARY_BIN`. Before any scans, the runner runs `<candidate_binary> scan --help` and checks for `--record-case-dir` in output.

| Probe outcome | Recording status |
|---|---|
| Flag present in help | Recording enabled |
| Flag absent | Recording disabled for run |
| Probe errors | Recording disabled for run |

Recording-disabled states are surfaced in `run_dir/recording_status.json` (run-level, distinct from the per-case file of the same name):

```
{
  "recording_enabled": false,
  "reason": "flag_absent_in_binary | probe_failed | case_raw_dir_unwritable",
  "probe_output_excerpt": "..."
}
```

When recording is disabled, **no scan receives `--record-case-dir`**. Scans proceed normally. Enrichment finds no `case_raw/*` directories and produces zero enriched records. Recording being disabled does not change the run's exit code or findings.

**Scanner-side directory validation** (applied in this order, first failure wins):

1. Supplied path is non-empty and does not contain a `..` component as a path segment. Checked against `Path(supplied).parts` — **not** the resolved path (resolution removes `..`).
2. Path resolves to absolute (relative supplied paths accepted for CLI convenience; resolved against CWD).
3. Path exists.
4. Path is a directory.
5. Path is **not a symlink itself** (`Path.is_symlink()` on the final component). Parent may be a symlink; the recording directory must not be.
6. Directory contains none of `case_records_raw.jsonl`, `recorder_failures.jsonl`, `recording_status.json`. Prior recordings indicate a stale directory or duplicate case_id.
7. Directory is writable: create-and-delete a temp probe file.
8. Scanner does **not** create or overwrite the directory — that is the runner's responsibility. A missing directory reaches check 3 and fails.

**Write confinement.** The scanner writes only within `--record-case-dir`. No upward traversal, no sibling writes, no files outside the assigned directory.
## 8. Recording coverage — per-case taxonomy and validation

### 8.1 — The `recording_status.json` file (per case)

Written by the scanner at the end of every scan invocation with `--record-case-dir` set. **Outside** the recorder's nested failure boundary — a scan-level status write, not a recorder operation.

```
{
  "recording_enabled": true,
  "recorder_constructed": true,
  "records_attempted": 3,
  "records_written": 2,
  "failures_total": 1,
  "failure_log_written": true,
  "scanner_version": "7.11.1",
  "completed_at": "2026-11-14T..."
}
```

If this write fails, the runner sees no status file and classifies the case as `recording_indeterminate`. That is the honest outcome.

### 8.2 — The runner must validate, not assume

**`recording_status.json` is a scan-level diagnostic, not proof of completeness.** Its mere existence does not establish that recording operated correctly. Before classifying any case, the runner validates:

| Check | Failure |
|---|---|
| File parses as valid JSON | `recording_indeterminate`, reason `status_file_unreadable` |
| `recording_enabled` is boolean `true` | `recording_indeterminate`, reason `status_file_invalid` |
| `recorder_constructed` is boolean `true` | `recording_indeterminate`, reason `status_file_invalid` |
| `records_attempted`, `records_written`, `failures_total` are non-negative integers | `recording_indeterminate`, reason `status_file_invalid` |
| `records_written <= records_attempted` | `recording_indeterminate`, reason `status_file_invalid` |
| `failures_total <= records_attempted - records_written` | `recording_indeterminate`, reason `status_file_invalid` |
| `failure_log_written` is boolean | `recording_indeterminate`, reason `status_file_invalid` |

**Any validation failure is `recording_indeterminate`. Never `zero_observations`.** Invalid or inconsistent status data is treated as absent data — and absent data means indeterminate, not zero.
### 8.3 — Five per-case observation dispositions plus one missing family

| Disposition | Precondition | Where recorded |
|---|---|---|
| **has_observations** | Status valid; `recorder_constructed: true`; `records_written >= 1` | `case_records.jsonl` — one line per observation |
| **zero_observations** | Status valid; `recorder_constructed: true`; `records_written == 0`; `failures_total == 0` | `case_zero_observations.jsonl` — one line per case with pointer to `recording_status.json` |
| **recording_failed** | Status valid; `failures_total > 0` | `case_recording_failed.jsonl` — one line per case with `partial: records_written > 0`. Successful observations also go into `case_records.jsonl`. Evidence preserved; failure recorded separately. |
| **recording_indeterminate** | Status file absent, unreadable, or invalid per §8.2 | `case_recording_indeterminate.jsonl` — one line per case, `reason: status_file_missing \| status_file_unreadable \| status_file_invalid` |
| **recording_disabled** (run-level) | The runner did not pass `--record-case-dir` for this run | No per-case file. Run-level `recording_status.json` names the reason. Every case uniform. |
| **missing** | Case exercised but no subprocess completion, OR never reached | `case_missing.jsonl` — four reasons per §9 |

A case may produce records in **multiple** files only when `recording_failed` (successful observations plus failure record). The `case_id` on both is identical.

### 8.3a — Disposition precedence

Every case in `case_selection.json` is classified into exactly one primary disposition, by the following ordered rules. First matching rule wins.

**Step 1 — did the subprocess complete?**

| Subprocess state | Primary disposition | Secondary coverage |
|---|---|---|
| **Did not complete** — no `attempt_finished` and no `attempt_errored` AND the run ended; OR `attempt_errored` present | **Missing family**, reason per §9 | `disabled` if run-level recording off; `indeterminate` if run-level recording on |

For every case where Step 1 yields "did not complete," the primary disposition is in the missing family. No further rules apply — the case is **not** also classified as `recording_disabled`, `recording_indeterminate`, or any other completed-subprocess disposition. The subprocess did not complete; the recording taxonomy does not apply to a subprocess that never produced a status.

**Step 2 — subprocess completed. Was recording enabled at run level?**

| Run-level recording | Primary disposition | Secondary coverage |
|---|---|---|
| **Disabled** (capability probe failed, or `case_raw/` unwritable) | `recording_disabled` | `disabled` |
| **Enabled** | Proceed to Step 3 | — |

`recording_disabled` therefore applies only to completed subprocesses in a run where recording was off at the run level. It does not apply uniformly to every selected case — missing cases remain in the missing family.

**Step 3 — subprocess completed, recording enabled. Is the recording status valid?**

| Status state | Primary disposition | Secondary coverage |
|---|---|---|
| Status absent, unreadable, or fails §8.2 validation | `recording_indeterminate` | `indeterminate` |
| Status valid, `failures_total > 0` | `recording_failed` (partial: `records_written > 0`) — successful observations **also** go into `case_records.jsonl` | `partial` if `records_written > 0`, else `failed` |
| Status valid, `failures_total == 0`, `records_written >= 1` | `has_observations` | `complete` |
| Status valid, `failures_total == 0`, `records_written == 0` | `zero_observations` | `complete` |

**Mutually exclusive primaries.** A case is counted in exactly one primary disposition. Secondary coverage is an attribute of the case — it is reported separately (§8.5a) and is never added to the primary totals.

**Why this restructure is correct:** the prior rule said "recording disabled at run level → `recording_disabled` for all cases uniformly." That cannot hold when some cases never completed. The corrected rule puts "did the subprocess complete" first, then checks recording config. A case that never completed is missing regardless of recording state — it never produced the status that would tell us anything about recording.
### 8.4 — The critical inference rule

No case is classified `zero_observations` unless the status file affirmatively shows `records_written == 0` **and** `failures_total == 0` **and** all §8.2 validation passes. The default for any ambiguity is `recording_indeterminate`, never `zero_observations`.

### 8.5a — `recording_summary.json` accounting

The sum constraint is corrected: six top-level primary dispositions sum to `cases_total`; four `missing_breakdown` values sum to `missing` and are not added again. The example demonstrates a recording-disabled run with at least one missing case.

```
{
  "recording_enabled": false,
  "cases_total": 133,
  "primary_dispositions": {
    "has_observations": 0,
    "zero_observations": 0,
    "recording_failed": 0,
    "recording_indeterminate": 0,
    "recording_disabled": 130,
    "missing": 3
  },
  "primary_dispositions_sum": 133,
  "missing_breakdown": {
    "not_reached": 1,
    "scan_aborted_at_case": 1,
    "scan_errored_at_case": 1,
    "execution_state_indeterminate": 0
  },
  "missing_breakdown_sum": 3,
  "recording_coverage_note": {
    "recording_was_enabled_this_run": false,
    "coverage_by_case_state": {
      "completed_subprocesses": { "coverage": "disabled", "count": 130 },
      "missing_subprocesses": { "coverage": "disabled", "count": 3 }
    },
    "note": "Recording was disabled for the entire run. No case has observation coverage. Completed subprocesses are classified recording_disabled in primary_dispositions; missing subprocesses are classified in the missing family with secondary coverage also disabled because recording was never enabled for the run."
  },
  "unmatched_observations": 0,
  "enrichment_conflicts": 0,
  "accounting_valid": true,
  "accounting_failure_reasons": []
}
```

**Sum constraints and invariant-failure behavior.**

- `primary_dispositions.has_observations + .zero_observations + .recording_failed + .recording_indeterminate + .recording_disabled + .missing` must equal `cases_total`. The runner writes `primary_dispositions_sum` as a computed value alongside `cases_total` so a reader can verify the arithmetic.
- `missing_breakdown.not_reached + .scan_aborted_at_case + .scan_errored_at_case + .execution_state_indeterminate` must equal `missing`. The runner writes `missing_breakdown_sum` alongside `primary_dispositions.missing`.
- `missing_breakdown` values are subdivisions of `missing`. They are not added again to the primary total.
**A recording-enabled example (illustrative):**

```
{
  "recording_enabled": true,
  "cases_total": 133,
  "primary_dispositions": {
    "has_observations": 10,
    "zero_observations": 45,
    "recording_failed": 2,
    "recording_indeterminate": 1,
    "recording_disabled": 0,
    "missing": 75
  },
  "primary_dispositions_sum": 133,
  "missing_breakdown": {
    "not_reached": 0,
    "scan_aborted_at_case": 1,
    "scan_errored_at_case": 2,
    "execution_state_indeterminate": 72
  },
  "missing_breakdown_sum": 75,
  "recording_coverage_note": {
    "recording_was_enabled_this_run": true,
    "coverage_by_case_state": {
      "completed_subprocesses": {
        "complete": 55,
        "partial": 2,
        "failed": 0,
        "indeterminate": 1
      },
      "missing_subprocesses": { "indeterminate": 75 }
    },
    "note": "Recording was enabled. Completed subprocesses carry coverage per their validated status. Missing subprocesses are coverage-indeterminate - recording was on; the subprocess did not complete; whether an observation would have been produced cannot be established."
  },
  "unmatched_observations": 0,
  "enrichment_conflicts": 0,
  "accounting_valid": true,
  "accounting_failure_reasons": []
}
```

In this illustrative example: 55 completed-with-complete-coverage (10 has_observations + 45 zero_observations), 2 completed-with-partial-coverage (recording_failed with records_written > 0), 1 completed-with-indeterminate-coverage, 75 missing all with indeterminate coverage. The primary dispositions sum to 133; the missing breakdown sums to 75; the coverage counts in each category sum correctly to their category totals.
**When an invariant fails** - either sum does not equal its target - the runner takes the following actions, and only these actions:

1. **Emits a diagnostic.** A line is written to `stderr` naming which invariant failed, the computed sum, and the expected sum. The same diagnostic is also recorded in `recording_summary.json` (see below).
2. **Marks the summary invalid.** `recording_summary.json` gains `"accounting_valid": false` and an `"accounting_failure_reasons"` array naming each violated invariant with its computed and expected values. When both invariants pass, `"accounting_valid": true` and `"accounting_failure_reasons": []`.
3. **Does not alter the disposition counts.** The per-case classifications that produced the counts stand exactly as recorded. The runner does not recategorize cases, does not move cases between dispositions, does not "repair" the arithmetic to force the invariant to pass. The disagreement between the counts and the expected total is surfaced, not resolved.
4. **Does not discard findings.** `findings.jsonl`, `skipped.jsonl`, `timeouts.jsonl`, and `case_records.jsonl` are untouched by an invariant failure. They were written before the summary was composed and are not affected by the summary''s internal consistency.
5. **Does not change the scan-derived exit status.** `run_janissary`''s return value - `1 if failures else 0`, accumulated from subprocess timeouts and non-(0,1) return codes - is returned unchanged. An accounting invariant failure is a summary-composition defect; it is not a scan outcome and must not be presented as one. The runner does not exit with a new failure code.

The invariant failure is a diagnostic about the runner''s own bookkeeping. It does not invalidate the scans that were performed, the observations that were recorded, or the findings that were emitted. It invalidates only the claim that the summary''s disposition counts form a complete accounting of `cases_total`.

**Consistency with failure isolation (§4).** This behavior is the same principle as the recorder''s nested failure boundary: a failure in the recording or reporting path must not alter the security outcome. A scan that produced findings produces those findings and exits with its scan-derived code, whether or not the runner''s post-hoc accounting is internally consistent.

**Secondary coverage - recording-disabled run:**

For a run where recording was disabled at run level:
- Every completed subprocess has secondary coverage `disabled`.
- Every missing subprocess has secondary coverage `disabled` - not `indeterminate`. The distinction: `indeterminate` means "recording was on and we could not establish coverage." In a disabled run, recording was never on, so there is nothing to establish. `disabled` is the correct secondary coverage for all cases in a disabled run.

**Secondary coverage - recording-enabled run:**

For a run where recording was enabled at run level:
- Completed subprocesses: secondary coverage per the Step 3 table (`complete`, `partial`, `failed`, or `indeterminate`).
- Missing subprocesses: secondary coverage `indeterminate`. Recording was on; the case did not complete; whether it would have produced a recorded observation cannot be established.

The runner writes a `recording_coverage_note` matching the run-level state, so a reader of `recording_summary.json` can interpret the coverage statuses correctly without consulting this document.
## 9. Missing-case taxonomy

The runner writes `case_attempts.jsonl` per case:

| Event | When |
|---|---|
| `attempt_started` | Before subprocess spawn |
| `attempt_finished` | After subprocess returns - includes `rc` and `timed_out` |
| `attempt_errored` | Subprocess exception before return |

`skipped.jsonl` and `timeouts.jsonl` behaviour is preserved unchanged. `case_attempts.jsonl` supplements; it does not replace or reinterpret.

**Four reasons for `case_missing.jsonl`:**

| Reason | Evidence |
|---|---|
| `not_reached` | No `attempt_started` event AND the runner can affirmatively establish the attempt never began |
| `scan_aborted_at_case` | `attempt_started` present, no completion or error event, run ended before this case''s scan finished |
| `scan_errored_at_case` | `attempt_errored` event, OR `attempt_finished` with rc not in (0,1) and `timed_out == false` |
| `execution_state_indeterminate` | Evidence cannot distinguish the three determinate states |

`not_reached` is never used as a fallback. `execution_state_indeterminate` is the correct fallback.

**A case exercised with zero observations is not missing.** It belongs in `case_zero_observations.jsonl` per §8.3.
## 10. Multi-observation coverage (conditional)

Observation-level records are retained. Multiple observations per case produce multiple records with the same `case_id`, distinct `observation_id`.

**Conditional limitation.** The runner lifecycle inspection (`runner.py:218-274`) establishes one subprocess invocation per benchmark case. It does **not** establish that the pathtraver oracle call site (`scanner.py:2125`) executes at most once within that subprocess. A single call site inside a loop can be reached multiple times.

**The number of oracle observations per subprocess has not yet been established by the runner lifecycle inspection.** Gate E must verify the enclosing scanner control flow at and around `scanner.py:2125` and determine whether the call site can execute more than once per subprocess.

The benchmark''s actual observation distribution is reported from collected records (`recording_summary.json`''s `has_observations` count against `cases_total`), not assumed from the design. Fixture tests cover multiple observations independently.

## 11. Module and file changes

### New files

- `src/janissary/harness/__init__.py`
- `src/janissary/harness/pathtraver.py`
- `tests/unit/test_harness_pathtraver_signature.py`
- `tests/unit/test_harness_pathtraver_classification.py`
- `tests/unit/test_harness_pathtraver_recorder.py`
- `tests/unit/test_recording_status.py`
- `tests/integration/test_cli_record_case_dir.py`
- `tests/integration/test_harness_runner.py`

### Modified files

| File | Change |
|---|---|
| `src/janissary/engine/scanner.py` | `record_case_dir` parameter; recorder construction; `recording_status.json` write at scan end; call site wrap |
| `src/janissary/cli.py` | `--record-case-dir` argument; passes to Scanner |
| `benchmark/track_a/runner.py` | Capability probe; case_id sanitization; per-case directory creation; attempt bookkeeping; command augmentation; directory collection; status-driven classification; five-state reconciliation; `recording_summary.json` |
| `docs/m83_scope.md` | Header line |
| `docs/MILESTONE-REGISTER.md` | §2 `scoped` addition; §5.2 M83 removed; §5.4 (new) M83 |

### Unchanged constraint

`src/janissary/detection/analyzer.py` - byte-identical. `DEFAULT_PAYLOADS` in `scanner.py` - byte-identical. `check_pathtraver_oracle` body - byte-identical.
## 12. Acceptance criteria (15)

| # | Criterion |
|---|---|
| 1 | **Persisted observation records.** Every observation successfully written by the recorder is represented in `case_records.jsonl`, with its `case_id` and `observation_id` preserved. Recording failures and incomplete coverage are reported under the recording-coverage taxonomy in §8. **No guarantee of a persisted record is made for an observation whose recording operation failed.** Multiple observations per case produce multiple records with the same `case_id`, distinct `observation_id`. Zero-observation cases are recorded in `case_zero_observations.jsonl`; missing cases are recorded in `case_missing.jsonl` with the appropriate reason per §9. |
| 2 | Record schema matches §3 of `docs/m83_scope.md` plus the additions in §3 and §8 of this document. |
| 3 | All four reachable classes producible from fixtures. |
| 4 | `distinctive_content` never emitted by first implementation. |
| 5 | Structural signature deterministic; UUID token-boundary rule per §3; evidence levels 1/2/3 per §3. |
| 6a | Valid recording configuration: scan findings and exit code byte-identical to a scan without the flag - including when the recorder raises and when both recorder and failure log raise. |
| 6b | Invalid recording configuration: scanner exits non-zero with clear error before any scan work - nonexistent, `..` segment, not a directory, symlink, contains prior recorder files, not writable. |
| 7 | R1b denominator derivable from fixture records (not hard-coded). || 8 | R2a enforced: contradictory evidence -> `inconclusive`. |
| 9 | R3a: leakage -> `inconclusive` with diagnostic in `classification_reason`. |
| 10 | `analyzer.py` and `DEFAULT_PAYLOADS` byte-identical; `scanner.py` and `cli.py` changes permitted and documented. |
| 11 | Full-body `evidence_hash` per probe; `structural_signature_*` per probe; truncation metadata; three-level reproducibility documented. |
| 12 | Unmatched records preserved as `enriched: false`; missing cases logged; counts reported; no silent drop. |
| 13 | Join integrity: duplicate URLs, multiple observations per case, unmatched, missing - all handled deterministically; all four missing-case reasons producible by fixtures; `not_reached` never used as fallback. |
| 14 | CLI integration and directory validation: flag enables per-case recording; flag absent preserves behavior byte-for-byte; each invalid directory config raises before scan work; write confinement; capability probe. |
| 15 | Recording coverage reporting: five per-case dispositions plus four missing reasons correctly counted. **Critical assertion:** `zero_observations` count is zero unless every zero-observation case has a valid `recording_status.json` showing `records_written == 0` and `failures_total == 0`. Sub-tests: recording-failure -> `recording_failed`, never `zero_observations`; status-file-missing -> `recording_indeterminate`; internally inconsistent status file -> `recording_indeterminate` with `reason: status_file_invalid`; recording disabled run-level -> all completed cases `recording_disabled`, missing cases in the missing family with secondary coverage disabled, zero `zero_observations` count; partial-failure case -> records in both `case_records.jsonl` and `case_recording_failed.jsonl`. |

## 13. Gate E prerequisites

Before Gate E implementation proposal is drafted:

1. **Scanner control-flow inspection** at `scanner.py:2125` - determine whether the pathtraver oracle call site can execute more than once per subprocess. This resolves §10''s conditional limitation.
2. **Record the finding** as an addendum to this document.

## 14. Out of scope

- `distinctive_content` classification (deferred to collapse-oracle harness extension)
- Changes to `check_pathtraver_oracle`
- Changes to `DEFAULT_PAYLOADS`
- Benchmark modifications beyond `runner.py`
- Any change to R1b/R2a/R3a recorded decisions