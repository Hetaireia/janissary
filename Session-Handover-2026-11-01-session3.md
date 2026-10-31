# Janissary — Session Handover #3, 2026-11-01 (FN-12 reverted; reclassified as Phase 0.2(b))

## Executive summary

Session 2 (`c24ba22`) closed with FN-12 filed. Session 3 attempted a fix,
made two correct-in-isolation edits, discovered a deeper layer, ran three
diagnostics, and reverted. The reversion is deliberate: under the Phase 0
architecture roadmap, FN-12 is Phase 0.2(b) work, not a hotfix. A
scanner-level bypass would patch a boundary the project intends to move.

## State at handover

- `origin/main`: `c24ba22` + this handover commit
- Tests: 671 total; 0 failures; 0-1 skipped depending on environment
- Corpus: tp=11 fp=0 fn=0 tn=24 f1=1.0
- Working tree: CLEAN

## What was reverted and why

Discarded from working tree (never committed):
- `src/janissary/detection/analyzer.py` — `_check_status` gate `>= 400` -> `>= 500`
- `src/janissary/engine/scanner.py` — warning threshold `>= 400` -> `>= 500`
- Two `.bak-*` backup files (deleted)

The analyzer change is correct in isolation but insufficient: `status_change`
is a corroborator, dropped unconditionally at `scanner.py:1048` via
`CORROBORATOR_ONLY_TYPES = frozenset({"status_change", "length_anomaly",
"length_shrink"})`. A scanner-level bypass (`payload_status >= 500 AND
baseline in 4xx`) is contraindicated by Phase 0.2(b) and the Phase 0
precision gate — see "Roadmap alignment" below.

## FN-12 — confirmed diagnosis (three diagnostics, all answered)

1. Failing test: `tests/unit/test_detection.py::test_status_does_not_fire_on_404_baseline`
   asserts `not any(f["type"] == "status_change" for f in findings)`.
   Expected — it is the status-gate test the analyzer change affects.
2. Corroborator classification: `CORROBORATOR_ONLY_TYPES` is a `frozenset`
   checked at `scanner.py:1048`; drop is unconditional.
3. Drop site: `scanner.py:1048-1052`. Comment block at `115-123` states the
   rationale: prevent F-002 through F-007 misattribution on `/traversal`
   (target that 500s for any unknown input).

Test counts with the dirty tree: 1 failed, 669 passed, 1 skipped (671 total).
Test counts after revert: 0 failed, 670 passed, 1 skipped (671 total) —
matching the session-2 figure of 671.

The narrow bypass (`payload_status >= 500 AND baseline in 4xx`) does **not**
distinguish a payload-specific 500 from an any-unknown-input 500. It would
fix juice-shop and reintroduce the `/traversal` misattribution the
corroborator layer was built to prevent. That is why the fix is deferred
to Phase 0.2(b), where the regression suite can catch the reintroduction.

## Roadmap alignment (recorded, not yet committed)

The Phase 0 architecture roadmap (provided 2026-11-01, not yet in repo)
reclassifies FN-12:

- Phase 0.1 — `VerificationEngine` is the sole emitter; all attack modules
  return `CandidateFinding`. This removes the structural cause of FN-12.
- Phase 0.2(b) — missed SQLi on Juice Shop "is either found or explicitly
  reported as 'candidate generated, verification failed because baseline
  was unstable' — **not silently dropped.**" This is FN-12's defect
  statement, written before FN-12 was filed.
- Phase 0 precision gate — "If any module cannot pass through the
  verification engine without losing recall, **document the reason and
  defer that module to Phase 2 rather than allowing a bypass.**" The
  one-condition bypass is the move this gate forbids.

**Action when the roadmap is adopted:**
1. Commit the roadmap as `docs/ROADMAP.md`.
2. Reclassify FN-12 in `docs/PHASE-6-PLAN.md` from Phase 6 to Phase 0.2(b).
3. Do **not** apply the scanner-level bypass.

## Next session — first action

Two paths depending on whether Phase 0.1 has started:

### If Phase 0.1 has started
FN-12 folds into it. `status_change` becomes a `CandidateFinding` with a
`verification_reason` code; the failing test is rewritten as part of the
Phase 0.2 regression suite (`tests/regression/test_juice_shop_precision.py`
per the roadmap). No separate FN-12 fix commit.

### If Phase 0.1 has not started
Implement **only** Phase 0.2(b): change `scanner.py:1048` to emit
`status_change` as a candidate with `verification_reason:
baseline_unstable` (or similar) rather than dropping it. This is ~1-2 hours,
does not touch `analyzer.py`, and satisfies the roadmap's "not silently
dropped" requirement without pre-empting the boundary refactor. Juice-shop
findings may still be 0; that is Phase 0.2 progress, not failure.

Pickup commands:

    Set-Location -LiteralPath 'C:\Users\M5 E60\janissary-project\janissary'
    git pull --ff-only
    git status --short              # expect: empty
    & ".\.venv\Scripts\python.exe" -m pytest tests/ -q
    git log --oneline -5            # expect: this handover commit on top

## Open items (carried forward from session 2)

- Adopt roadmap: commit as `docs/ROADMAP.md`, then reclassify FN-12 in
  `docs/PHASE-6-PLAN.md` to Phase 0.2(b)
- FN-12 fix — Phase 0.2(b), see "Next session" above
- M7 (demo.gif) — needs asciinema + agg install OR screen recorder
- Candidate C (deeper corpus) — needs decision on which cases
- Volume scripts — needs live container test
- Gitea fresh-volume — automation decision
- crAPI compose — vendoring decision
- SSRF-FP-1 regression — corpus expansion decision

## Environment findings (carried forward)

- Post-commit hook `git add` + `git commit --amend` deadlocks on Windows;
  hooks must not invoke git write commands
- `git add` occasionally no-ops after `git push`; retry with `-v`
- `docker rm -f` destroys vampi seed; use stop/start/restart
- vampi `/createdb` non-idempotent; retry on 500 (BOOTSTRAP.md)
- gh CLI not authenticated; use web UI or `gh auth login`
- PowerShell here-string `@'...'@` preserves content; use for all file writes

## Session failures (honest)

Session 3 produced no shipped code — deliberately. The value is the
confirmed diagnosis and the reclassification. Prior session failures
(paste-as-command incidents, commit-claims-X-but-didn't) are recorded in
the session 2 handover and did not recur in the portion of session 3
covered here beyond the initial incomplete-fix attempt, which was caught
and reverted before commit.
