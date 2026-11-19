# ADR-032 — SPA catch-all false-positive floor

**Status:** Proposed
**Date:** 2026-11-19
**Defects:** D-9 (no FP regression corpus; Precision Gate 1 FAIL), D-21 / GH#1 (admin module reports false positives on SPA catch-all routing)
**Related:** D-5, D-6, D-8 - the grading and discrimination classes the floor depends on

## Context

A single-page application serves one HTML shell for every unmatched path. The Python dev server, Next.js rewrites and nginx try_files fallbacks all answer 200 with the shell. The admin module probes conventional administration paths and reads a 200 plus shell markup as evidence of an exposed console. On a catch-all host every probe returns 200, so every probe reports.

Section 7 item 2 of the register already records this as a residual surface: a structural DOM differential against the root page runs before emission, and routes that match the root closely enough pass the gate. Section 7 is a warning, not a floor.

The module has no regression corpus behind it. Precision Gate 1 reads FAIL for exactly this reason, REMEDIATION-REGISTER line 12: no FP regression corpus exists yet. A fix with no floor is a claim, not a change.

## Decision

1. A false-positive floor slice is committed at benchmark/fp_floor/spa_catchall/, seeded and runnable offline.
2. The floor is absolute: 0 verified findings across 3 consecutive runs on the slice.
3. The floor is paired with a no-regression gate: M89 delta 0 against the current baseline.
4. Failing either arm has a consequence: the admin module leaves the default-enabled set and becomes opt-in behind --admin, rather than staying default with a caveat.
5. This slice is the corpus Precision Gate 1 cites. Gate 1 cannot read PASS on any other basis.

## Slice definition

- app.py: one catch-all route returning 200 with a fixed shell body, plus /healthz (200, ok) and one real static asset with a correct MIME type.
- seed.json: 40 benign paths (static assets, docs, deep links) so crawl noise is represented, not only the three admin probes.
- expect.json: verified 0, one entry per seeded probe mapped to the reason it must stay silent.
- run.ps1: boots on a fixed port, runs janissary scan --url http://127.0.0.1:PORT, writes findings.jsonl, exits non-zero on any verified finding.
- No network, no Docker, no Track A case files. It is a fixture, so it never enters F1.

## Gate

- 3 consecutive runs, 0 verified findings in each. One finding in any run fails the floor.
- M89 rescore delta 0, proving the change costs no recall.
- Both arms pass in the same session; a pass on one does not carry.

## Consequences

- The admin module may be enabled by default only while the floor holds. A later regression demotes it instead of reopening the argument.
- A 40-path fixture is cheap to write against, which keeps the fix small.
- The slice is reusable for every later default-enabled class, so this ADR sets the pattern for the rest of D-9.
- Cost: one fixture directory plus a run script, and the floor re-runs in any PR touching detection defaults.

## Alternatives considered

- Downgrade admin detections to candidates. Rejected: the candidate stream is for unprovable findings, not known-false ones.
- Soft threshold of 1 FP. Rejected: with three admin probes a threshold of one tolerates a third of the module.
- Manual review before each default change. Rejected: not reproducible, so not a gate.
- Corpus-wide zero FPs. Rejected: out of reach until D-6 and D-8 land. This slice is deliberately narrow.

## Refs

- D-9 and D-21, docs/MILESTONE-REGISTER-COLLATED.md sections 5 and 7
- docs/quality/REMEDIATION-REGISTER.md gate table, line 12
- GH#1

