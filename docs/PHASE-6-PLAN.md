# Phase 6 - Scope Decision

Status: **unresolved** (decision required from maintainer)
Entry point: b144be9, v7.10.2, 667/667 tests, corpus tp=11 fp=0 fn=0 tn=24 f1=1.0

## Purpose

Phase 5 closed the locked 7-app regression. Phase 6 has no defined scope.
This document records the three candidates discussed, their known state,
scope estimates, and risks, so the decision is a choice and not a
re-derivation. Nothing below is a commitment. No candidate has been started.

## Candidate A - Integration arms (Nuclei / SARIF)

**What it is.** Connect Janissary to external detection and reporting:
a Nuclei arm (shell out to nuclei, normalize JSONL into the finding model)
and a SARIF arm (emit results.sarif v2.1.0 for CI / code scanning).

**Known state - audit first.** The test tree already contains:
- tests/unit/test_nuclei.py
- tests/integration/test_sarif_output.py
- tests/integration/test_sarif_schema.py
- tests/unit/test_sarif_rules.py

So this candidate may be built, half-built, or scaffolded-then-abandoned.
**First task under this candidate is a 30-minute audit, not a build.**
Read those four files, run them, and report what works end-to-end versus
what is unit-tested against stubs only.

**Scope estimate.** Small if the audit finds working arms (documentation
plus corpus wiring). Medium if it finds stubs (build, wire, negative-check).
Unknown until audited.

**Dependencies.** nuclei binary availability; SARIF schema version pin.

**Risks.**
- Two external moving parts (nuclei version, SARIF schema evolution).
- An arm that only passes mock-based unit tests is a claim, not evidence.
  Same discipline as 4a2d0d1: demonstrate against a live target.

**Done looks like.** Nuclei findings normalized into the finding model for
at least one live corpus app; SARIF emits schema-valid v2.1.0 for the same
run; both wired into a reproducible command.

## Candidate B - New app category

**What it is.** Deploy one additional vulnerable app into benchmark/track_c:
image digest pinned in apps.json, startup documented in BOOTSTRAP.md,
corpus cases added. Primary motivation on the table: no current app has a
confirmed injectable POST+path target, so the v7.9.1 capability is
wire-verified but corpus-untested.

**Scope estimate.** Multi-hour (handover estimate). New deploy, digest pin,
BOOTSTRAP entry, corpus rows, fresh full run.

**Dependencies.** Docker; image digest reproducibility; BOOTSTRAP.md update.

**Risks.**
- An app that does not exercise anything the current 7 do not is padding.
  The concrete gap is POST+path; a candidate must plausibly close it.
- Fresh-volume state issues (gitea note in BOOTSTRAP.md) recur per app.
- crAPI compose already lives outside the repo; another external dependency
  worsens fresh-clone reproducibility.

**Open question.** Which app? WebGoat (broad, older Java stack), Juice Shop
(Node, overlapping surface with DVWA/bwapp), or a custom Flask (control,
maintenance burden). Answer needed before scoping.

**Done looks like.** New app pinned and startable from BOOTSTRAP.md alone;
at least one corpus case exercising a previously-untested capability
(ideally POST+path); fresh full run reproduces, or honestly documents the
delta (4a2d0d1 style).

## Candidate C - Deeper corpus

**What it is.** Expand cases.csv against the existing 7 apps: more trials,
more auth states, more injection points. No new deploys.

**Scope estimate.** Small per case. Diminishing returns after the first few.

**Dependencies.** None new.

**Risks.**
- Self-deception: more green on the same apps does not prove generalization.
  Every added case needs a stated reason it is non-trivial; a case that only
  re-tests what is green inflates the corpus without adding evidence.
- If a new case exposes an FN, that is the valuable outcome. Record it
  (4a2d0d1 style) before fixing.

**Done looks like.** Corpus grows with a written rationale per case; f1
stays 1.0 only if each new case was genuinely hard; any FN found is
recorded as a measurement commit before the fix.

## Recommended pre-decision step (candidate-independent)

Audit Candidate A. Cheap (~30 min), may collapse the decision (if the SARIF
and Nuclei arms already work, the build is small), and costs nothing if you
then choose B or C. Do this before committing to any direction.

## Audit Results (2026-10-30)

Filled in after the plan was written. Falsifies the "stubs" hypothesis in Candidate A.

### Both arms are wired into the CLI

- src/janissary/cli.py:300-301, 1260 - scan `--export *.sarif` -> `_write_sarif`
- src/janissary/cli.py:953-955 - agent `--export *.sarif` -> `_write_sarif`
- src/janissary/cli.py:732-802, 1461-1484 - `janissary attack nuclei` -> `NucleiRunner`

### Both arms are unit/integration proven

- SARIF: 41 tests pass (test_sarif_output 10, test_sarif_schema 12, test_sarif_rules 19).
  Schema-validated against OASIS SARIF 2.1.0 fixture (tests/fixtures/sarif/sarif-schema-2.1.0.json,
  3389 lines, 43 schema refs, 0 mocks).
- Nuclei: 22 tests pass, but 11 mock refs (subprocess patched). No live binary exercise.

### Neither arm has ever produced a live artifact in this repo

- No .sarif tracked in benchmark/track_c/runs/ (git ls-files)
- No .sarif on disk (untracked scan returned none)
- nuclei binary not on PATH (`Get-Command nuclei` fails)

### Commit history for the source modules

- 95e0eff feat(ssrf): wire scanner._ssrf_phase, CLI flags, SARIF + grouping (ADR-012 D3-D5)
- 3f89e55 feat(sarif): rule catalog module (0.3c-a)
- 535e97d P3.2: Nuclei runner (257 tests, --templates required, subprocess wrapper)

SARIF touched recently. Nuclei last touched at P3.2 - settled, not iterated.

## Revised scope for Candidate A

Original estimate: "Medium if stubs." Audit falsifies the stub premise. Scope was Small - task 1 now DONE, zero code written.

Remaining work:
1. [DONE 2026-10-30] SARIF live demo - out.sarif schema-valid vs OASIS 2.1.0 on aborted-scan path (see benchmark/track_c/runs/20261030-233451-sarif-demo/). Zero code change; measurement only.
   validate against the schema fixture. Zero code required; this is measurement, not build.
2. Nuclei install + live demo - install binary, run `janissary attack nuclei <url>
   --attack-confirm --templates <path>` against one corpus app.
3. Record measurement - if either fails live (likely for Nuclei under real template/output
   variation), record as a measurement commit before the fix, exactly as 4a2d0d1 did for FN-3.

## Decision

Direction: **Candidate A - Integration arms**
Status: audit complete; first task not yet started
Rationale: Both arms are wired and unit-proven. The only gap between claim and evidence
is a live run. This is the smallest Phase 6 direction that produces real audit material.
Candidate B (new app) is higher-value but multi-hour. Candidate C (deeper corpus) risks
padding without generalization evidence.

First concrete task: SARIF live export against existing artifacts or an empty findings
store, validated against the OASIS schema fixture. No code change.

Exit criteria (adapted from the template below): live SARIF export validates against
OASIS 2.1.0; nuclei binary installed and one live run completes against a corpus app;
any failure recorded in git history before fix.

## Open questions for the first task

- Is a corpus app container currently running? If not, agent-path export against the
  findings store is the fallback (empty findings still produce schema-valid SARIF -
  test_sarif_empty_findings_still_schema_valid proves it).
- Nuclei template source - does the repo ship any, or must the user supply? `--templates`
  is required per cli.py:1465, so a template path is needed for the demo.
### FN-4 candidate (measured 2026-10-30, task 1 run)

Agent orchestrator exits 2 against vampi with "no platforms detected and no
fallback scan adapter registered". vampi is a locked corpus app with 4 known
vulnerability classes in apps.json.

Recorded in benchmark/track_c/runs/20261030-233451-sarif-demo/FN-4.md
before any fix. Not part of task 1. Fix is a separate forward commit.

Open question: does `janissary scan <url>` (single-module, no orchestrator)
work against vampi and produce SARIF? If yes, the gap is orchestrator-only;
if no, the gap is broader. That is the next measurement, not the next fix.
## Exit criteria template

Whichever direction is chosen, Phase 6 is done when:
- the capability is demonstrated against a live target, not only unit tests;
- any gap found is recorded in git history before it is fixed;
- full suite green and corpus numbers either reproduce or the delta is documented;
- package version matches newest tag (guard: tests/test_version_tag_consistency.py).
