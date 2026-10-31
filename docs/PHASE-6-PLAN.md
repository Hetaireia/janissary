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
2. [DONE 2026-10-31] Nuclei live demo - exit 0, nuclei_exit 0, aborted false, 0 findings, 70.7s. Export JSON parses. See benchmark/track_c/runs/20261031-000218-nuclei-demo4/. Zero code change.
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
### FN-4 scope conclusion (measured 2026-10-30, scan-vs-agent)

janissary scan -u http://127.0.0.1:5000 --export scan-out.sarif
  exit 0, SARIF 3682 bytes, schema-valid vs OASIS 2.1.0
  artifacts: benchmark/track_c/runs/20261030-233727-scan-demo2/

janissary agent http://127.0.0.1:5000 --attack-confirm --export out.sarif
  exit 2, "no platforms detected and no fallback scan adapter registered"
  artifacts: benchmark/track_c/runs/20261030-233451-sarif-demo/

**Conclusion:** FN-4 is orchestrator-scoped. The single-module scan path is
correct; the gap is in the agent module registry / platform detection path.
Fix shape: fallback scan adapter invoked when platform detection yields no
modules, instead of aborting. Narrow, additive, no change to scan.

Fix is a separate forward commit; not part of Candidate A task 1.
## Phase 6 close status (2026-10-31)

**Candidate A - Integration arms: COMPLETE.** Both arms live-proven with
schema-valid exports against a running corpus app.

- SARIF: aborted-scan path produced schema-valid SARIF 2.1.0 (e8e1b47)
- Nuclei: completed run, exit 0, valid JSON (20261031-000218-nuclei-demo4)

Neither needed code changes. Audit's "Medium if stubs" estimate was wrong;
reality was Small, and Small is now zero remaining work.

### Deferred work items (fully specified, not started)

**FN-4 - SHIPPED (`f02d72d`) - agent orchestrator gap.** `janissary agent` against vampi exits 2
with "no platforms detected and no fallback scan adapter registered".
`agent.py:189` already has the fallback hook (`plan = ["scan"] if "scan" in
self.adapters else []`), but no `"scan"` adapter is registered by `cli.py:904`.
Fix shape: write a scan adapter (target, context) -> list[Finding], register
it at cli.py:904, add a test. ~45-90 min. Additive; no change to agent.py or
scan. Measurement at e8e1b47 and a33cbb0.

**FN-5 - SHIPPED (`ebb449b`) - --nuclei-path CLI flag.** `NucleiRunner(nuclei_path=...)`
exists but `janissary attack nuclei` has no CLI flag to set it. The runner's
own error message advertises the capability ("or pass nuclei_path explicitly").
Fix shape: add `--nuclei-path` arg to the subparser at cli.py:1461, plumb
through to `NucleiRunner(...)`, add a test. ~15-30 min.

### Flag semantics discovery (worth a CLI docs fix, not yet filed)

`--rate-limit` is total requests/second across all templates, not per-template.
Observed: 219 templates at rate-limit 10 exceeded 120s; same set at rate-limit
100 completed in 70.7s. `--rate-limit` help text (cli.py:1480) is silent on the
semantic. One-line help update later; no behavior change.

#
## Environment carry notes for next session

- **FN-6 candidate (surfaced 2026-11-01 at `f02d72d`):** the fallback scan adapter runs and the agent exits 0, but a live run against vampi produced **0 findings**. Cause unmeasured: could be built-in default params not matching endpoint forms, or `scan -u` on a bare URL also finding 0. Next measurement: run `janissary scan -u http://127.0.0.1:5000` directly and compare findings count. If direct scan >0, gap is parameter discovery in the fallback; if 0, gap is broader.
- Nuclei not on PATH after direct-download install. `%LOCALAPPDATA%\Programs\nuclei`
  needs manual PATH prepend, or use the shipped `--nuclei-path` flag (FN-5, `ebb449b`). `go install` would
  put it on PATH but fails on Go 1.27 (dependency graph mismatch); winget is
  flaky; direct download is the reliable path.
- `nuclei -update-templates` hangs at cleanup on this machine (observed 6+ min
  past template download completion). Templates are complete; kill the process,
  don't re-run.
- PS7 8.3 short-name expansion: `Remove-Item $env:TEMP\...` fails with "object
  at path C:\Users\XXXXXX~1 does not exist" even when `Test-Path` returned true.
  Use `[System.IO.File]::Delete` / `[Environment]::GetFolderPath('...')` and
  avoid `$env:TEMP` / `$env:LOCALAPPDATA` in PS provider cmdlets.

## Candidate A exit criteria - met

- [x] SARIF arm produces schema-valid output on a live invocation
- [x] Nuclei arm completes a live run with valid JSON export
- [x] Both demonstrated against a running corpus app (vampi)
- [x] Zero code changes required (as the audit predicted, once "Medium" was corrected to "Small")
- [x] Evidence committed as run dirs, auditable in git log
## Exit criteria template

Whichever direction is chosen, Phase 6 is done when:
- the capability is demonstrated against a live target, not only unit tests;
- any gap found is recorded in git history before it is fixed;
- full suite green and corpus numbers either reproduce or the delta is documented;
- package version matches newest tag (guard: tests/test_version_tag_consistency.py).

---

## FN-6 resolution (2026-11-01)

**Status: RESOLVED — not a detection gap.**

The 2026-11-01 handover's FN-6 measurement was invalid. It ran
`janissary scan -u URL -p param` with default `--inject-in auto`, which uses
query-string injection for GET requests. Vampi's scored SQLi endpoint is
`/users/v1/{username}` with injection-location `path` (`cases.csv` row
`path_param_sqli`). Query injection against that route produces 0 findings
correctly — the payloads never reach the SQL.

**Verified correct invocation (9 findings / 2 groups):**

    janissary scan \
      -u "http://127.0.0.1:5000/users/v1/{username}" \
      -p username \
      --inject-in path \
      --baseline-value name1

Findings: `sql_single_quote`, `sql_union_null`, `sql_sleep_mysql`,
`sql_paren_quote`, `sql_paren_double`, `sql_paren_union`, `sql_paren_or`,
`sql_hash_comment`, and `sqli_quote_oracle`. All CRITICAL, matched SQLITE
error signature plus bare-quote oracle.

**H1 rejected:** vampi is a JSON API, no HTML forms to parse.

**H2 rejected:** scanner runs 351 clean requests against `/` and reaches
the differential phase on path routes without aborts or misdetection.

**Actual cause:** `--inject-in path` + `--baseline-value` are required for
path injection. Default `--inject-in auto` is query for GET. Both flags
exist and work; the measurement just didn't use them.

**Side findings filed:**

- **FN-10:** `--baseline-value` requirement for `--inject-in path` is
  undiscoverable from the `--inject-in` help text. Suggested fix: either
  mention `--baseline-value` in `--inject-in path` help line, or auto-probe
  common baselines (`admin`, `name1`, `1`, `test`).
- **FN-11:** Vampi's `/createdb` is non-idempotent — `drop_all()` +
  re-insert, random `bookTitle` collision mid-insert leaves DB half-seeded
  and 500s. Recovery is retry once or twice; document in `BOOTSTRAP.md`
  alongside the "state gap" section.

**Recommendation:** add a `BOOTSTRAP.md` section documenting the corpus
invocation per injectable-endpoint shape (query vs body vs path). This
session spent ~90 minutes on FN-6 because the invocation pattern wasn't
documented anywhere.
