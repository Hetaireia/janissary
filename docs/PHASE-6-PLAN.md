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

---

## FN-12 — SQLi on non-2xx baseline endpoints is a detection blind spot

**Status: FIXED 2026-11-01.**

**Fix commits:** `faade6c` (core: analyzer gate + conditional corroborator
drop), `2707a32` (template `_categories` opt-in), `ef79e31` (CLI display),
`96e0e49` (JSON/SARIF output), `c4e994a` (`scan_incomplete` flag),
`fd1c870` (regression suite).

**Verified end-to-end:** OWASP Juice Shop `/rest/user/login` produces
findings marked `unproven` with `verification_reason='corroborator_structural'`.
See `LIMITATIONS.md` FN-12 (FIXED 2026-11-01) and `BENCHMARK.md`
Amendment 25.

> **Session-4 correction to `f28b10e`:** that commit's message claimed to
> reclassify this entry but the file was not modified; a subsequent
> commit performed the reclassification.
>
> **Session-22 status update:** reclassified to FIXED after Phase 0.2(b)
> landed.

### Symptom

`janissary scan -u "http://127.0.0.1:3000/rest/user/login" -p email
--method POST --inject-in json-body --json-template tmp-juice-login.json`
produces 0 findings against a demonstrably vulnerable endpoint.

### Manual proof of vulnerability

| Request | Response |
|---|---|
| `{"email":"admin@juice-sh.op","password":"wrongpassword"}` (baseline) | 401 |
| `{"email":"admin@juice-sh.op'","password":"x"}` | **500** |
| `{"email":"' UNION SELECT 1,2,3--","password":"x"}` | **500** |
| `{"email":"admin'","password":"x"}` | **500** |

Error-based SQLi confirmed. Every error-inducing payload returns 500, distinct
from the 401 baseline. The scanner sends all 8 payloads but produces 0 findings.

### Root cause (two compounding)

1. **Status gate disabled when baseline isn't 2xx.** Scan output warns:
   `[email] warning: baseline modal status is 401 - status gate disabled`
   The "different status = potential finding" logic shuts off when baseline is
   4xx/5xx. Heuristic is reasonable for GET endpoints (400 response to malformed
   input is noise), but wrong here — 5xx vs 4xx is categorically different.

2. **No SQL error text in juice-shop's 500 body.** Express default 500 page has
   no `SQL syntax error near` signature. Error-signature matcher also doesn't
   fire. Two safety nets, both ineffective for this endpoint class.

### Why the corpus didn't catch it

Prior cases exercised query params and path params, but the only error-based
SQLi case with a non-2xx baseline is crapi's `/workshop/api/shop/apply_coupon`
(`json_body:templates/crapi_coupon.json`). That case's `expected_finding_class`
is `sqli_blind` — meaning the corpus already expects only blind detection on
that endpoint, not error-signature detection. Whether the current scanner
actually detects that case has not been re-verified this session.

### Proposed fix (30-60 min)

The status gate should fire on **5xx-vs-non-5xx deltas** regardless of baseline
status. Concrete: in the status-gate logic, allow findings when
`payload_status >= 500 and baseline_status < 500`. That catches server-side
errors as injection signals without turning every 400 into a finding.

Files likely to change: `src/janissary/engine/scanner.py` (status gate logic),
possibly `src/janissary/engine/analyzer.py` or whatever module handles finding
emission. Tests: add a test that a 500 response to a payload is a finding when
baseline is 401 and a test that 400-vs-401 is not (to avoid FP regression).

### Reproducer for next session

    # 1. Confirm vulnerability
    curl.exe -s -o NUL -w "%{http_code}`n" -X POST http://127.0.0.1:3000/rest/user/login -H "Content-Type: application/json" -d '{"email":"admin'"'"'","password":"x"}'
    # -> 500

    # 2. Confirm scanner miss
    @'
    {"email":"{{PAYLOAD}}","password":"x"}
    '@ | Set-Content -LiteralPath tmp-juice-login.json -Encoding utf8 -NoNewline

    & ".\.venv\Scripts\python.exe" -m janissary scan -u "http://127.0.0.1:3000/rest/user/login" -p email --method POST --inject-in json-body --json-template tmp-juice-login.json --baseline-count 5
    # -> 0 findings (bug)

### Candidate corpus case (deliberately NOT committed)

    juice-shop,/rest/user/login,POST,email,sqli,false,sqli,json_body:templates/juice_login.json,,

Template committed at `benchmark/track_c/templates/juice_login.json`.

> **Session-22 update:** the case WAS added on 2026-11-01 in commit
> `5976d32` after the fix landed. It is now a permanent regression guard:
> if FN-12 ever recurs, the Track C juice-shop run will show `fn=1`.
> The original "do not add" guidance applied only to the pre-fix state.

### Filed-by evidence

Session 2026-11-01, second handover. Diagnostic scripts in transcript.

## FN-13 — Reflected XSS on JSON APIs is a detection blind spot (RETRACTED)

**Status: RETRACTED 2026-11-01. Filed on a false premise.**

> **Retraction note:** FN-13 was filed based on a Track C expansion
> (BENCHMARK.md Amendment 25) that appeared to expose an xss detection
> gap on Juice Shop's `/rest/products/search?q=` endpoint. Subsequent
> investigation (session 24, commit `77821e2`) found two compounding
> errors in the original filing:
>
> 1. The xss trial used an endpoint that does not reflect payloads
>    server-side (Angular SPA, client-rendered results). The response was
>    verified live: `{"status":"success","data":[]}`.
> 2. The benchmark runner had a filename collision bug that produced a
>    phantom sqli FN, which was conflated with the xss trial's expected
>    miss.
>
> Neither was a scanner defect. See BENCHMARK.md Amendment 26 for the
> full retraction and corrected Track C measurement (P=R=F1=1.0, tp=12,
> fn=0). The DOM-based XSS scope limit is documented in LIMITATIONS.md
> under "DOM-based XSS on SPAs" — as a limit of the tool class, not a
> bug.

### Symptom

`janissary scan -u "http://127.0.0.1:3000/rest/products/search?q=test" -p q --jsonl --quiet`
produces zero xss findings against an endpoint that reflects xss payloads
back in the JSON `data` array.

### How it was found

Not by a user report — by the Track C expansion on 2026-11-01. Adding the
xss-search trial to `benchmark/track_c/cases.csv` (commit `5976d32`) took
the corpus from tp=11 fn=0 to tp=12 fn=1, falsifying Track C hypothesis
H-C2 (see `BENCHMARK.md` Amendment 25). The FN exposed a real gap that
the previous 1.0 F1 was hiding.

### Root cause

Two compounding issues in the reflection path:

1. **The reflection gate is category-scoped.** `scanner.py` refuses to
   emit `payload_reflected` under any category except xss (correctly — an
   echo on an sqli probe is not evidence of sqli). But it also does not
   promote `payload_reflected` to `reflected_xss` when the response is a
   JSON API — the reflected-xss oracle expects HTML context.
2. **No JSON-aware xss oracle exists.** The reflected-xss oracle runs
   against HTML responses. On a `Content-Type: application/json` response,
   the payload in the body is real reflection but the oracle cannot classify
   it because it does not parse JSON to find the reflected value under an
   HTML-rendering assumption.

The sqli finding *is* correctly emitted on this endpoint because the
endpoint *is* SQLi-vulnerable. The xss signal is lost, not the sqli signal.

### Why the corpus didn't catch it

Track C's juice-shop had 3 cases (1 vuln sqli, 2 safe) prior to `5976d32`.
xss was in `apps.json` `known_vulnerable` but had no trial in `cases.csv`.
Amendment 23 recorded the corpus as it stood; the gap was latent from the
start.

### Proposed fix

Phase 2 protocol-specific oracle work. Two options, not mutually exclusive:

- **A (JSON-aware confirmer, ~2 hrs):** add a `JsonReflectionConfirmer`
  that parses `application/json` response bodies, searches string fields
  for the payload, and confirms reflection with `verification_reason='json_reflection'`.
  Emit as `verified` (not `unproven`) because JSON-reflected payloads are
  documented exploitable when the consumer renders them — this is signal,
  not a structural observation.
- **B (content-type dispatch, ~30 min):** route responses by `Content-Type`
  header so JSON bodies go to a JSON-aware path and HTML bodies to the
  existing oracle. Lighter than A; leaves JSON as `unproven` pending A.

B is the minimum viable fix; A is the correct one. B unblocks the corpus
quickly; A closes the gap properly.

### Verification criterion

After the fix, re-run `benchmark/track_c/runner.py --app juice-shop`.
Expected: `xss.jsonl` in the run directory contains at least one finding
with `class='xss'` on `/rest/products/search?q=test`. Corpus
`H-C2` then holds again at 13/13, and Track C aggregate returns to F1=1.0
— but with genuinely broader coverage than the pre-`5976d32` 11-trial
corpus.

Do **not** re-run with `fn=1` accepted as the new normal. H-C2 falsification
is a record of the gap, not a change to the hypothesis.

### Reproducer

    docker start janissary-trackc-juice  # or docker run -d -p 3000:3000 ...
    janissary scan -u "http://127.0.0.1:3000/rest/products/search?q=test" -p q --jsonl --quiet

Expected: xss finding on the q parameter.
Actual: no xss finding (sqli finding emitted).

### Filed-by evidence

Session 2026-11-01 (session 20). Track C expansion. Full trail:

- `BENCHMARK.md` Amendment 25 — the measurement and H-C2 falsification
- `LIMITATIONS.md` "Reflected XSS on JSON APIs" — user-facing entry
- `benchmark/track_c/runs/20261101T062713Z-juice-shop/` — the run artifacts
- `benchmark/track_c/corpus-score.json` — corpus aggregate at `ac8e19e`

## FN-14 — Track C runner overwrites findings when two trials share a vuln_class

**Status: FIXED 2026-11-01 (commit `77821e2`).**

### Symptom

Running `benchmark/track_c/runner.py --app juice-shop` with two sqli
trials (login + search) produced only one sqli finding in the run
directory. The second trial's output file overwrote the first's.

### Root cause

`runner.py:scan_case` wrote findings to `{case['vuln_class']}.jsonl` in
`"w"` mode. Any two trials in the same app with the same `vuln_class`
shared a filename. The last trial to run clobbered the previous one.

Session 20's Track C expansion added two sqli trials to juice-shop
(`5976d32`). The runner collision turned the correct `tp=2` result into
`tp=1, fn=1` — a phantom FN that was then attributed to an unrelated
xss trial, cascading into FN-13's false filing.

### How it was found

Session 24 investigation of FN-13's claimed xss gap. Verifying whether
the xss payload was actually reflected (it wasn't) also revealed that
the sqli findings file contained only the login finding, not the search
finding — despite both trials returning exit code 1 with non-empty
output.

### Fix

`benchmark/track_c/runner.py`:
- `scan_case` gains an `idx` parameter (trial index within the app's case set)
- Output files become `{idx:03d}-{vuln_class}.jsonl` and `.stderr`
- Caller passes `idx` from `enumerate(cases)`

`benchmark/track_c/score.py`:
- `case_class` extraction now strips the numeric prefix:
  `jl.stem.split('-', 1)[1] if '-' in jl.stem else jl.stem`
- Backward-compatible: old runs without numeric prefix still parse correctly

### Verification

New juice-shop run `20261101T065046Z-juice-shop` produces four separate
files (`000-sqli.jsonl`, `001-safe.jsonl`, `002-safe.jsonl`,
`003-sqli.jsonl`). Score: `tp=2, fn=0, f1=1.0`. See BENCHMARK.md
Amendment 26.

### Filed-by evidence

Session 2026-11-01 (session 24). Investigation of FN-13. Full trail:

- `77821e2` — the fix commit (runner.py + score.py + re-run artifacts)
- BENCHMARK.md Amendment 26 — the retraction and corrected numbers
- `benchmark/track_c/runs/20261101T065046Z-juice-shop/` — the correct run artifacts

### Retrospective

This bug existed since Track C was introduced (Amendment 23, 2026-10-30).
It was latent because every app in the pre-expansion corpus had at most
one trial per vuln_class. The juice-shop expansion was the first app with
two sqli trials, which exposed the collision. Any future app with
multiple trials of the same class would have hit the same bug.

## FN-15 — GraphQL findings bypass the VerificationEngine and BaselineNormalizer

**Status: FIXED 2026-11-01.**

**Fix commits:**
- `cdda9d3` — `GraphQLNormalizer` (part 1)
- `1c60ac1` — `GraphQLDiscoveryModule` (part 2)
- `918365a` — `GraphQLReconConfirmer` + `_ENGINE` wiring (part 3a)
- `5e6ecc3` — `Scanner.scan_graphql()` (part 3b)
- `acf528d` — `--graphql` CLI flag + merge helper (part 3c)

> **Session-34 status update:** reclassified from FILED to FIXED after
> the five-part integration landed across sessions 29–33. The original
> framing — "not a bug, a documented integration gap" — remained
> accurate throughout; the gap is now closed. Findings now flow through
> `VerificationEngine.verify()` and are marked `unproven` by
> `GraphQLReconConfirmer` (reason `graphql_recon`) rather than
> overclaimed as `verified`. See the 51 integration tests across
> `test_protocols_graphql.py`, `test_graphql_discovery.py`,
> `test_graphql_recon_confirmer.py`, `test_scan_graphql.py`, and
> `test_graphql_cli.py`.

### What it is

GraphQL feature coverage is present (`src/janissary/integrations/graphql.py`,
20KB, 25 tests): introspection, depth probes, alias probes, argument
fuzzing, batch detection. The module works.

The missing piece is integration. Findings produced by the
`janissary graphql` subcommand do not route through
`VerificationEngine.verify()`. They are printed directly by
`cli.py:cmd_graphql` and never become `CandidateFinding` or
`VerifiedFinding` objects. They therefore do not participate in:

- Phase 0.1's emission boundary invariant (`ScanSummary.findings` only
  accepts engine-produced findings)
- Phase 0.3's baseline normalization (no `GraphQLNormalizer` exists)
- Cross-class grouping in `summary.groups`
- SARIF/JSON output uniformity with other finding classes

Same structural shape as nuclei (`PHASE-0.1-SCOPE.md` section 1) and
WebSocket (section 2). GraphQL is the third deliberate scope exception
to Phase 0.1's "engine is sole emitter" invariant.

### How it was found

Session 26 inspection during Phase 2.1 scoping. LIMITATIONS.md claimed
"introspection and depth only" — factually wrong in one direction
(module does more) and missing the integration caveat in another.
Corrected in the same session.

### Root cause

Not a defect. `integrations/graphql.py` was developed before Phase 0.1
existed and predates the engine boundary. Wiring the subcommand
through `Scanner.scan()` was never in scope for the graphql recon
workflow — it was a standalone tool.

### Proposed integration (Phase 2.1 proper)

Three pieces, independent:

1. **`GraphQLNormalizer`** — `protocols/graphql.py`, implementing the
   Phase 0.3 `BaselineNormalizer` interface. Must:
   - Parse JSON responses
   - Sort object keys recursively (field-order variance)
   - Strip resolver timing fields
   - Normalize error message formatting
   - Return `NormalizedResponse` with `stripped` metadata

2. **`GraphQLDiscoveryModule`** — wraps existing `detect()` +
   `introspect()` + `fuzz_arguments()` to produce `CandidateFinding`
   objects with schema path attached. No direct emission.

3. **Scanner integration** — `Scanner.scan()` optionally invokes the
   discovery module when the endpoint reports GraphQL support. All
   candidates route through `VerificationEngine.verify()` before
   entering `summary.findings`. Confirmer strategy TBD — likely a
   `GraphQLResponseConfirmer` that inspects the `data` field
   structurally (per ROADMAP Phase 2.1).

### Verification criterion

After the integration:

1. `janissary scan -u <graphql-endpoint> -p x` produces findings in
   `summary.findings` with `verification_status` populated.
2. `janissary graphql -u <endpoint>` remains as a recon-only subcommand
   (unchanged behavior; or deprecated in favor of scan path — decide
   during implementation).
3. SARIF/JSON output for GraphQL findings is structurally identical to
   HTTP findings.
4. `tests/unit/test_graphql.py` gains coverage for:
   - `GraphQLNormalizer` construction and behavior (analogous to
     `test_protocols_http.py`)
   - Candidate emission shape
   - Engine routing (i.e., the finding is a `VerifiedFinding`, not a
     raw dict)

### Not blocked by

- Phase 0.1 — complete, the interface is stable
- Phase 0.3 — complete, `BaselineNormalizer` is stable

The GraphQL integration can be scheduled whenever Phase 2.1 opens.
Estimated effort: 2-4 hours for `GraphQLNormalizer` + tests, plus
however much integration into `Scanner.scan()` needs (unknown until
the Scanner routing for GraphQL is inspected).

### Filed-by evidence

Session 2026-11-01 (session 26). Investigation of Phase 2.1 readiness.
Relevant files inspected:

- `src/janissary/integrations/graphql.py` (20KB, 25 tests, standalone)
- `src/janissary/cli.py:426` (`cmd_graphql` — prints directly, no
  engine routing)
- `src/janissary/agent/adapters.py:103` (imports `detect`, agent path)
- `LIMITATIONS.md` (stale claim, corrected this session)
- `docs/PHASE-0.1-SCOPE.md` (did not mention GraphQL, corrected this
  session)

No commit fixed this — the filing is the record of the gap.

## FN-16 — WebSocket recon exists; Phase 2.2 learn/probe/verify pipeline does not

**Status: FILED 2026-11-01. Phase 2.2 build gap, distinct from FN-15
(GraphQL integration).**

### What exists

`src/janissary/integrations/websocket.py` (8KB, 13 tests) provides
passive reconnaissance for one endpoint at a time:

- `is_plaintext()` — `ws://` detection on non-loopback hosts
- Missing-Origin validation (cross-site WebSocket hijacking detector)
- Blind echo detection
- No-auth handshake check
- `scan_sync()` / `scan()` entry point

The `janissary ws <url>` subcommand calls `scan_sync()` directly and
prints findings; nothing routes through `Scanner.scan()`,
`VerificationEngine`, or `BaselineNormalizer`.

### What Phase 2.2 requires that does not exist

From `docs/ROADMAP.md` Phase 2.2:

1. **Learn phase** — sample traffic passively for N seconds, fingerprint
   the wire format (JSON/XML/Protobuf), identify injectable fields, and
   record a baseline message sequence. **Not implemented.**
2. **Probe phase** — inject the payload into a well-formed base message
   (not a raw string). **Not implemented.**
3. **Verify phase** — compare observed message sequences against the
   baseline, allowing for interleaving and delay, and flag only a
   reproducible semantic delta. **Not implemented.**

Without (1) and (3), the current module cannot detect WebSocket-based
injection — it only detects configuration-level weaknesses (plaintext,
missing Origin, no-auth) and blind echo.

### Why this is a different gap than FN-15

| | GraphQL (FN-15) | WebSocket (FN-16) |
|---|---|---|
| Existing size | 20KB | **8KB** |
| Existing detection classes | 5 (full) | **4 (passive only)** |
| Missing | Engine routing + `GraphQLNormalizer` | **Learn/probe/verify pipeline + engine routing + `WebSocketNormalizer`** |
| Effort to complete Phase | ~2–4 hours | **~8–16 hours (substantial build)** |

FN-15 is a wiring task — the features are there, they just need to flow
through the engine. FN-16 is a build task — the Phase 2.2 features do
not exist. Scheduling them the same way would underestimate FN-16 by a
factor of four.

### Not blocked by

- Phase 0.1 — complete, the engine interface is stable
- Phase 0.3 — complete, `BaselineNormalizer` is stable
- Phase 2.1 / FN-15 — independent

Can be scheduled whenever Phase 2.2 opens. The existing passive-recon
code is a solid foundation to build on; the missing pieces are the
bidirectional stateful test harness, the wire-format fingerprinter,
and the message-sequence differ.

### Verification criterion (for Phase 2.2 proper)

1. `janissary scan -u <ws-endpoint>` (or a `--ws` flag) runs the
   learn/probe/verify pipeline, produces findings in
   `ScanSummary.findings` with `verification_status` populated.
2. A `WebSocketNormalizer` exists in `protocols/websocket.py`,
   implementing the Phase 0.3 `BaselineNormalizer` interface, and
   normalizes message *sequences*, not frames.
3. Test corpus includes at least one realtime app with documented
   CSWSH and injection issues (roadmap Phase 2.2 requires a benchmark
   target — currently none exists).
4. Existing `janissary ws` subcommand either stays as a passive-recon
   entry point or is deprecated in favor of the scan path; decide
   during implementation.

### Filed-by evidence

Session 2026-11-01 (session 27). Investigation following FN-15's
identification of the "roadmap may underestimate existing code" pattern.

Relevant files inspected:

- `src/janissary/integrations/websocket.py` (8KB, passive-only)
- `src/janissary/cli.py:520` (`cmd_websocket` — standalone, prints directly)
- `docs/PHASE-0.1-SCOPE.md` — WebSocket section is accurate as-written
  (verified this session; no change needed)
- `LIMITATIONS.md` — "not supported" was wrong; corrected to "passive
  recon only" this session

No commit fixed this — the filing is the record of the gap. FN-16 is
the concrete scope for whoever opens Phase 2.2.

## FN-17 — gRPC protocol support does not exist (Phase 2.3 greenfield)

**Status: FILED 2026-11-01. Build gap. Unlike FN-15 and FN-16, no
existing code exists at all.**

### Current state

- `src/janissary/integrations/grpc.py` — **does not exist**
- `tests/unit/test_grpc.py` — **does not exist**
- Zero references to `grpc`, `protobuf`, or `proto3` in `src/` (verified
  via grep after correcting an over-broad pattern that was also matching
  XSS `reflection` code)
- `LIMITATIONS.md` says "not supported" — **accurate**
- `docs/PHASE-0.1-SCOPE.md` makes no mention of gRPC — **accurate**,
  nothing to scope out

This is the first of the three protocol phases where the roadmap's claim
matches reality. Phase 2.1 and 2.2 both had more existing code than the
roadmap assumed. Phase 2.3 is genuinely greenfield.

### Roadmap Phase 2.3 scope (unmodified)

From `docs/ROADMAP.md`:

1. **`gRPCDiscoveryModule`** — uses server reflection to enumerate
   services and methods; parses message descriptors to understand field
   types; generates type-aware mutations
2. **`baseline_message()`** — constructs a valid request from the
   descriptor
3. **`fuzz_field()`** — mutates one field at a time, per type class
   (strings get SQLi/XSS/traversal payloads; ints get boundary values;
   bytes get null-byte patterns)
4. **Verification oracle** — decode the response Protobuf, compare
   field values structurally against baseline, require reproducible
   delta across three runs before emitting

Plus a **hard constraint from the roadmap**:

> If server reflection is unavailable, the module must report
> `grpc_reflection_unavailable` and produce zero findings. It must not
> fall back to HTTP-level guessing.

That constraint is important and is why gRPC is *harder* than HTTP
protocol work. HTTP always has a message you can send even without a
schema. gRPC requires schema knowledge to construct a valid Protobuf
message at all. Guessing at binary framing is not a fallback — it is
either a decode error or a false positive. The roadmap is right to
forbid it.

### Why this is different from FN-15 and FN-16

Three-way sizing comparison:

| Tracker | Existing code | Missing | Effort |
|---|---|---|---|
| **FN-15 (GraphQL)** | 20KB, 5 classes | Engine wiring + normalizer | ~2–4 hrs |
| **FN-16 (WebSocket)** | 8KB, 4 passive checks | Learn/probe/verify pipeline | ~8–16 hrs |
| **FN-17 (gRPC)** | **0 bytes** | **Everything** | **~12–20 hrs** |

FN-17 is harder than FN-16 for two structural reasons:

1. **Binary protocol infrastructure.** Protobuf requires encode/decode
   tooling. Whether to use `google.protobuf`, `grpcio`, or a leaner
   dependency is a project decision with license/bundle-size implications.
2. **Reflection gating.** gRPC server reflection is not universally
   enabled. A tool that requires it produces zero findings on
   non-reflecting servers — a large fraction of real deployments. The
   roadmap's "don't fall back to guessing" constraint means gRPC support
   will be narrower in applicability than HTTP support, and that's a
   documented posture, not a temporary limitation.

### Not blocked by

- Phase 0.1 — complete, the engine interface is stable
- Phase 0.3 — complete, `BaselineNormalizer` is stable; a future
  `GRPCNormalizer` would implement the same interface
- FN-15 or FN-16 — independent

Schedulable whenever Phase 2.3 opens, but should not be scheduled
optimistically. The infrastructure decision (Protobuf dependency)
should be made explicitly before code work begins.

### Verification criterion (for Phase 2.3 proper)

1. `GRPCDiscoveryModule` enumerates services and methods via reflection
   on a test gRPC server that has reflection enabled.
2. The module emits `CandidateFinding` objects with the schema path
   attached (e.g., `Service.Method.Field`).
3. All candidates route through `VerificationEngine.verify()`.
4. `GRPCNormalizer` exists in `protocols/grpc.py`, decodes Protobuf
   responses to comparable structures, and normalizes before delta
   computation.
5. On a server without reflection: module reports
   `grpc_reflection_unavailable`, emits zero findings, and does not
   fall back to HTTP framing guesses.
6. Benchmark target added to `benchmark/track_c/` (a gRPC service with
   known vulnerabilities) — currently none exists.

### Filed-by evidence

Session 2026-11-01 (session 28). Final phase of the roadmap-vs-reality
audit begun in sessions 26 (GraphQL) and 27 (WebSocket).

Files inspected:

- `Get-ChildItem '*grpc*'` in `src/` and `tests/unit/` — **zero results**
- `Select-String 'grpc|protobuf|proto3'` in `src/` — matches are all
  `reflection` (XSS context), zero gRPC
- `LIMITATIONS.md` line 31 + line 150 — "not supported" is accurate

No commit fixed this — the filing is the record of the gap, and it
records the three-phase audit finding: **the roadmap is accurate about
Phase 2.3 and undersells Phases 2.1 and 2.2.**

## FN-18 — GraphQL depth_probe returns 1 (no depth testing) against every real server

**Status: FIXED 2026-11-01 (commit `1f4cca5`, live-verified).**

> **Session-37 status update:** fixed and live-verified against the
> GraphQL fixture server (`scripts/graphql_fixture_server.py`). All 5
> detection paths now fire against a real graphql-core server
> (introspection, batching, suggestions, depth, alias).
>
> **Also uncovered while fixing FN-18:** `build_wrapped_nested_query`
> had a *separate* bug — it did not terminate the innermost selection
> with `__typename`, so every depth produced a GraphQL validation error
> instead of a valid nested query. Fixed in the same commit with a
> regression test (`test_build_wrapped_nested_query_ends_with_typename_leaf`).
> This is exactly the class of bug FN-18's fix was supposed to expose:
> a fix that only *looks* correct until it hits a real server.

### Symptom

`GraphQLDiscoveryModule` against any real GraphQL server never emits
`graphql_depth_abuse`. `depth_probe` returns `(1, "<any error>")` and the
`< _DEPTH_THRESHOLD` check skips emission — reported as "no depth issue"
when no depth was actually tested.

### Root cause

`build_nested_query(field, depth)` produces `{ field { field { ... } } }`.
`depth_probe` calls it with `field_name="__typename"` (its default). But
`__typename` is a GraphQL built-in scalar (`String!`) — scalars cannot
have subfields. Any server responds with a validation error:

    Field "__typename" must not have a selection since type "String!" has no subfields.

In `depth_probe`:

    if _refused(resp, DEPTH_ERROR_RE) or _is_error_only(resp):
        high = d

`_is_error_only()` returns True for ANY error-only response — validation
errors included. The loop treats a validation error on depth-2 as a
"depth refusal" and returns `low=1`. Then `1 < 10` = no finding.

### How it was found

Session 36, live validation against a real graphql-core server. Session 35
missed it — I attributed "no depth_abuse finding" to "shallow fixture" but
the actual cause was client code silently accepting a validation error
as a depth refusal.

### Proposed fix

**A (real fix):** `GraphQLDiscoveryModule._probe_candidates` derives a
self-referencing field from the introspected schema (e.g. `User.friend:
User`, `Post.author: User` + `User.posts: [Post]`). Pass that field name
to `depth_probe(field_name=...)`. `depth_probe` already accepts the
parameter (unused because default is `__typename`).

**B (safety net):** in `depth_probe`, remove `_is_error_only()` from the
depth-refusal branch. Only treat a refusal as depth-related if
`DEPTH_ERROR_RE` matches. The current query would then fail loudly
(server rejects it) and return `depth=None` — still no finding, but
honest about why.

A is the fix; B ensures the fix can't silently regress.

### Verification criterion

- Against a fixture with recursive type: `depth_probe` returns `(low>1, refusal)`;
  `graphql_depth_abuse` fires with real depth in detail
- Against a schema with no self-referencing type: no finding emitted,
  note logged (not "no depth issue" but "depth not testable on this schema")

### Filed-by evidence

Session 36 inspection of `graphql.py:185-190` (`build_nested_query`) and
`graphql.py:512-550` (`depth_probe`). Session 35 live-validation commit
`334b625` surfaced the absence by not exercising depth; session 36
identified the cause.

---

## FN-19 — GraphQL suggestions_enabled can never fire on a real server

**Status: FIXED 2026-11-01 (commit `1f4cca5`, live-verified).**

> **Session-37 status update:** fixed and live-verified against the
> GraphQL fixture server (`scripts/graphql_fixture_server.py`). All 5
> detection paths now fire against a real graphql-core server
> (introspection, batching, suggestions, depth, alias).
>
> **Also uncovered while fixing FN-18:** `build_wrapped_nested_query`
> had a *separate* bug — it did not terminate the innermost selection
> with `__typename`, so every depth produced a GraphQL validation error
> instead of a valid nested query. Fixed in the same commit with a
> regression test (`test_build_wrapped_nested_query_ends_with_typename_leaf`).
> This is exactly the class of bug FN-18's fix was supposed to expose:
> a fix that only *looks* correct until it hits a real server.

### Symptom

`GraphQLDiscoveryModule` never emits `graphql_suggestions_enabled` against
any real GraphQL server, regardless of whether the server produces field
suggestions.

### Root cause

`detect()` probes with:

    query { __definitelyNotARealField_xyz }

and looks for a response matching:

    r'Did you mean\s+["\']?([A-Za-z_][A-Za-z0-9_]*)["\']?'

Real GraphQL servers (graphql-core, Apollo, Hasura) emit suggestions only
when the probe name is *close to* a real field — typically Levenshtein
distance ≤ 2-3. `__definitelyNotARealField_xyz` is ~20 edits from any real
field. No suggestion is ever produced. `SUGGESTION_RE` never matches.

### How it was found

Same session 36 inspection as FN-18. Session 35 called it "correct
behavior, probe too far from schema fields" — treating the fixture as the
constraint. In reality the constraint is the client's probe choice, which
is fixed regardless of schema.

### Proposed fix

`_probe_endpoint` in `graphql.py` should do suggestions detection AFTER
introspection (which is step 2):

1. Pick a real field name from `profile.schema`
2. Mutate by one character: delete one, transpose two, substitute one
3. Send `{ <mutated> }` as the probe
4. Check `SUGGESTION_RE` against error messages
5. If suggestion mentions the original field name, `suggestions_supported = True`

If introspection is unavailable, report `suggestions_untestable` rather
than `suggestions_supported = False` — honest about the uncertainty.

### Verification criterion

- Against graphql-core: `suggestions_enabled` fires with `True`
- Against a server that disables suggestions: `False`
- Against schema-inaccessible server: `False` with a note (not silent FN)

### Filed-by evidence

Same as FN-18. Session 36 inspection of `graphql.py:83-95` and
`graphql.py:~410` (`_probe_endpoint` step 4).

---

## FN-18 / FN-19 — shared root cause and lesson

Both bugs share a pattern: **client code assumes a fixed probe shape works
against any schema, without deriving it from the schema itself.** Both
would have been caught by session-36 inspection; both were masked in
session 35 by my initial "shallow fixture" explanation.

The general lesson: **a probe that never fires because of an assumed
constant is indistinguishable from a probe that works and reports
"clean."** Any future `probe_*` function needs a positive-control test
against a real server, not just unit tests with mock responses.

## FN-16 follow-up: WebSocket recon findings presentation

Smoke test (local echo server, `--ws --ws-payloads payloads.txt`) produced
11 findings, all `verification_status=unproven`, all `websocket_*_probe`,
all `severity=medium`. Verification is correct; the human summary is not.
Evidence: `docs/smoke-evidence/fn16-ws-smoke-echo-server.json`.

### Items
- [x] Human summary (`cli.py _print_summary`) does not surface `unproven`.
      Fixed in 186c7a8: severity fallback now annotates `(unproven: N)`.
      Runtime-confirmed against local echo server:
      `    MEDIUM     11  (unproven: 11)`.
- [x] `WebSocketDiscoveryModule.discover()` detail string is
      "produced a server response that differs from baseline" for every
      payload class. Fixed in 02c6a05: binary taxonomy
      (`echoed_payload` vs `response_delta`) appended as
      ` (delta: <kind>)`.

      Runtime smoke against local echo server:
      `10/11 echoed_payload, 1/11 response_delta`. The outlier is
      the fallback working as designed — one payload value did not
      appear verbatim in the normalized echoed response (likely a
      normalizer-stripped payload such as `generic_null_byte`). Not a
      bug; taxonomy is "did the payload come back verbatim," and one
      did not. If future investigation identifies a case where an
      echoed payload incorrectly falls into `response_delta`, that
      becomes a `_classify_delta` refinement ticket.

      Status/timing deltas deferred — verify() does not currently
      compute them; adding that is a separate change that would expand
      what the normalizer compares.
- [ ] `LIMITATIONS.md`: note that discover() fires on echo-reflection —
      correct given inputs, but worth saying out loud.

### Not bugs (do not "fix")
- Verification engine marks all recon probes `unproven`: correct.
- `Scanner.scan_ws` URL handling: fixed in 8f821ad, runtime-confirmed.
- Discovery fires one candidate per payload: by design.
