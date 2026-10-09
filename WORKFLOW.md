# JANISSARY — Port Workflow Tracker
## STATUS: S10 CLOSED — three-run Track A reproducible at F1 0.682 / P 1.000; shim flake fixed and pushed
## NEXT: Recall recovery — 682 FN, of which 86 are the TP paths the FP fix cost (0.724 -> 0.682). Then structural throttle fix (--library-mode, Phase 4.5).
## LAST COMPLETED: Three clean single-process runs at F1 0.682 (P 1.000 / R 0.518). Shim crash (WinError 5 / 0xC0000005, ~7% per spawn) worked around via JANISSARY_USE_MODULE=1. Five commits pushed to origin/main, HEAD b651c29. See SESSION HANDOFF.

Last updated: 2026-10-09
Project root: C:\Users\M5 E60\janissary-project\janissary

---

## How to resume after losing context

From PowerShell, in the project root:

    Get-Content WORKFLOW.md -TotalCount 20

Or, to jump straight to the current step:

    Select-String -Path WORKFLOW.md -Pattern "^## Current step" -Context 0,30

From VS Code: open WORKFLOW.md. The STATUS / NEXT / LAST COMPLETED
lines at the top tell you exactly where we are. Copy the Current Step
section into the chat and continue.

---

## Rules of engagement

1. One command at a time. Wait for output before issuing the next.
2. Never batch PowerShell commands — each is reviewed before the next.
3. Update this file at the end of every completed step.
4. If a command fails, stop and report the error before proceeding.

---

## Phase 0 — Green baseline — COMPLETE

Goal: janissary scan finds a real SQLi on a mock server.

- [x] P0.1 Fix scanner.py indentation bug
- [x] P0.2 Nest payload loop inside the params loop
- [x] P0.3 Integration test for scanner (mock HTTP, one SQL error)
- [x] P0.4 Prototype not on disk, no-op

## Phase 1 — High-value subsystems — COMPLETE

- [x] P1.1a Credential scanner engine + CLI
- [x] P1.1b Git history walker (--scan-git + path validation)
- [x] P1.2 WAF detector + adaptive pacer
- [x] P1.3 XML-RPC multicall harness
- [x] P1.4 Platform fingerprint

## Phase 2 — Medium-value subsystems — COMPLETE

- [x] P2.1 GraphQL fuzzer
- [x] P2.2 WebSocket scanner
- [x] P2.3 Admin panel probe

## Phase 3 — Low-value / risky subsystems — COMPLETE

- [x] P3.1 SQLi UNION extractor (gated behind --attack-confirm)
- [x] P3.2 Nuclei runner (expose NucleiRunner, drop stub)
- [x] P3.3 Agent / FindingStore / PlatformKB

## Legal framework — DONE

- [x] LEGAL.md + first-run acceptance gate (210 tests pass at the time)

---

## P3.1 — SQLi UNION extractor (DONE)

Delivered:

- New `src/janissary/attack/` package, separate from `detection`
  on purpose: detection identifies, attack extracts.
- `src/janissary/attack/sqli_union.py`:
    - `UnionExtractor`, `build_union_payload`, `detect_dbms`,
      `split_concat`.
    - Per-DBMS metadata queries for MySQL, PostgreSQL, MSSQL,
      Oracle, SQLite.
    - `AttackConfirmationRequired`, `UnstableTargetError`.
- Three independent safety layers: Terms-of-Use gate (fires because
  `attack` is in `legal.GATED_COMMANDS`), `--attack-confirm` flag,
  and `attack_confirm=True` at the class level.
- Hard limits: columns 1-32, max_rows <= 100, max_bytes <= 65536.
- CLI: `janissary attack sqli-union <url> --param X --columns N
  --attack-confirm`.
- `tests/unit/test_sqli_union.py` — 25 tests, payload-aware mock.

Suite: 235 tests passing. Ruff clean.

---

## Legal framework — Terms of Use + acceptance gate (DONE)

- `LEGAL.md` — supplementary Terms of Use. Clauses: authorised use,
  indemnity, limitation of liability, export control, good-faith
  research, no warranty, governing law. Apache-2.0 remains the code
  licence; LEGAL.md supplements it. Governing law: Victoria,
  Australia.
- `src/janissary/legal.py` — versioned terms text, marker helpers
  (`~/.janissary/terms-accepted.json`), `require_acceptance()`.
- `src/janissary/cli.py` — gate in `main()`. Gated commands: scan,
  fingerprint, graphql, ws, admin, attack. New `janissary terms
  {show,status,accept}` subcommand.
- `README.md` — Authorised-Use block at the top.
- `tests/unit/test_legal.py` — 19 tests.

---

## P2.3 — Admin panel probe (DONE)

- `src/janissary/recon/admin.py` — `ADMIN_PATHS` (18 platforms),
  `AdminProbe`, `probe_admin`.
- `janissary admin <url>` CLI subcommand.
- `tests/unit/test_admin.py` — 13 tests.

## P2.2 — WebSocket scanner (DONE)

- `src/janissary/integrations/websocket.py` — async `scan`, sync
  `scan_sync`, `is_plaintext`, echo probe, CSWSH origin check.
- `janissary ws <url>` CLI subcommand.
- `tests/unit/test_websocket.py` — 13 tests, real in-process servers.

## P2.1 — GraphQL fuzzer (DONE)

- `src/janissary/integrations/graphql.py` — client, builders,
  `detect`, `enumerate_fields`, `depth_probe`, `alias_probe`,
  `fuzz_arguments`.
- `janissary graphql <url>` CLI subcommand.
- `tests/unit/test_graphql.py` — 25 tests.

## P1.4 — Platform fingerprint (DONE)

- `src/janissary/recon/fingerprint.py` — `Fingerprinter`,
  `fingerprint()`.
- `janissary fingerprint <url>` CLI subcommand.
- `tests/unit/test_fingerprint.py` — 15 tests.

## P1.3 — XML-RPC multicall harness (DONE)

- `src/janissary/integrations/xmlrpc.py` — encoder, decoder,
  `XmlRpcClient`, `detect`, `bruteforce_multicall`, `pingback_probe`.
- `tests/unit/test_xmlrpc.py` — 26 tests.

## P1.2 — WAF detector + adaptive pacer (DONE)

- `src/janissary/recon/waf.py` — `WAFDetector`, 10 vendor signatures.
- `src/janissary/recon/pacer.py` — `AdaptivePacer`, `PacerConfig`.
- Wired into `engine/scanner.py`; `--no-waf` flag.
- `tests/unit/test_waf.py` (10), `tests/unit/test_pacer.py` (9),
  `tests/integration/test_scanner_recon.py` (4).

---

## P3.2 - Nuclei runner (DONE)

- src/janissary/attack/nuclei.py provides NucleiRunner, which shells
  out to the nuclei binary, requests JSONL output, and parses each
  line into a NucleiFinding.
- parse_nuclei_line() handles blank lines, non-JSON, non-dict JSON,
  and objects without a template-id by returning None. It accepts
  both 'template-id' and 'templateID' spellings, and both list and
  comma-separated-string forms for tags and reference.
- Guard rails, three layers:
    1. attack_confirm=True required at construction.
    2. nuclei binary must resolve on PATH (NucleiNotFound otherwise).
    3. templates must be a non-empty list. The runner refuses to use
       nuclei's default template set.
- Exit-code handling: 0 clean, 1 findings (not an error), anything
  else marks the run aborted.
- Timeout is clamped to 1800s. Rate limit defaults to 50.
- CLI: janissary attack nuclei <url> --templates a,b --severity X
  --tags Y --attack-confirm.
- tests/unit/test_nuclei.py - 22 tests, subprocess.run mocked.

Suite: 257 tests passing. Ruff clean.

---

## P3.3 - Agent / FindingStore / PlatformKB (DONE)

Three new submodules in src/janissary/agent/.

finding_store.py:
- Finding dataclass, FindingStore class.
- Append-only, deduplicating (sha256 over
  target|category|finding_type|discriminator).
- Atomic saves: write to tmp, os.replace. Original untouched on crash.
- Load tolerates missing file, corrupt JSON, non-dict entries.
- Query helpers: by_target, by_severity, by_category, summary.

platform_kb.py:
- Surface dataclass, PLATFORMS table covering 11 platforms.
- surfaces_for(platform), modules_for(platform), plan_for(list).
- plan_for is stable and de-duplicated, ignoring unknown platforms.

agent.py:
- Agent orchestrator with AgentRun result type.
- Takes a fingerprinter callback; reads .cms and .waf.
- Runs adapters in plan order; a missing or raising adapter is
  skipped, never fatal.
- Optional allowed_platforms filter, max_modules cap.

adapters.py:
- Real-world adapters wrapping recon/admin, integrations/xmlrpc,
  integrations/graphql, recon/fingerprint.
- Kept in a separate module so the agent stays unit-testable.

CLI:
- janissary agent <url> --attack-confirm
- Flags: --store, --platforms, --timeout, --proxy, --export, --quiet.
- Persists findings to a JSON store, prints severity breakdown.

Tests:
- tests/unit/test_finding_store.py - 19
- tests/unit/test_platform_kb.py - 12
- tests/unit/test_agent.py - 15

Suite: 303 tests passing. Ruff clean. Phase 3 complete.

---

## SESSION HANDOFF

### 2026-10-09 — S10: three-run Track A closed, shim bypass shipped

**Headline: three-run F1 0.682 / P 1.000.** Amendment 9's FP fix (reflection
gate + PG db_error anchor) landed as expected: all FPs eliminated, recall
dropped by the mislabeled-TP count. New canonical 3-run table:

| run | dir                              | TP  | FP | FN  | P     | R     | F1    |
|-----|----------------------------------|-----|----|-----|-------|-------|-------|
| r1  | (handoff-referenced run)         | 732 | 0  | 683 | 1.000 | 0.517 | 0.682 |
| r2  | 20261001T170823Z-janissary-r1    | 732 | 0  | 683 | 1.000 | 0.517 | 0.682 |
| r3  | 20261009T100138Z-janissary-r3    | 733 | 0  | 682 | 1.000 | 0.518 | 0.682 |

Headline: **P = 1.000 +/- 0.000, R = 0.518 +/- 0.001, F1 = 0.682 +/- 0.000.**
Pre-registered F1 target (>= 0.70) missed by 0.018; P target (>= 0.90)
exceeded by 0.10. Recall is the sole remaining gap.

**The 0.682 is 86 TP below the old 0.724 headline (e5c95f1).** The FP fix
took P 0.967 -> 1.000 and cost R 0.578 -> 0.517. The 86 lost TP paths are
the findings that were scoring as TPs but were not real detections of their
stated class (reflection-path sqli/traversal on xss echo paths, and the 249
db_error mislabels whose path-based score counted them as TPs). Those 86 are
the concrete first target for recall recovery.

**Chunked-vs-single-process: -0.003 F1.** A parallel 4-chunk run (merged-r3)
scored F1 0.679 vs 0.682 for single-process. Chunks are disjoint (1077
lines, 1077 unique, zero overlap), merge is correct, but the process-boundary
effect costs ~4 TPs. Do not use chunked runs for headline numbers.

#### Failure modes catalogued this session

1. **Shim flake — FIXED (b651c29).** The pip-generated launcher stub
   `.venv\Scripts\janissary.exe` crashes with WinError 5 or 0xC0000005
   (STATUS_ACCESS_VIOLATION) at ~7% per spawn, measured by a 30-iteration
   loop test (2/30 fails). At 2740 cases that is ~180 expected crashes per
   full run. Two runs died mid-corpus (20261004T070653Z, 20261004T214325Z),
   both with the interrupted manifest signature (no exit_code, no
   finished_at). Fix: opt-in env flag JANISSARY_USE_MODULE=1 swaps the shim
   for `python -m janissary` via sys.executable. 0/30 fails with the module
   path.

2. **Docker Desktop auto-shutdown — pre-flight mandatory.** Container
   exits with `Exited (255)` on host sleep or Docker Desktop shutdown. On
   resume the target is dead and the runner completes cleanly with zero
   findings and no error (see 20261004T214325Z). Before any run:
   `docker ps` must show Up, and `Invoke-WebRequest
   http://127.0.0.1:8080/benchmark/` must return 200. Consider
   `docker run --restart unless-stopped` before the next long session.

3. **Pytest PermissionError under elevated shell.** 40 tests in
   `tests/unit/test_legal.py` error with `[WinError 5] Access is denied:
   \\?\...\.pytest_tmp` when run from an admin terminal. Pre-existing,
   environmental. Run pytest from a non-admin shell.

#### Session takeaways

- **Precision we didn't need.** The FP fix gained 0.033 precision against
  a 0.90 target already at 0.967, and cost 0.061 recall, netting -0.042 F1
  and pushing the headline below target. At this margin, recall is worth
  strictly more per unit than precision. Future precision work should
  require an explicit recall justification.

- **"86 lost TP paths" was exact.** It is the measured delta between the
  e5c95f1 3-run (0.724, ~818 TP mean) and now (0.682, 732-733 TP). The
  full FN pool is 682; the recoverable-with-known-fix subset is 86.

- **Enumerate, don't recall — run dirs too.** S9's handoff named the
  run dir `20261001T170823Z`; on disk it is
  `20261001T170823Z-janissary-r1` (make_run_dir suffix). Cost one wasted
  scorer invocation. Copy run-dir names verbatim from `Get-ChildItem`.

#### Commits this session

- `b651c29` BENCHMARK: add JANISSARY_USE_MODULE to bypass flaky shim
  (also gitignores `benchmark/track_a/_chunks/`).
- Pushed with the 4 prior unpushed commits: `294acbd`, `2ce4fc8`,
  `ac2ae1b`, `8a65195`.

#### Open at handoff

1. **Recall recovery** on the 682 FN; start with the 86 recoverable paths
   (git history of `f37df99`, `e5c95f1`, `8a65195`).
2. **Structural throttle fix** (`--library-mode`, Phase 4.5) — unchanged
   from S9.
3. **`docs/launch-plan.md` numbers stale** — still says 11/2 SQLi.
4. **CI gaps** — mypy / bandit / pip-audit are local-only.
5. **PyPI / launch** — browser-blocked, unchanged.

---

### 2026-09-27 (late) — baseline + pacer fixes, CI verified

Two bugs from the previous handoff are fixed, tested, and pushed. CI is green
on `1a32eb0` across py3.10-3.14. This is the first verified CI run since
`8ced0f4`.

#### Commits this session

- `03adc5b` fix(scanner): sample baseline with the URL's existing param value
  + 5 tests in `tests/unit/test_scanner_baseline.py`, one xfail (see below).
  Traversal bench: 12/1 (no traversal) -> 36/7.
- `97313f4` docs(workflow): handoff for the baseline fix (superseded by this).
- `33f3877` fix(pacer): stop backing off on server-side 5xx + 3 tests.
- `1a32eb0` chore: ruff gate fix (trailing newline, deprecated ANN101/ANN102).

#### Closed from previous handoff

- **Traversal produced zero findings.** Real scanner bug: `collect_baseline`
  rotated through `["1","test","index","home","default"]`, one value per
  sample. On `/traversal` all five benign values 500'd, so `modal_status`
  became 500 and `is_stable_body` became False -- both the status and length
  gates bailed before any payload was sent. Now reads the target URL's
  existing value for `param` and replays it N times. Falls back to `"1"` only
  when the URL has no value for the param. `keep_blank_values=True` preserves
  the `?q=` / `?q` distinction.
- **Pacer backs off to 30s on app-level 500s.** `SOFT_ERROR_STATUSES =
  {500, 502, 504}` called `_backoff()` on any of them. On targets that 500
  for unknown input, delay doubled 0.5 -> 1.0 -> 2.0 -> ... -> 30.0. Removed
  the set and the branch. 5xx still resets `clean_streak` (cannot count
  toward recovery) but no longer touches delay. Block statuses unchanged:
  `{403, 406, 418, 429, 501, 503}`.
- **~2.0s "localhost floor."** Not a separate bug. It was the pacer's
  doubling sequence mid-escalation. Closed with the pacer fix.
- **CI verified on HEAD.** Five matrix jobs (py3.10-3.14) green on `1a32eb0`.

#### Still open

- **Structural misattribution -- three instances, all closed.** A finding
  may carry a category only if the response contains a category-specific
  artifact. Generic facts about an endpoint ("it echoes," "the status
  changed," "the length moved," "the time moved") are not category-specific
  and must not be stamped with the probe's category. Three leaks of this
  class have been found and fixed:

  1. `_check_status` / `_check_length` emitted category-labeled findings on
     any target that 500s for unknown input. Closed by the scanner's
     `CORROBORATOR_ONLY_TYPES` filter. Regression test:
     `test_500_on_unknown_input_does_not_misattribute_categories`.

  2. `payload_reflected` on non-xss probes stamped the probe's category on
     any echoing endpoint. Closed by a scanner-side gate; xss still emits
     `reflected_xss` because there a raw echo *is* the bug. Regression
     tests: `test_scan_suppresses_sqli_reflection_on_echoing_target` and
     `test_scan_keeps_xss_reflection_on_echoing_target`.

  3. The postgresql `db_error` pattern `unterminated quoted string` matched
     bash's `sh: 1: Syntax error: Unterminated quoted string`, mislabeling
     249 command-injection findings as sqli. Anchored to `at or near`, which
     real PG errors carry and shell errors do not.

  Not yet enforced structurally: the analyzer still returns category-free
  evidence and the scanner still stamps the probe's category at emit time.
  The refactor -- evidence self-classifies, scanner can only emit a category
  the evidence justifies -- is scheduled post-launch.

- **Enumerate, don't recall.** Identifiers (amendment numbers, commit
  hashes, case counts, line numbers) must be read from the artifact,
  never asserted from memory. If a document uses a numbering scheme,
  list every existing value first, then compute the next one. The same
  discipline the tool applies to categories -- no claim without the
  artifact to back it -- applies to the docs and to this file.
- **`docs/launch-plan.md` numbers are STALE.** Says "23 findings / 3 groups"
  and "1 group with 8 evidence rows." Actual SQLi = 11/2 with 10 evidence
  rows in F-001. Update AFTER the misattribution is settled, not before.
- **CI only runs ruff + pytest.** mypy, bandit, pip-audit are local-only
  despite WORKFLOW.md claiming all five gates green. Add them to
  `.github/workflows/ci.yml` as a separate work item.
- **PyPI / launch.** Browser-blocked. TestPyPI + PyPI accounts, 2FA, API
  tokens, upload, fresh-venv verify, README install-line revert.
- **Domains.** Register hetaireia.io first, then hetaireia.com.au (needs ABN
  or ACN).

#### Local dev note (Windows only)

Python 3.14.7 on Windows hard-crashes pytest with `0xC0000005` (access
violation) before any test runs. Not reproducible on Linux; CI is unaffected.
Workaround for local dev only: run `pytest -p no:faulthandler ...`. Do NOT
add `-p no:faulthandler` to `pyproject.toml` -- that would disable fault
handling for all contributors on all platforms, including Linux CI, to paper
over a Windows-only interpreter bug.

#### To resume

1. `git log --oneline -6` -- confirm `1a32eb0` is HEAD and CI is green.
2. Structural misattribution: three instances closed (see "Still open"
   above). Post-launch work: enforce it structurally so the scanner can
   only emit a category the evidence justifies. Read the git history of
   this file for the original F-002 through F-007 analysis.
3. Update `docs/launch-plan.md` numbers once (2) is settled.
4. Add mypy/bandit/pip-audit to CI as a separate commit.
5. PyPI/launch (browser-blocked, unchanged).

## Current step
Phase 4 - Launch.

COMPLETE:
- M1-M3 shipped, 314 tests pass, CI green.
- M4 blog + demo GIF, M5 README polish + pre-flight verification.
- README/blog sample synced to bench-sqli-1.json (11 findings / 2 groups, port 5001, /sqli).
- Repo moved to github.com/Hetaireia/janissary (org created 2026-09-27).
- History rewritten: ascension doc and tracker removed from all commits, force-pushed.
- pyproject metadata fixed: URLs to Hetaireia, author Hetaireia, SPDX license.
- Build artifacts clean: janissary-7.1.0.tar.gz + wheel, twine check PASSED.
- Bandit gate closed: XXE fix via defusedxml, 0 Medium / 0 High. All five gates green (ruff, mypy, pytest, bandit, pip-audit).
- v7.1.0 tagged (annotated) and pushed. CI green on a688bec across py3.10-3.14.

BLOCKED ON (browser, your end):
- TestPyPI + PyPI accounts, 2FA, API tokens.
- Then upload to TestPyPI, verify fresh-venv install, upload to PyPI.
- Then revert README install line from git clone to pip install janissary.

PENDING (browser):
- Register hetaireia.io first, then hetaireia.com.au (needs ABN or ACN).

THEN:
- M6 launch posts per docs/launch-plan.md and reference doc. Tuesday or Wednesday 08:00 ET.

## Post-launch backlog

Candidates for the first feature after M4/M6/M7 ship. Final pick
should be driven by user feedback, not decided now.

Tier 1 - adoption blockers

- Authenticated scanning. Sessions, token refresh, login flow.
  Reuse requests.Session. New flag group: --login-url, --login-data,
  --auth-header. Effort: medium. Impact: very high. Currently the
  single biggest gap vs top-20 tools.

- OpenAPI / Swagger ingestion. Parse spec, enumerate endpoints and
  params, drive Scanner. Handles 2.0, 3.0, 3.1, $ref resolution.
  Effort: medium (2-3x P3.2). Impact: high for API-first targets.

- Crawler / endpoint discovery. Same-origin links, forms,
  robots.txt, sitemap.xml. Static HTML first; headless browser
  later if warranted. Effort: high. Impact: very high, but changes
  the tool's character from fast-targeted to slower-thorough.

Tier 2 - high value

- Out-of-band (OAST) detection. Callback server for blind SSRF,
  XXE, blind cmdi. Effort: high. Impact: medium-high.

- Compliance report templates (PCI, HIPAA). PDF rendering of
  existing findings. Effort: low-medium. Impact: matters for the
  Phase 6 enterprise sale.

- CI/CD native action. Publish action.yml, document the recipe.
  Effort: low. Impact: medium.

Tier 3 - differentiators, not blockers

- Intercepting proxy mode. Large; changes the tool's character.
  Not recommended.

- IAST integration. Requires agent on target. Out of scope.

- SPA crawling via Playwright. Playwright already an optional dep.
  Dramatically slower; conflicts with the speed positioning.

Sequencing rule: ship M4, M6, M7 first. Build whichever Tier 1 item
users ask for most. If the answer is unclear after launch, build
authenticated scanning - it is the safest bet.

---

## Git status note

HEAD `b651c29`, working tree clean, `origin/main` up to date. Five
commits pushed 2026-10-09 (S10). All Track A infrastructure work
committed; run artifacts remain gitignored under
`benchmark/track-a/runs/`.

