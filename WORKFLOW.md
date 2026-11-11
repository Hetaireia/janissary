# JANISSARY — Port Workflow Tracker
## STATUS: Track A DAST-applicable F1 0.921 (P 1.000, R 0.854, TP 987, FN 169) -- reproduces Amendment 21 and the 7.5.0 baseline artefact; --retry-zero in runner.py produces these numbers in one command at full 2740-case scale. Full-corpus F1 0.822. pathtraver 0.049-0.308, documented as target-capped and confirmed by zero recovery on the FN-retry pass. Amendment 20 recorded TP 984 / F1 0.920 before Amendment 21 closed a 3-case gap on 2026-10-25; STATUS line had been stuck at the pre-Amendment-21 figure. ~16% of DAST-applicable FN are batch-context-sensitive. wrong_family=0; out_of_scope=735 (735 ssrf findings the benchmark cannot score — it has no ssrf category; the 100 sqli_blind findings originally counted as wrong_family were a scorer bug, FAMILY_OF lacked sqli_blind -> sqli mapping, fixed 2026-11-10 with no change to F1 0.921). ADR-030 Stage 2 (ref resolution) shipped 2026-11-11: local and external ref chains for path items and parameters, cycle and depth detection; 40 refs+parser+fixtures+differential+kube+servers+dispatch tests and 1032 tests/unit pass in the WSL venv. ADR-030 Stage 4 (server URL) shipped 2026-11-11: 3.0 servers[0].url template substitution; 2.0 schemes+host+basePath; Operation gains base_url. ADR-030 Stage 5 (dispatch layer) shipped 2026-11-11: Operation gains parameter_locations; build_scan_targets emits one target per distinct parameter location; end-to-end operation scanning (the Scanner loop) is Stage 6. ADR-030 Stage 3 (Swagger 2.0) shipped 2026-11-11: version gate accepts swagger 2.0; petstore-2.0 fixture flows through oracle and parameter-name differential; Kubernetes swagger.json (4.3 MB, 1172 operations) parses in 0.27s at 17.4 MB peak. Ascension roadmap and dashboard are local-only as of 2026-11-11: renders/ is untracked and gitignored, generator pipeline (tools/ascension.py, ascension_state.json, dashboard-template.html, extract-template.py) deleted from repo. Session close 2026-11-11 (late): dashboard corrected (M4 proposed '?' -> 'unscheduled'; ADR-030 M61-M66 appended, all delivered 11-NOV-2026; 41/66 = 62.12% work complete; time-elapsed fallback 3.28% -> 6.29%). M4 verified complete in code: VerificationEngine at verification/engine.py:64 (20 _ENGINE.verify sites, 0 direct VerifiedFinding constructions in scanner.py), FN-12 at verification/confirmers.py:148 + detection/analyzer.py:693, scan_incomplete at cli.py:54/121; LIMITATIONS.md:35 reads FIXED 2026-11-01. JANISSARY-ASCENSION.md:90-106 citations converted to file:line + post-rewrite SHAs (15 of 15 mapped; ef93cf9 -> faabefa and 2d7fb1e -> b7e2c9d recovered from the 2026-11-10 mirror); duplicate Session 2026-11-08 block removed (184 -> 170, now 172 after the citation note). JANISSARY_ASCENSION.md PART FOUR amended to reference the dashboard instead of the retired generator; PART FOUR-B brand spec untouched. WORKFLOW.md rules 5-7 pushed (027195a). Tag divergence RESOLVED 2026-11-11: all 18 local tags force-pushed to origin; v7.11.1 = 3ade65f/ca20c2c on both sides; pre-rewrite objects preserved in /mnt/c/Users/M5 E60/janissary-backup-20261110.git. tests/test_version_tag_consistency.py passes (1 passed) so the divergence now has a watchdog. M4 re-run 2026-11-11: tests/unit/test_verification_engine.py 16 passed, tests/unit/test_scan_incomplete.py 6 passed, full tests/unit 1032 passed / 1 skipped; the unit skip is tests/unit/test_interactsh.py (cryptography not installed in the WSL venv); tests/regression/test_juice_shop_precision.py skips by design unless JANISSARY_INTEGRATION=1. ADR-030 Stage 5 body-target defect found and fixed: dispatch emitted inject_in='json-body' with json_template=None, which Scanner.__init__ rejects; body targets now emit 'auto' with an empty params list and a limitation note. New tests/unit/test_openapi_dispatch_consumption.py constructs a Scanner from every emitted target type, covering the join that dispatch.py's no-scanner-import design left untested. tests/unit: 1039 passed, 1 skipped. Stage 6 effort revised to 7-9h.
## NEXT: (1) BL-2 CSTI detection -- design corrected in DETECTION-BACKLOG (new oracle, not payload additions; needs ADR before code). (2) BL-5 OpenAPI import -- ADR-030 Stage 5 dispatch layer shipped (7597258); next is Stage 6, CLI wiring and per-operation scan loop (--openapi flag, --dry-run, one Scanner per build_scan_targets output; estimate revised upward from the ADR 2-3h since the transformation shipped but not its consumer); kube torture test has no prance differential (documented in test docstring). (3) Windows git broken (corrupt GCM config); all pushes via wsl -d Ubuntu with --no-verify until repaired. (4) Dashboard visual verification -- brand palette and SVG banner applied but never opened in a browser; PART FOUR-B of JANISSARY_ASCENSION.md is the written brand spec.
## CONTAINER: Track A target is janissary/owasp-benchmark:20cbf3d-ldapfix (LDAP + HSQLDB entrypoint fixes committed). Entrypoint version-controlled at benchmark/track_a/docker/entrypoint.sh. See benchmark/track_a/docker/README.md.
## LAST COMPLETED: WORKFLOW.md rules 5-7 added and pushed (027195a, 2026-11-11); the same session corrected dashboard M4 proposed date to 'unscheduled', appended ADR-030 M61-M66 (41/66 = 62.12%), verified M4 complete in code, converted JANISSARY-ASCENSION.md:90-106 citations to file:line with remapped SHAs (13 of 15), removed the duplicate Session 2026-11-08 block (184 -> 170 lines), and amended JANISSARY_ASCENSION.md PART FOUR to point at the dashboard; note: an earlier wrong-grep basis briefly deleted JANISSARY_ASCENSION.md, restored from backup with 197 lines verified. Prior: ADR-030 Stage 5 dispatch layer shipped (2026-11-11). 7597258: Operation gains parameter_locations, populated from the in key of each resolved parameter; unsupported locations (2.0 formData) append a parser note and are excluded from dispatch. New src/janissary/importers/dispatch.py with build_scan_targets(op): one target per distinct location, because Scanner.inject_in is a single mode per instance. Mode map: path->path, query->param-name, header->header, cookie->cookie, body->json-body. Parameterless operations yield one auto target. No scanner import, no network; pure transformation. 6 new tests in test_openapi_dispatch.py; 40 OpenAPI tests and 1032 tests/unit pass. End-to-end operation scanning, the loop that constructs N Scanners from these targets, is Stage 6 and is not part of Stage 5. Prior: ADR-030 Stage 4 shipped (2026-11-11). 2ad849b: Operation gains base_url field; _resolve_base_url dispatches on swagger 2.0 vs openapi 3.0. 3.0: servers[0].url with {var} substitution from variables[var].default, per-operation servers overrides out of scope. 2.0: schemes[0] + host + basePath, https default when schemes absent. Unresolvable variable appends a note and leaves base_url empty rather than emitting SkipRecords, because server resolution is spec-level and skipping would zero out every operation; this deviates from the ADR wording and the ADR is amended accordingly. 4 new tests in test_openapi_servers.py; 34 OpenAPI tests pass; 1012 tests/unit unchanged. Prior: ADR-030 Stage 3 shipped (2026-11-11). 9a997c0: version gate accepts swagger 2.0 alongside openapi 3.0.x; spec_version reports swagger X.Y. 38624fe: petstore-2.0 fixture (13.8 KB minified, 14 paths, 20 operations) plus expected counts from prance; oracle relaxed to accept both versions. 7cfc8ad: RefResolver fast path for nodes without ref plus _resolved_path memoisation. Fixes pathological Path.resolve calls against /mnt/c 9p mount: kube parse minutes to 0.27s. 3e497ed: Kubernetes torture test (1172 operations, 0 skipped, 0 notes, 17.4 MB peak vs 100 MB ceiling, 0.27s), tools/fetch_kube_spec.py, large-fixture gitignore rule. 30 OpenAPI tests pass; 1012 tests/unit unchanged. Prance cannot parse kube (treats every ref key as URL; kube uses ref as JSON Schema property name) so no differential for that fixture. Prior: Ascension local-only + dashboard branding (2026-11-11). 46c7dda: dashboard timestamp refreshed, time-bar static fallback corrected, false generator-provenance footer replaced. e545af0: generator pipeline retired (ascension.py, ascension_state.json, dashboard-template.html, extract-template.py, check-ascension.ps1; 1044 lines). 1407a45: brand palette (Carbon Black #0B0B0F, Aurum Gold #D4AF37, Steel Grey #4B5057, Platinum #EBEBEB) applied to :root; green/red retained as functional signals. c48519c: text h1 replaced by inline SVG banner (emblem + JANISSARY + SIGNAL OVER NOISE); Montserrat loaded; ASCENSION kept as small artifact-name label; subtitle preserved. 9366779: renders/ untracked (git rm --cached), renders/ ignore rule restored under its orphaned comment at .gitignore:153. Prior: ADR-030 Stage 2 shipped (2026-11-11). 0144ecc: src/janissary/importers/refs.py RefResolver -- local and external ref chains, cycle detection, depth limit 10, external file cache. openapi.py rewired: path items resolved first with SkipRecord on RefError; parameter entries resolved with notes on failure. d6296c0: external-ref fixture pair under refs/ (dodges non-recursive oracle glob), expected count from prance, tools/validate_openapi_fixture.py. Two silent-drop classes closed: path-item ref vanishing with no SkipRecord; parameter ref name lost while count stayed green. 20 refs+parser+fixtures tests pass; 1012 tests/unit pass in WSL venv /home/oraclemode/janissary-venv (Python 3.14.4, pytest 9.2.0). Kube torture test deferred to Stage 3 (Swagger 2.0; Stage 2 _validate is 3.0-only). 1138 Windows baseline still NOT re-verified in WSL scope. Prior: ADR-030 Stage 1 shipped (2026-11-10). d1c5e2a: fixtures petstore 3.0 and uspto 3.0 with committed expected counts, dev deps prance>=23.6 and openapi-spec-validator>=0.7, differential self check test. 3c9eae7: parser skeleton at src/janissary/importers/openapi.py with the silent drop invariant (imported + skipped equals total) and 11 parser tests. 15 tests pass in the new WSL venv /home/oraclemode/janissary-venv (Python 3.14.4, pytest 9.2.0). Two bugs found by review, both fixed: misplaced closing bracket in the pyproject dev list; Path("__file__") string literal in the fixtures test, proved by running that test from /tmp. The 1138 test baseline belongs to the Windows .venv and was NOT re-verified in the WSL venv. Earlier this session 818876a removed two stale NEXT items (docs cross reference, benchmark artefact verification).
Prior-1: Public/private split + history rewrite (2026-11-10). Removed docs/FUTURE-STATE-PLAN.md, docs/ROADMAP.md, docs/launch-plan.md, JANISSARY-ASCENSION.md from all public history via git-filter-repo and force-push (old HEAD 67ee17d -> new HEAD ade51cc; every SHA rewritten). Pre-rewrite mirror at /mnt/c/Users/M5 E60/janissary-backup-20261110.git (14 MB) for rollback. Local-only copies restored to /mnt/c/Users/M5 E60/local-only-backup/: 4 strategic files + strategy/ dir + janissary_assessment.txt. .gitignore hardened with explicit rules (lines 166-173) verified via git check-ignore. README references to removed files rewritten to describe private/public split. All 1138 tests still pass on rewritten tree. Three GitHub tokens leaked into transcript during session; all revoked. Pre-push hook still requires --no-verify (pre-commit not on non-interactive bash PATH).
Prior-2: --retry-zero verified at full corpus scale. 2740 cases, 227 in second pass, 2073 findings merged, scoring clean. DAST-applicable F1 0.921 (P 1.000, R 0.854, TP 987, FP 0, FN 169). Matches artifacts/7.5.0-baseline/summary/run-1-recovery-score.txt exactly: all 33 per-category rows identical, all four pathtraver rows identical at 0.049/0.154/0.160/0.308. STATUS line claims TP 984 / FN 172 / F1 0.920 -- 3-case delta against both this run and the artefact. Version drift, source not identified; follow-up task. --retry-zero is therefore proven as the Amendment 20 protocol at full scale, reproducible in one command, no external script.
Prior-3: pathtraver doc precision audit (NEXT item 1 closed). Verified docs/pathtraver.md against committed artefacts; corrected three claims: (a) "all 72 pathtraver cases" was unsupported -- case_vectors.csv marks 133 vulnerable; now sample-of-72 language plus a provenance note citing 133 cases, TP=10, recall 0.075, 123 FN. (b) "excluded F1 would be above 0.99" was arithmetically wrong; corrected to 0.976 (TP 984, FP 0, FN 49). (c) 4/22/46 shape split preserved as hand-sample observation, not a census. Core thesis (differential oracle, target-capped, zero recovery) verified and stands.
Prior-4: scan --url ergonomics decision (NEXT item 1 closed). Evaluated three options; chose B: keep the existing runtime guard cluster ([!] + exit 64) rather than argparse required=True, because promoting --url would break `janissary scan --version` (short-circuited at cli.py:289 before the guard) and would be inconsistent with the sibling guards --sessions, --idor, --ws. Enriched the message with a concrete example: "[!] scan requires --url (e.g. -u http://localhost:8080)". Verified: hint prints, exit 64 preserved, scan --version still returns "janissary 7.11.1".
Prior-5: --retry-zero (alias --second-pass) scripted into benchmark/track_a/runner.py, reproducing the Amendment 20 FN-retry protocol in a single invocation; unit-tested with a fake driver (fired-set extraction, zero-finding subset selection, findings merge, no-op path). End-to-end run against the Track A container still pending (Docker Desktop not running).
Prior: Amendment 20. FN recovery run. 204 DAST-applicable FN re-scanned in isolation; 32 recovered; two identical runs agreed on 31/32 cases. DAST-applicable F1 0.903 -> 0.920. pathtraver recovered 0, confirming target-capped hypothesis. Batch-context effect quantified at ~16% of FN. See Amendment 20.
Last updated: 2026-11-11 late (session close: dashboard M4 -> unscheduled, ADR-030 M61-M66 appended, 41/66 = 62.12%; M4 verified complete in code; JANISSARY-ASCENSION.md citations -> file:line, dedup 184 -> 170; JANISSARY_ASCENSION.md PART FOUR amended; WORKFLOW.md rules 5-7 at 027195a; 18 tags force-pushed; M4 re-run green: 1032 passed, 1 skipped)
Project root: C:\Users\M5 E60\janissary-project\janissary

---

## How to resume after losing context
**Mandatory reads before acting:** run `ls *.md` at repo root and read any file matching `PASTE|HANDOVER|FAILURE|HAZARD|RESUME`. These contain channel and state lessons that are not repeated in the session handover.

**Two WORKFLOW.md files:** status block (STATUS / NEXT / LAST COMPLETED) is root `WORKFLOW.md`. Process patterns are `docs/WORKFLOW.md`. The handover uses the bare name for both — verify which one before editing.

**Channel policy:** WSL bash for git and pytest. Single-line PowerShell for structural ops. Anchored Python scripts with `NOT FOUND` guards for multi-line text edits. Never multi-line here-strings. Never paste Python into the PowerShell prompt.

**Handovers:** trust the narrative, verify the paths. Descriptions of what happened transfer; locations on disk need checking.

**Step 0 — read `docs/WORKFLOW.md` first.** It records eight process patterns learned from prior measurement work (verify before claiming, file-based execution for complex commands, explicit-path output capture, cleanup-before-port-check, three-outcome distinction, forward-only corrections, shape checks, write-down-when-wrong). Violating those patterns produced two incidents in the 2026-11-10 session alone. Read them before issuing any command.

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
5. **Verify before claiming.** Never state a file's content, a line number, a count, a hash, or a test result without a command output from this session showing it. If it cannot be verified, the claim says "unverified".
6. **Predictions are not evidence.** Label a prediction as a prediction. When a prediction and an output disagree, the output is truth and the prediction is corrected in the next message, never silently dropped.
7. **Destructive edits:** back up first, assert the anchor before writing, assert the content after writing, read the diff. A guard that fires after a write is a guard that failed.

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

HEAD f10fcdc, working tree clean, origin/main up to date. Twelve commits pushed 2026-11-11. All Track A infrastructure work committed; run artifacts remain gitignored under benchmark/track-a/runs/.

Remote refs as of 2026-11-11: preserve-7.5.0-c8c0030 is a remote-only branch (its object is not present in this full clone) from the 7.5.0 era, almost certainly the pre-rewrite safety bookmark from 2026-11-10. refs/notes/commits points at commit 7384b7f, present locally as a commit object. Neither is touched or blocking. Duplicate tag naming observed but not fixed: 7.3.0 and v7.3.0 point at different objects for what should be one release; same for 7.4.0 versus v7.4.0-benchmark. Windows git still broken (corrupt GCM config); all pushes via wsl -d Ubuntu with --no-verify until repaired.

## Session hazards

- The unqualified git rm aborts atomically on any pathspec that is not tracked (observed 2026-11-11 with scripts/check-ascension.ps1). Split tracked vs untracked deletions into git rm and rm respectively, or the whole command is a no-op. Also: gits index refresh against /mnt/c takes 6-8 seconds on this repo; not a hang.

- Local JANISSARY_ASCENSION.md PART FOUR still instructs running python tools/ascension.py (complete/reset/list). That tool was deleted 2026-11-11. The roadmap file is local-only and gitignored, so this is a local documentation defect to fix or accept; it does not affect the public repo.

See PASTE-FAILURES-2026-11-08.md. The paste channel strips the dollar sign, double underscore, backtick, and double asterisk, and converts hyphens to Unicode minus. Multi line pastes are destructive: they have created nested git clones and re-pointed the global editable install twice. Single line commands only. Test the channel at session start with Get-Date and Write-Output abc.
