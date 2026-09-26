# JANISSARY — Port Workflow Tracker
## STATUS: PHASE 4 COMPLETE - READY TO LAUNCH
## NEXT: Execute docs/launch-plan.md (Show HN, r/netsec, blog cross-post)
## LAST COMPLETED: P4.4 — Launch plan, blog, demo GIF, README proof block (314 tests pass)

Last updated: 2026-09-26
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

## Current step

Phase 4 - Launch.

NEXT: M4 - Technical blog post + demo video.

After that:
- M5 README polish (use the positioning statement from
  JANISSARY_ASCENSION.md).
- M6 Launch posts: HN (Show HN), r/netsec, r/AskNetsec,
  r/blueteamsec, OWASP Slack, awesome-security lists.
- M7 Claim listings: G2, Capterra, PeerSpot, AlternativeTo.

The detailed plan for each milestone is in JANISSARY_ASCENSION.md.
Track progress with:

    python tools/ascension.py
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

All work through P3.1 is committed and pushed. The legal framework,
the ASCENSION roadmap, the countdown tracker, and P3.1 are on GitHub
at the latest `main`.

---

## Vision

See `JANISSARY_ASCENSION.md` for the full roadmap to top-20 DAST
ranking, the competitive positioning, and the 12-month timeline.

Track progress:

    python tools/ascension.py
