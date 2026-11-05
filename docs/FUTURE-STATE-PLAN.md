# JANISSARY — Future State Implementation Plan

**Document status:** Approved (2026-11-04)
**Prepared for:** Hetaireia
**Companion to:** Uploaded 4-phase roadmap and code artifacts
**Purpose:** Translate the uploaded ambition into a plan that survives contact with reality

This document is the strategic core adopted after reviewing the uploaded 4-phase roadmap. It supersedes the "unresolved" status in `docs/PHASE-6-PLAN.md` and maps to milestone series M36a–M48 in `tools/ascension_state.json`.

---

## Executive Summary

The uploaded roadmap proposed four things in sequence over 12 months:

1. **Legal reframe** — Apache-2.0 -> AGPLv3, CLA, restructure into core/ + modules/heuristic/
2. **Dual-track engine** — Track A (deterministic) and Track B (heuristic) with schemas, confidence clamping, suppression
3. **Discovery expansion** — headless Playwright crawler + stateful API chain tracking
4. **Commercial platform** — FastAPI + Redis + Postgres + React dashboard, multi-tenant SaaS

**Assessment:**
- Engineering ideas in Phases 1-2 are sound and already 60% built
- Commercial moves in Phases 3-4 are premature by at least 12 months
- Legal moves are the right instinct at the wrong time, with the wrong mechanism
- Competitive-ranking claims are fabricated and cannot ship

**Recommendation:** Re-sequenced version that keeps the ambition but inserts gates where past ventures failed.

- **Keep and finish:** dual-track formalization (extend the existing unproven architecture - don't rewrite it)
- **Keep and defer:** tri-session auth (needs ADR-010 revision, then ~2 weeks of code)
- **Restructure:** license change as ADR + 90-day notice, not a script
- **Defer by 12 months:** proprietary crawler, SaaS platform, React dashboard, Redis workers
- **Reject outright:** fake competitive rankings, hardcoded passwords, sys.exit at import in libraries

The gates between phases are the mechanism preventing the "went too fast" failure mode.

---

## Part 1 — Assessment of the Uploaded Plan

### What's genuinely strong

| Element | Why it works |
|---|---|
| Dual-track concept | Already the architecture under different names. `attack` modules discover, `_ENGINE.verify()` decides. |
| Confidence clamping below 1.000 | Correct mechanism. Prevents heuristic candidates from masquerading as verified findings. |
| Track A hit suppresses Track B for that payload | Correct rule. Matches ADR-001 (single emitter). |
| Triage queue as separate output stream | Aligns with M16 unproven marker. Extends to SARIF secondary run. |
| WAF test harness | Mirrors existing docker-compose.waf.yml from M13. |
| HEURISTIC_CANDIDATE as distinct severity | Right way to preserve "1.000 verified" without lying about "0 FP total." |

### What's risky as written

| Element | Risk | Better approach |
|---|---|---|
| Apache-2.0 -> AGPLv3 script | Retroactive license change requires contributor consent. AGPL banned by many enterprises. | ADR-driven decision, 90-day notice, only if business reason emerges. Hybrid: Apache core + proprietary SaaS wrapper. |
| CLA before contributors | Building CLA infrastructure for nonexistent contributor base signals "not ready." | Defer until first external PR. Use DCO as interim. |
| Directory restructure | Breaks every import, every test. | Additive: `src/janissary/heuristic/` as sibling to `detection/`. |
| `scan.py` as entry point | Breaks 856 tests, every invocation. | Additive: `run_scan()` as function called by `cmd_scan`. |
| Pydantic as new core dependency | Codebase is dataclass-based. | ADR-worthy. Evaluate before deciding. |
| Proprietary crawler | Legal ambiguity. Splits community. | Open crawler, proprietary platform. Split at dashboard/API/RBAC. |

### What's aspirationally false

- "Bug bounty ranking 16th -> 2nd" — no such ranking exists. Delete.
- "Enterprise platform ranking 20th -> 5th" — same. Delete.
- "1.000 Gated Balance" — only achievable if heuristic candidates never ship as VerifiedFinding. Rewrite as: "1.000 precision on VerifiedFinding; heuristic candidates tracked separately."
- "Memory & CPU Footprint: Low -> High" — customer objection, not achievement. Rewrite as cost to minimize.
- Hardcoded Postgres password in `docker-compose.prod.yml` — never commit. Use env vars.
- `sys.exit(1)` at import in `queue_db.py` — breaks pytest/linters. Raise from explicit init function.

---

## Part 2 — Five Strategic Decisions (Approved)

### Decision 1: License model — D (Hybrid)

**Approved:** Apache core + proprietary SaaS wrapper. No license change. The wrapper is a separate product.

**Why:** AGPL is a procurement blocker for the enterprise customers you'd sell to. BUSL fails the same legal gates with added "not really open source" branding. Keep Apache-2.0 for the core; the commercial layer (dashboard, SSO, RBAC, audit, multi-tenancy) is separate proprietary code that talks to the core over a defined interface.

**Trigger for revisiting:** 100+ stars, 5+ outside contributors, and a named enterprise interested in managed hosting.

### Decision 2: Crawler placement — C now, B later

**Approved:** Open crawler, delay integration.

Build `janissary-crawl` as a standalone open-source tool that emits a parameter map file. Users pipe into `janissary scan` manually or use standalone. Integration code lands only after proving demand.

### Decision 3: SaaS timing — C initially

**Approved:** Never build SaaS initially. Publish hosted CLI as paid wrapper if demand emerges.

**Trigger for revisiting:** 5,000+ monthly active CLI users, or 3 named enterprise LOIs.

### Decision 4: Engine naming — B

**Approved:** "Verified Engine" (Track A internally) and "Discovery Engine" (Track B internally).

User-facing vocabulary: verified findings vs discovery candidates. Internal ADR/code vocabulary: Track A / Track B.

### Decision 5: Commercial split — B immediately, A eventually

**Approved:** Immediate — monetize effort (consulting, benchmark validation). Eventual — open core + paid enterprise features.

**Never:** closed enterprise fork.

---

## Part 3 — The Revised Plan with Gates

### Phase 0 — Foundation (Weeks 1–4)

**Goal:** Legal + naming + triage schema decisions locked. No code.

**Deliverables:**
- ADR-016: Verified vs Discovery engine vocabulary
- ADR-017: Heuristic pipeline emission model (candidates only; reaffirms ADR-001)
- ADR-018: License decision + timeline (Decision 1)
- ADR-019: Triage queue output format (SARIF extension)
- ADR-020: Pydantic vs dataclasses decision
- ADR-021: Crawler placement decision
- Updated `docs/PHASE-6-PLAN.md`: reference this document
- Updated `docs/ROADMAP.md`: Phase 2-5 mapping

**No new code. Only ADRs and docs.**

### Phase 1 — Dual-Track Formalization (Months 1–3) — M37–M40

**Deliverables:**
- `src/janissary/heuristic/` package (additive)
- `signatures.py` — signature registry (dataclasses or pydantic per ADR-020)
- `engine.py` — HeuristicEngine returns CandidateFinding, not ScanFinding
- CLI `--heuristic` flag, off by default; findings marked `unproven`
- SSRF payloads extended with metadata_aws, metadata_gcp, metadata_azure, metadata_v6
- SARIF extended with second run tagged `properties.track: "discovery"`
- Tests — 20-30 unit tests
- `docs/LIMITATIONS.md` — explicit "what heuristic mode catches, what it doesn't, why off by default"

**Gate 1 (before Phase 2 code):**
- [ ] ADRs 016-021 accepted
- [ ] 856+ existing tests still pass
- [ ] Heuristic mode produces zero false positives on OWASP benchmark subset
- [ ] A named external user has run the CLI and confirmed heuristic mode is useful to them

### Phase 2 — Tri-Session Auth (Months 4–6) — M41–M43

**Deliverables:**
- ADR-022: Tri-session auth model + ADR-010 supersession rules
- `auth.py` extension — AuthConfig becomes SessionTriplet (three independent requests.Session)
- `detection/idor.py` — candidate-only IDOR probe (A vs B differential; C blocked)
- CLI `--cookie-alt`, `--bearer-alt`, `--idor` (candidates go to triage stream)
- Tests — 30+ tests; corpus integration against crAPI
- ADR-010 update — single-session mode keeps abort; tri-session mode rotates

**Gate 2:**
- [ ] Tri-session auth works against crAPI end-to-end
- [ ] IDOR candidates don't leak into verified findings
- [ ] A named external user has found at least one candidate useful against their own target

### Phase 3 — Discovery Expansion (Months 7–9) — M44–M45

**Deliverables:**
- New repo `janissary-crawl` — Playwright-based, emits `crawl-output.json`
- CLI in new repo — `janissary-crawl <url>` outputs parameter map
- Integration test — output piped to `janissary scan` via shell
- Zero new code in main janissary repo

**Gate 3:**
- [ ] `janissary-crawl` works standalone against 3 different apps
- [ ] At least 3 users have asked "can it feed directly into janissary scan?"

### Phase 4 — Local Triage UI (Months 10–12) — M46–M48

**Deliverables:**
- `janissary ui` subcommand — local web server on localhost:8080
- Single-page app — static HTML + minimal JS; no React; no build step
- Two tabs: "Verified Findings" and "Discovery Candidates"
- Reads from local JSON/SARIF files, not from a DB
- No authentication — it's a local tool

**Gate 4:**
- [ ] 100+ downloads of local UI release
- [ ] 3 named users have asked for a hosted version
- [ ] A single named enterprise has expressed written interest (LOI, email, or explicit ask)

### Phase 5 — SaaS (Year 2, conditional)

**Only proceed if Gate 4 passes.**

- Multi-tenant FastAPI
- Postgres + Redis
- Real RBAC, SSO, audit logging
- Split: core is Apache-2.0, SaaS layer proprietary (Decision 1D)

---

## Part 4 — Safeguards Against Past Failure

### Failure Pattern 1: Building platform before users

**Safeguard:** Gate 4's "3 named users + 1 LOI" is a hard stop. Phase 5 requires external evidence before any code. The local UI in Phase 4 is the demand test.

### Failure Pattern 2: License change alienates contributors

**Safeguard:** Decision 1 recommends staying Apache-2.0 until 100+ stars, 5+ contributors, and a named enterprise. License change becomes reactive, not proactive.

### Failure Pattern 3: Rewriting working code

**Safeguard:** The plan is entirely additive. `heuristic/` is new. `cli.py` gets new flags. `scan.py` is never created. The 856-test suite must stay green at every gate.

### Failure Pattern 4: Fabricated benchmarks and rankings

**Safeguard:** Zero tolerance for unverifiable claims. Competitive rankings in the upload are rejected. Claims must be (a) reproducible by documented command, (b) timestamped, (c) named third party.

### Failure Pattern 5: Scope creep during engineering

**Safeguard:** Kill criteria per phase. If Phase 1 doesn't hit Gate 1 by week 12, stop and reassess. Do not extend — split or cancel. ADRs are the contract; additions require amendment.

---

## Part 5 — ADR and Milestone Mapping

### ADR sequence

| ADR | Topic | Phase |
|---|---|---|
| ADR-016 | Verified vs Discovery engine vocabulary | 0 |
| ADR-017 | Heuristic emission model (reaffirms ADR-001) | 0 |
| ADR-018 | License timeline and community consultation | 0 |
| ADR-019 | Triage output format (SARIF extension) | 0 |
| ADR-020 | Pydantic vs dataclasses | 0 |
| ADR-021 | Crawler placement | 0 |
| ADR-022 | Tri-session auth model | 2 |
| ADR-024 | IDOR candidate generation rules | 2 |
| ADR-024 | Local UI vs SaaS split | 4 |

### Milestone mapping

| Existing | New | Content |
|---|---|---|
| Phase 4.5 (M13-M36) | Unchanged | All delivered, 63.9% |
| — | M36a | ADR series 016-021 (Phase 0) |
| — | M37 | `heuristic/signatures.py` + registry |
| — | M38 | `heuristic/engine.py` + CLI flag |
| — | M39 | SSRF metadata payloads (4) |
| — | M40 | SARIF triage stream |
| — | M41 | Tri-session auth |
| — | M42 | IDOR candidate probe |
| — | M43 | crAPI end-to-end validation |
| — | M44 | `janissary-crawl` repo |
| — | M45 | Crawl output -> scan pipeline |
| — | M46 | `janissary ui` local server |
| — | M47 | Local UI tabs |
| — | M48 | Gate 4 evidence collection |
| Phase 5 (M21-M25) | Pushed ~6 months | Business milestones |
| Phase 6 (M26-M30) | Pushed ~12 months | Enterprise, SaaS, ARR |

The business milestones (M21-M30) shift to year 2. That's the cost of building engineering capability first. If revenue needs to arrive before year 2, the plan changes: ship Phase 1, go to market, come back to Phase 2 in 12 months.

---

## Part 6 — Immediate Next Steps

### This week

1. **Command A** — SPA README fix (correction owed to prior work)
2. **Command B** — SSRF metadata payloads (4 payloads + 4 oracles + tests)
3. **Command C** — ADR-016 draft (Verified vs Discovery vocabulary)
4. **Command D** — PHASE-6-PLAN.md rewrite (this document becomes strategic core)

### Before Phase 1 code (this month)

1. Read and sign off on ADRs 016-021
2. Decide Decision 1 (license) and Decision 3 (SaaS timing) — highest-stakes
3. **Interview 3 candidate external users** — ask: "Would you pay for a hosted version? At what price? What would make you switch from your current tool?" If no one says yes, Gate 4 will fail — find that out now, not in 18 months.

---

## Part 7 — Governance

This document is the strategic core. Changes to the phased plan require:

1. A new ADR documenting the change and rationale
2. Reference to the affected milestone(s)
3. Update to `tools/ascension_state.json`
4. Re-run `python tools/ascension.py` to regenerate the dashboard

Questions about specific decisions route to their governing ADR. Questions about the overall plan route to this document.


### Roadmap confidentiality (trigger-activated)

This plan is published publicly as long as it aids adoption,
contributor recruitment, and enterprise procurement. At the
moment Gate 2 (first paying customer) OR Gate 4 (SaaS decision)
fires, the following bifurcation takes effect automatically:

1. Create `docs/internal/` (gitignored via `.gitignore` entry
   `docs/internal/`).
2. Move the following content from this file into
   `docs/internal/GATES.md` (private):
   - Part 3 gate thresholds ("3 named users", "5,000 MAU",
     "1 LOI" etc.)
   - Part 5 milestone mapping business rows (M21-M30)
   - Any named enterprise reference (LOIs, contracts)
3. Keep this file public with phase structure and ADR references
   intact; replace the specific numbers with "see internal
   gates doc" in the affected sections.
4. Update README Roadmap section to add: "Internal gate
   thresholds are redacted per FUTURE-STATE-PLAN Part 7."
5. Update `tools/ascension_state.json` M49 with a `delivered`
   date and reference to this section.

**Trigger activation is manual** (no cron can detect "a named
enterprise asked"). The M49 milestone on the dashboard is the
durable reminder: any maintainer planning Gate 2 or Gate 4
work sees M49 pending and reads this section before touching
the sensitive parts.

**Approved by:** Hetaireia, 2026-11-04
**Implementation begins:** Phase 0 (ADRs 016-021) following Command A/B/C/D above
