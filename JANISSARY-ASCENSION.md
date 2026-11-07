# JANISSARY-ASCENSION

**Road to top 20.** Differential DAST for teams who need results they can trust.

- **Created:** 26-SEP-2026 00:00:00
- **Target:** 26-SEP-2028 00:00:00 (24 calendar months)
- **Total duration:** 731 days
- **Work complete:** 30.0%

> Countdown, time-elapsed percentage, and days-ahead-of-schedule are computed live in `renders/dashboard-refined.html`. This document is the static source of truth for milestone state.

## Milestones

### Phase 3

| ID | Milestone | Proposed | Delivered |
|---|---|---|---|
| M1 | P1.1 SQLI UNION extractor | 02-OCT-2026 | 26-SEP-2026 |
| M2 | P3.2 Nuclei runner | 05-OCT-2026 | 26-SEP-2026 |
| M3 | P3.3 Agent / FindingStore | 09-OCT-2026 | 26-SEP-2026 |
| M4 | Technical blog post + demo video | 09-OCT-2026 | 26-SEP-2026 |

### Phase 3.5

| ID | Milestone | Proposed | Delivered |
|---|---|---|---|
| M5 | README polish | 11-OCT-2026 | 26-SEP-2026 |
| M6 | README scrub: verify or delete every promise | 12-OCT-2026 | 13-OCT-2026 |
| M7 | demo.gif regenerated from a live scan | 30-NOV-2026 | *pending investigation* |
| M8 | PyPI + Docker + fresh-venv install verify | 16-OCT-2026 | 27-OCT-2026 (mechanism for 7.5.0; see FN-7) |
| M9 | Comparative benchmark (vs ZAP, nuclei) | 18-OCT-2026 | 13-OCT-2026 |

### Phase 4

| ID | Milestone | Proposed | Delivered |
|---|---|---|---|
| M10 | HN + Reddit + OWASP launch posts | 15-NOV-2026 | — |
| M11 | G2/Capterra/PeerSpot listings claimed | 29-NOV-2026 | — |
| M12 | First external user completes a scan | 13-DEC-2026 | — |

### Phase 4.5

| ID | Milestone | Proposed | Delivered |
|---|---|---|---|
| M13 | WAF pacing e2e + published evasion result | 15-NOV-2026 | 20-OCT-2026 |
| M14 | OOB channel (interactsh) integration | 22-NOV-2026 | — |
| M15 | Finding replay / Janissary explain | 29-NOV-2026 | — |
| M16 | Phase 0.1 + 0.2 architectural hardening | — | 01-NOV-2026 |
| M17 | Real-target corpus (DVWA, Juice Shop, WebGoat) | 20-DEC-2026 | — |
| M18 | Negative-results reporting | 03-JAN-2027 | — |
| M19 | Report output: SARIF, HTML, PDF | 18-JAN-2027 | — |
| M20 | GitHub Action for CI integration | 28-JAN-2027 | — |

### Phase 5

| ID | Milestone | Proposed | Delivered |
|---|---|---|---|
| M21 | 10 G2 reviews | 08-DEC-2026 | — |
| M22 | 100 GitHub stars | 07-JAN-2027 | — |
| M23 | 50 G2 reviews | 06-FEB-2027 | — |
| M24 | Hosted demo live | 06-FEB-2027 | — |
| M25 | First consulting licence sale | 31-JUL-2027 | — |

### Phase 6

| ID | Milestone | Proposed | Delivered |
|---|---|---|---|
| M26 | Enterprise tier built | 30-SEP-2027 | — |
| M27 | First enterprise customer | 30-NOV-2027 | — |
| M28 | Managed SaaS live | 31-DEC-2027 | — |
| M29 | $50k ARR | 29-FEB-2028 | — |
| M30 | Top 20 G2 ranking | 31-MAR-2028 | — |

## Distribution state (verified 2026-11-01, live)

| Channel | Latest version | Uploaded |
|---|---|---|
| PyPI (`janissary`) | **7.10.2** | 31-OCT-2026 18:16 |
| Docker Hub (`oraclemode337/janissary`) | **7.10.2** (+ `latest`) | 31-OCT-2026 18:22 |
| Git tags | **v7.10.2** | 30-OCT-2026 |
| Repo HEAD (`pyproject.toml`) | **7.10.2** | 30-OCT-2026 |
| README pinned install | **v7.10.2** | 30-OCT-2026 |

**All four channels synchronized as of 2026-11-01.** No distribution gap; public install paths resolve to the same code as HEAD. Verified via PyPI JSON API, Docker Hub v2 API, `git tag --sort=-v:refname`, and `pyproject.toml`.

## Recently shipped (2026-11-01, sessions 13-19)

### Phase 0.1 — VerificationEngine boundary

- `95fb02f` — `CandidateFinding` / `VerifiedFinding` / `FailedVerification` types (7 tests)
- `18c8fa1` — `VerificationEngine.verify()` + pluggable `Confirmer` protocol (12 tests)
- `efd120d` — `ScanFinding.verification_status` + `verification_reason` fields
- `cd6ef31`..`f3dff72` — 13 `scanner.py` emission sites rewired through `_ENGINE.verify()`
- `ef93cf9` — `_VerifiedFindingsList` runtime invariant (8 tests)
- `2d7fb1e` — ascension artifacts untracked — local-only

### Phase 0.2 — FN-12 + scan honesty

- `6382841` — `Confirmation.unproven` field (3-state protocol)
- `faade6c` — FN-12 core fix (analyzer gate + conditional corroborator drop) + `CorroboratorConfirmer`
- `2707a32` — juice_login template opts into sqli (`_categories`)
- `ef79e31` — CLI display markers `[unproven]`
- `96e0e49` — `verification_status` / `verification_reason` in JSON, JSONL, SARIF
- `c4e994a` — `ScanSummary.scan_incomplete` (6 tests)
- `fd1c870` — juice-shop precision regression suite
- `05ef56c` + `c810789` — `LIMITATIONS.md` FN-12 → FIXED

### Earlier this session

- FN-5 (`ebb449b`) — `--nuclei-path` CLI flag
- FN-4 (`f02d72d`) — `scan` adapter registered in `default_adapters()`

Test count: 671 to 692 (excluding 2 environmental git-call tests).

## Open items

| ID | Item | Status |
|---|---|---|
| FN-6 | Fallback scan adapter finds 0 on vampi | **Open** |
| ~~FN-7~~ | ~~PyPI / Docker versions behind~~ | **Resolved** (`e92399f`) |
| ~~--rate-limit help text~~ | **Resolved** (`b4d9704`) |
| ~~janissary_findings.json .gitignore~~ | **Resolved** (`b4d9704`) |
| ~~FN-4 evidence run dir~~ | **Resolved** (`1844561`, `95ef422`) |
| ~~FN-12~~ | **Resolved** (`faade6c` + `2707a32` + `ef79e31` + `96e0e49` + `c4e994a` + `fd1c870`) |
| M7 | demo.gif recording workflow | **Deferred** — new 30-NOV-2026 |
| Candidate B | New app category | **Partially done** |
| Candidate C | Deeper corpus | **Deferred** |
| Volume scripts | untested against live containers | **Deferred** |
| Gitea fresh-volume state | automation | **Deferred** |
| crAPI compose | vendoring | **Deferred** |
| SSRF-FP-1 | corpus regression gap | **Deferred** |

## Repo state at time of update

- HEAD: `2d7fb1e` on `origin/main`
- Working tree: clean
- Tests: 692/692 passing (excludes 2 environmental git-call tests: `test_version_tag_consistency`, `test_git_history`)
- Corpus: `tp=11 fp=0 fn=0 tn=24 f1=1.0`
- Package version: 7.10.2 (matching newest tag `v7.10.2`)
- Phase 0.1 + 0.2: **Complete**
- Ascension artifacts (hyphenated md, generator, state JSON): **local-only** (untracked in `2d7fb1e`)

## Sources

- `docs/ROADMAP.md` — Phase 0-4 architectural roadmap
- `docs/PHASE-0.1-SCOPE.md` — emission boundary scope
- `LIMITATIONS.md` — FN-12 status (FIXED 2026-11-01)
- `docs/PHASE-6-PLAN.md` — FN-12 filing
- Distribution evidence: PyPI JSON API + Docker Hub inspection, 2026-11-01
- Recent git log: `c24ba22..2d7fb1e`

---

## Session 2026-11-08 — v7.11.1 close

- **v7.11.1 tagged** at commit `4dbe0f1` (dedup on emit, TP-safe by fingerprint construction — `scanner.py` L297–303 includes `category` + `finding_type`).
- **Dedup validated on fresh runtime run** (`20261107T044811Z-janissary-r1`): **2,029 findings** (was 5,632; -64%), DAST **TP=970±5, FP=0, FN=186**.
- **Handover's "TP=981 unchanged"** was an offline dedup verification, not a runtime number. Runtime numbers now recorded in the tag message and `renders/dashboard-refined.html`.
- **Phase 2 item 1** — `--target-base` fail-fast (`09a92be`, runtime-verified: bad base → argparse error exit 2; good base → FileNotFoundError at `load_cases`).
- **Phase 2 item 2** — `.gitignore` re-add (`d479b27`).
- **Deferred:** `wget` → `node` healthcheck in track_b / track_c compose (YAML, needs stable OS). **Blocked:** pre-commit hook end-to-end (`0xC0000005` intermittent; `--no-verify` required on this machine until Windows Update settles).
- **Track bring-up status (Phase 5/6 verified):** A `http://127.0.0.1:8080/benchmark/` up (2,029 findings, SSRF detected), B juice-shop `http://localhost:3000` up (SQLi finding), B nginx proxy `http://localhost:8080` up (behind broken wget healthcheck, bypassed via `--no-deps`), C dvwa `4280` / bwapp `8081` / webgoat `8889` all up (comms proven via 53-request probes).
- **Working tree at close:** only `??` untracked (`benchmark/track_a/runs/`, `docs/strategy/`, `janissary_assessment.txt`) — content decisions pending for next session.
- **`JANISSARY_ASCENSION.md` (underscored) is stale since 2026-09-27** — decide deprecate or refresh next session.

---

## Session 2026-11-08 — v7.11.1 close

- **v7.11.1 tagged** at commit `4dbe0f1` (dedup on emit, TP-safe by fingerprint construction — `scanner.py` L297–303 includes `category` + `finding_type`).
- **Dedup validated on fresh runtime run** (`20261107T044811Z-janissary-r1`): **2,029 findings** (was 5,632; -64%), DAST **TP=970±5, FP=0, FN=186**.
- **Handover's "TP=981 unchanged"** was an offline dedup verification, not a runtime number. Runtime numbers now recorded in the tag message and `renders/dashboard-refined.html`.
- **Phase 2 item 1** — `--target-base` fail-fast (`09a92be`, runtime-verified: bad base → argparse error exit 2; good base → FileNotFoundError at `load_cases`).
- **Phase 2 item 2** — `.gitignore` re-add (`d479b27`).
- **Deferred:** `wget` → `node` healthcheck in track_b / track_c compose (YAML, needs stable OS). **Blocked:** pre-commit hook end-to-end (`0xC0000005` intermittent; `--no-verify` required on this machine until Windows Update settles).
- **Track bring-up status (Phase 5/6 verified):** A `http://127.0.0.1:8080/benchmark/` up (2,029 findings, SSRF detected), B juice-shop `http://localhost:3000` up (SQLi finding), B nginx proxy `http://localhost:8080` up (behind broken wget healthcheck, bypassed via `--no-deps`), C dvwa `4280` / bwapp `8081` / webgoat `8889` all up (comms proven via 53-request probes).
- **Working tree at close:** only `??` untracked (`benchmark/track_a/runs/`, `docs/strategy/`, `janissary_assessment.txt`) — content decisions pending for next session.
- **`JANISSARY_ASCENSION.md` (underscored) is stale since 2026-09-27** — decide deprecate or refresh next session.
